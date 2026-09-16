/**
 * 一条 WSS 连接上的会话管理器。
 *
 * 绑定关系：(WSS 连接, sessionId) ↔ 外网目标 TCP 套接字 —— 一对一。
 * 职责：
 *   - 建立 / 复用目标 TCP 连接
 *   - 双向透传原始字节（服务端 → WSS 二进制帧；WSS 二进制帧 → 服务端）
 *   - 空闲超时回收、断线全量释放
 */

import net from 'node:net';
import { EventEmitter } from 'node:events';
import { encodeDataFrame, MODE_TCP_OVER_WSS } from './protocol.js';
import { guardTarget } from './ssrf.js';

/** 会话状态 */
const STATE_CONNECTING = 'connecting';
const STATE_OPEN = 'open';
const STATE_CLOSED = 'closed';

export class Session extends EventEmitter {
  /**
   * @param {object} opts
   * @param {number} opts.id sessionId
   * @param {string} opts.host
   * @param {number} opts.port
   * @param {string} [opts.mode]
   * @param {string} [opts.clientIp]
   */
  constructor(opts) {
    super();
    this.id = opts.id;
    this.host = opts.host;
    this.port = opts.port;
    this.mode = opts.mode || MODE_TCP_OVER_WSS;
    this.clientIp = opts.clientIp;
    this.state = STATE_CONNECTING;
    this.socket = null;
    this.createdAt = Date.now();
    this.lastActiveAt = Date.now();
    this.bytesToTarget = 0;
    this.bytesFromTarget = 0;
    /** 客户端是否已半关上行（不再发送数据） */
    this.uplinkClosed = false;
    /** 下行背压：目标 socket 是否因 WSS 缓冲堆积而暂停 */
    this._paused = false;
    this._resumeTimer = null;
  }

  touch() {
    this.lastActiveAt = Date.now();
  }

  /** 目标 socket 收到数据 → 交给上层封装成二进制帧 */
  _onData(chunk) {
    this.bytesFromTarget += chunk.length;
    this.touch();
    this.emit('data', chunk);
  }

  /** WSS 侧收到数据 → 写入目标 socket */
  write(chunk) {
    if (this.state !== STATE_OPEN || !this.socket || this.uplinkClosed) return false;
    this.bytesToTarget += chunk.length;
    this.touch();
    return this.socket.write(chunk);
  }

  /**
   * 上行 EOF：客户端不再发送数据（半关写端），但仍需接收下行。
   * 语义等价于向目标 socket 发送 FIN，而不是关闭整个会话。
   * 此后到达的 write() 一律丢弃（目标已不该再收到数据）。
   */
  halfClose() {
    if (this.state !== STATE_OPEN || !this.socket) return;
    this.uplinkClosed = true;
    this.touch();
    try {
      this.socket.end();
    } catch { /* 忽略 */ }
  }

  /**
   * 关闭会话。
   * @param {string} [reason]
   */
  close(reason = 'closed') {
    if (this.state === STATE_CLOSED) return;
    this.state = STATE_CLOSED;
    if (this._resumeTimer) {
      clearTimeout(this._resumeTimer);
      this._resumeTimer = null;
    }
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }
    this.emit('close', reason);
  }
}

/** SessionManager 的配置默认值，用于配置对象缺字段时兜底 */
const DEFAULTS = {
  connectTimeoutMs: 10000,
  idleTimeoutMs: 120000,
  maxSessionsPerConnection: 256,
  /** WebSocket 发送缓冲高水位：超过则暂停读取目标 socket（下行背压） */
  wsBufferedHighWaterMark: 4 * 1024 * 1024,
  /** WebSocket 发送缓冲低水位：回落到此值以下恢复读取 */
  wsBufferedLowWaterMark: 1 * 1024 * 1024,
};

/** 背压恢复检查的轮询间隔 */
const BACKPRESSURE_POLL_MS = 20;

/**
 * 单个 WSS 连接的所有会话。
 */
export class SessionManager {
  /**
   * @param {object} opts
   * @param {object} opts.ws WebSocket 连接
   * @param {string} opts.clientIp
   * @param {object} opts.config
   */
  constructor(opts) {
    this.ws = opts.ws;
    this.clientIp = opts.clientIp;
    // 保留对配置对象的活引用（而非快照），这样运行期调整配置
    // （如运维热改上限、测试注入 lookup）能立即生效。
    // 缺失字段用 getter 兜默认值，避免直接调 createServer({...}) 时拿到 undefined。
    this.rawConfig = opts.config || {};
    this.config = new Proxy(this.rawConfig, {
      get: (target, prop) => {
        if (prop in target && target[prop] !== undefined) return target[prop];
        return DEFAULTS[prop];
      },
      has: () => true,
    });
    /** @type {Map<number, Session>} */
    this.sessions = new Map();
    this.closed = false;
    this._sweeper = null;
  }

  start() {
    this._sweeper = setInterval(() => this.sweepIdle(), 5000);
    if (this._sweeper.unref) this._sweeper.unref();
  }

  stop() {
    if (this._sweeper) clearInterval(this._sweeper);
    this._sweeper = null;
    this.destroyAll('manager stopped');
  }

  _send(obj) {
    if (this.ws.readyState !== 1) return;
    try {
      this.ws.send(JSON.stringify(obj));
    } catch {
      /* 连接已断，交由 close 流程清理 */
    }
  }

  _sendError(sessionId, message) {
    this._send({ type: 'error', sessionId, message });
  }

  /**
   * 处理 connect 控制消息：解析目标 → SSRF 校验 → 建连。
   * @param {{sessionId: number, host: string, port: number, mode?: string}} msg
   */
  async handleConnect(msg) {
    const { sessionId, host, port } = msg;
    if (this.closed) return;
    if (this.sessions.has(sessionId)) {
      this._sendError(sessionId, 'duplicate sessionId');
      return;
    }
    if (this.sessions.size >= this.config.maxSessionsPerConnection) {
      this._sendError(sessionId, 'per-connection session limit reached');
      return;
    }

    const mode = msg.mode || MODE_TCP_OVER_WSS;
    if (mode !== MODE_TCP_OVER_WSS) {
      this._sendError(sessionId, `unsupported mode: ${mode}`);
      return;
    }

    const session = new Session({
      id: sessionId,
      host,
      port,
      mode,
      clientIp: this.clientIp,
    });
    this.sessions.set(sessionId, session);

    const guard = await guardTarget(host, this.config.lookup);
    if (this.closed || session.state === STATE_CLOSED) return;
    if (!guard.ok) {
      this._sendError(sessionId, guard.reason);
      this.sessions.delete(sessionId);
      return;
    }

    // 关键：连接使用「校验通过的 IP」，而不是再次传递域名解析。
    // 避免 DNS rebinding / TOCTOU —— 校验的地址与实际连接地址必须一致。
    // 测试注入点：默认连到「校验通过的 IP」，测试可覆盖为本地目标
    const connectHost = this.config.connectOverride
      ? this.config.connectOverride(guard.addresses[0], host)
      : guard.addresses[0];
    const socket = net.connect({ host: connectHost, port });
    session.socket = socket;
    socket.setNoDelay(true);
    // 建连阶段用 connectTimeoutMs 兜底，建连成功后切换为读写空闲超时
    socket.setTimeout(this.config.connectTimeoutMs);

    const onFail = (reason) => {
      if (session.state === STATE_CLOSED) return;
      this._sendError(sessionId, reason);
      session.close(reason);
    };

    socket.once('connect', () => {
      if (session.state === STATE_CLOSED) return;
      session.state = STATE_OPEN;
      session.touch();
      // 建连完成，超时改为读写空闲超时
      socket.setTimeout(this.config.idleTimeoutMs);
      this._send({ type: 'connected', sessionId });
    });
    socket.on('data', (chunk) => session._onData(chunk));
    socket.on('timeout', () =>
      onFail(session.state === STATE_OPEN ? 'target idle timeout' : 'target connect timeout'),
    );
    socket.on('error', (err) => onFail(`target socket error: ${err.code || err.message}`));
    socket.on('end', () => session.touch());
    socket.on('close', () => session.close('target closed'));

    session.on('data', (chunk) => {
      if (this.ws.readyState !== 1) return;
      try {
        this.ws.send(encodeDataFrame(sessionId, chunk), { binary: true });
      } catch {
        session.close('wss send failed');
        return;
      }
      // 下行背压：WSS 发送缓冲堆积（慢速客户端下载大文件）时暂停读取目标，
      // 避免缓冲无上限增长；回落到低水位后恢复。
      this._applyBackpressure(session);
    });
    session.on('close', (reason) => {
      this.sessions.delete(sessionId);
      this._send({ type: 'close', sessionId, reason });
    });
  }

  /**
   * 根据 WSS 发送缓冲水位，对目标 socket 做暂停 / 恢复（下行背压）。
   * 仅对处于 open 且有 socket 的会话生效。
   */
  _applyBackpressure(session) {
    const socket = session.socket;
    if (!socket || socket.destroyed) return;
    const buffered = this.ws.bufferedAmount ?? 0;

    if (buffered >= this.config.wsBufferedHighWaterMark) {
      if (!session._paused) {
        session._paused = true;
        try { socket.pause(); } catch { /* 忽略 */ }
      }
      this._scheduleResume(session);
    } else if (session._paused && buffered <= this.config.wsBufferedLowWaterMark) {
      session._paused = false;
      try { socket.resume(); } catch { /* 忽略 */ }
    }
  }

  /** 缓冲回落后恢复读取；会话已关闭则停止轮询 */
  _scheduleResume(session) {
    if (session._resumeTimer) return;
    session._resumeTimer = setTimeout(() => {
      session._resumeTimer = null;
      if (session.state === STATE_CLOSED) return;
      const socket = session.socket;
      if (!socket || socket.destroyed) return;
      const buffered = this.ws.bufferedAmount ?? 0;
      if (buffered <= this.config.wsBufferedLowWaterMark) {
        session._paused = false;
        try { socket.resume(); } catch { /* 忽略 */ }
      } else {
        this._scheduleResume(session);
      }
    }, BACKPRESSURE_POLL_MS);
    if (session._resumeTimer.unref) session._resumeTimer.unref();
  }

  /** 处理来自 WSS 的二进制数据帧 */
  handleData(buf) {
    if (this.closed) return;
    if (buf.length < 4) return;
    const sessionId = buf.readUInt32BE(0);
    const payload = buf.subarray(4);
    const session = this.sessions.get(sessionId);
    if (!session) return;
    session.write(payload);
  }

  /** 处理 half-close 控制消息：上行 EOF，保留下行 */
  handleHalfClose(msg) {
    if (this.closed) return;
    const session = this.sessions.get(msg.sessionId);
    if (session) session.halfClose();
  }

  /** 处理 close 控制消息 */
  handleClose(msg) {
    const session = this.sessions.get(msg.sessionId);
    if (session) session.close('client closed');
  }

  /** 回收空闲 / 超时会话 */
  sweepIdle() {
    const now = Date.now();
    for (const session of this.sessions.values()) {
      if (now - session.lastActiveAt > this.config.idleTimeoutMs) {
        session.close('idle timeout');
      }
    }
  }

  /** 连接断开时全量释放 */
  destroyAll(reason = 'wss closed') {
    this.closed = true;
    for (const session of [...this.sessions.values()]) {
      session.close(reason);
    }
    this.sessions.clear();
  }

  stats() {
    return {
      sessions: this.sessions.size,
      open: [...this.sessions.values()].filter((s) => s.state === STATE_OPEN).length,
    };
  }
}
