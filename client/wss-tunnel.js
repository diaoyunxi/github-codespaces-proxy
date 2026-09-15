/**
 * WSS 隧道客户端 —— 一条（或少量）WSS 长连接承载全部 TCP 会话。
 *
 * 职责：
 *   - 维护到远端代理服务端的 WSS 长连接（自动重连、心跳保活）
 *   - 分配 / 回收 sessionId
 *   - 把本地 TCP 字节 → WSS 二进制帧；WSS 二进制帧 → 本地 TCP
 */

import { EventEmitter } from 'node:events';
import WebSocket from 'ws';
import { encodeDataFrame, decodeDataFrame, controlMessage, MODE_TCP_OVER_WSS } from '../server/protocol.js';

/** 会话状态 */
const STATE_CONNECTING = 'connecting';
const STATE_OPEN = 'open';
const STATE_CLOSED = 'closed';

export class TunnelSession extends EventEmitter {
  constructor(id, target) {
    super();
    this.id = id;
    this.target = target; // { host, port }
    this.state = STATE_CONNECTING;
    this.createdAt = Date.now();
    this.closedReason = null;
  }

  /** WSS 侧收到数据 → 交给本地 TCP 连接 */
  deliver(chunk) {
    if (this.state === STATE_CLOSED) return;
    this.emit('data', chunk);
  }

  /** 本地 TCP 收到数据 → 交给上层封帧 */
  push(chunk) {
    if (this.state === STATE_CLOSED) return;
    this.emit('uplink', chunk);
  }

  markOpen() {
    if (this.state === STATE_CLOSED) return;
    this.state = STATE_OPEN;
    this.emit('open');
  }

  close(reason = 'closed') {
    if (this.state === STATE_CLOSED) return;
    this.state = STATE_CLOSED;
    this.closedReason = reason;
    this.emit('close', reason);
    this.removeAllListeners();
  }
}

export class WssTunnel extends EventEmitter {
  /**
   * @param {object} opts
   * @param {string} opts.url 如 wss://proxy.example.com/
   * @param {number} [opts.connectTimeoutMs]
   * @param {number} [opts.handshakeTimeoutMs] 单会话建连（服务端 connected 回执）超时
   * @param {number} [opts.reconnectDelayMs]
   * @param {number} [opts.maxReconnectDelayMs]
   * @param {number} [opts.pingIntervalMs]
   * @param {number} [opts.maxSessions] 本地 sessionId 上限（同时活跃会话数上限）
   */
  constructor(opts) {
    super();
    this.url = opts.url;
    this.connectTimeoutMs = opts.connectTimeoutMs ?? 10000;
    this.handshakeTimeoutMs = opts.handshakeTimeoutMs ?? 15000;
    this.reconnectDelayMs = opts.reconnectDelayMs ?? 500;
    this.maxReconnectDelayMs = opts.maxReconnectDelayMs ?? 15000;
    this.pingIntervalMs = opts.pingIntervalMs ?? 25000;
    this.maxSessions = opts.maxSessions ?? 1024;
    /** 透传给 ws 客户端的 TLS / 握手选项（CA、rejectUnauthorized 等） */
    this.wsOptions = opts.wsOptions ?? {};

    /** @type {Map<number, TunnelSession>} */
    this.sessions = new Map();
    this.ws = null;
    this.ready = false;
    this.stopped = false;
    this._nextId = 1;
    this._reconnectAttempts = 0;
    this._pingTimer = null;
    this._reconnectTimer = null;
  }

  /** 建立（或重建）WSS 长连接 */
  connect() {
    if (this.stopped) return;
    this._clearReconnect();
    const ws = new WebSocket(this.url, {
      handshakeTimeout: this.connectTimeoutMs,
      ...this.wsOptions,
    });
    this.ws = ws;

    ws.on('open', () => {
      this.ready = true;
      this._reconnectAttempts = 0;
      this._startPing();
      this.emit('ready');
    });

    ws.on('message', (data, isBinary) => {
      if (isBinary) {
        const frame = decodeDataFrame(Buffer.isBuffer(data) ? data : Buffer.from(data));
        if (!frame) return;
        const session = this.sessions.get(frame.sessionId);
        if (session) session.deliver(frame.payload);
        return;
      }
      let msg;
      try {
        msg = JSON.parse(data.toString());
      } catch {
        return;
      }
      this._onControl(msg);
    });

    ws.on('close', () => {
      this._onDisconnected('wss closed');
    });

    ws.on('error', (err) => {
      this.emit('error', err);
      this._onDisconnected(`wss error: ${err.message}`);
    });
  }

  _onControl(msg) {
    const session = typeof msg.sessionId === 'number' ? this.sessions.get(msg.sessionId) : null;
    switch (msg.type) {
      case 'connected':
        if (session) session.markOpen();
        this.emit('session-open', msg.sessionId);
        break;
      case 'close':
        if (session) session.close(msg.reason || 'server closed');
        break;
      case 'error':
        if (session) {
          session.emit('error', new Error(msg.message || 'server error'));
          session.close(`server error: ${msg.message}`);
        }
        this.emit('session-error', msg);
        break;
      default:
        break;
    }
  }

  /** WSS 断开：全部在途会话立即断流、释放 */
  _onDisconnected(reason) {
    this.ready = false;
    this._stopPing();
    for (const session of [...this.sessions.values()]) {
      session.emit('error', new Error(reason));
      session.close(reason);
    }
    this.sessions.clear();
    this.emit('down', reason);
    if (!this.stopped) this._scheduleReconnect();
  }

  _scheduleReconnect() {
    this._clearReconnect();
    const delay = Math.min(
      this.reconnectDelayMs * 2 ** this._reconnectAttempts,
      this.maxReconnectDelayMs,
    );
    this._reconnectAttempts += 1;
    this._reconnectTimer = setTimeout(() => this.connect(), delay);
    if (this._reconnectTimer.unref) this._reconnectTimer.unref();
  }

  _clearReconnect() {
    if (this._reconnectTimer) clearTimeout(this._reconnectTimer);
    this._reconnectTimer = null;
  }

  _startPing() {
    this._stopPing();
    this._pingTimer = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        try { this.ws.ping(); } catch { /* 忽略 */ }
      }
    }, this.pingIntervalMs);
    if (this._pingTimer.unref) this._pingTimer.unref();
  }

  _stopPing() {
    if (this._pingTimer) clearInterval(this._pingTimer);
    this._pingTimer = null;
  }

  /** 分配一个未使用的 sessionId（uint32，非 0） */
  _allocId() {
    for (let i = 0; i < this.maxSessions * 2; i++) {
      const id = this._nextId;
      this._nextId = id >= 0xffffffff ? 1 : id + 1;
      if (!this.sessions.has(id)) return id;
    }
    return null;
  }

  /**
   * 打开一个到 host:port 的隧道会话。
   * @param {string} host
   * @param {number} port
   * @param {string} [mode]
   * @returns {TunnelSession | null} 隧道未就绪或超限时返回 null
   */
  openSession(host, port, mode = MODE_TCP_OVER_WSS) {
    if (!this.ready || !this.ws || this.ws.readyState !== WebSocket.OPEN) return null;
    if (this.sessions.size >= this.maxSessions) return null;
    const id = this._allocId();
    if (id === null) return null;

    const session = new TunnelSession(id, { host, port });
    this.sessions.set(id, session);

    const timer = setTimeout(() => {
      if (session.state !== STATE_OPEN) {
        session.emit('error', new Error('tunnel handshake timeout'));
        session.close('handshake timeout');
      }
    }, this.handshakeTimeoutMs);
    if (timer.unref) timer.unref();

    session.on('uplink', (chunk) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
      try {
        this.ws.send(encodeDataFrame(id, chunk), { binary: true });
      } catch {
        session.close('wss send failed');
      }
    });

    session.on('open', () => clearTimeout(timer));
    session.on('close', () => {
      clearTimeout(timer);
      this.sessions.delete(id);
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        try { this.ws.send(controlMessage('close', { sessionId: id })); } catch { /* 忽略 */ }
      }
    });

    this.ws.send(controlMessage('connect', { sessionId: id, host, port, mode }));
    return session;
  }

  close() {
    this.stopped = true;
    this._clearReconnect();
    this._stopPing();
    for (const session of [...this.sessions.values()]) session.close('tunnel shutdown');
    this.sessions.clear();
    if (this.ws) {
      try { this.ws.close(); } catch { /* 忽略 */ }
      try { this.ws.terminate?.(); } catch { /* 忽略 */ }
    }
    this.ws = null;
    this.ready = false;
  }

  stats() {
    return {
      ready: this.ready,
      sessions: this.sessions.size,
      url: this.url,
    };
  }
}
