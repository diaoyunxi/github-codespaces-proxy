/**
 * 本地用户态 HTTP 代理（127.0.0.1:8080）
 *
 * 关键约束：
 *   - 纯用户态，无网卡、无驱动、无全局路由劫持
 *   - 不本地建立到目标的 TCP 连接，全部经 WSS 隧道
 *   - 同时处理 `CONNECT` 与普通 HTTP 请求
 *
 * 普通明文 HTTP 处理策略（方案第三节「候选 C」）：
 *   本地只解析出请求行中的目标 host:port 与报文边界，然后把**原始请求字节**
 *   原样透传给服务端（保留绝对 URL 形式，即 `GET http://host/path HTTP/1.1`）。
 *   不改写请求行，由上游源服务器按 RFC 7230 语义处理绝对形式 request-target。
 */

import http from 'node:http';
import { URL } from 'node:url';
import { MODE_TCP_OVER_WSS } from '../server/protocol.js';

const DEFAULT_PORTS = { 'http:': 80, 'https:': 443 };

/** 解析绝对形式 request-target，如 `http://example.com:8080/path` */
function parseAbsoluteTarget(target) {
  try {
    const u = new URL(target);
    const port = u.port ? Number(u.port) : DEFAULT_PORTS[u.protocol];
    if (!u.hostname || !port) return null;
    return { host: u.hostname, port };
  } catch {
    return null;
  }
}

/** 解析 Host 头，兜底求 host:port */
function parseHostHeader(hostHeader, defaultPort = 80) {
  if (!hostHeader) return null;
  const value = hostHeader.trim();
  // IPv6 字面量：[::1]:8080
  const m = /^\[(.+)\](?::(\d+))?$/.exec(value);
  if (m) return { host: m[1], port: m[2] ? Number(m[2]) : defaultPort };
  const idx = value.lastIndexOf(':');
  if (idx > -1 && /^\d+$/.test(value.slice(idx + 1))) {
    return { host: value.slice(0, idx), port: Number(value.slice(idx + 1)) };
  }
  return { host: value, port: defaultPort };
}

/**
 * 半关（收到对端 FIN）后的**空闲兜底超时**。
 *
 * TCP 层无法区分「对端只是关了写端、仍在读」（合法半关）
 * 与「对端进程已退出」（连接实际已死）——两者都只表现为收到 FIN。
 * 因此策略是：半关后保留下行继续读取，但只要「无任何下行数据」持续
 * 超过该时长，就判定连接已死并回收，避免会话无限滞留。
 * 期间任何下行数据都会重置该计时。
 */
const DEFAULT_HALF_CLOSE_IDLE_MS = 3000;

/**
 * 监听客户端 socket 的**真正断开**信号。
 *
 * 关键语义区分：
 *   - 'end'   == 对端发了 FIN，**只表示不再发送数据（半关写端）**。
 *               此时客户端仍在等响应，绝不能杀掉会话。
 *   - 'close' == 连接彻底关闭，此时才能回收会话。
 *
 * 「请求发完 → shutdown 写端 → 等响应」是合法且常见的用法
 * （HTTP/1.0 客户端、部分语言 SDK、隧道内半关闭）。
 * 若把 'end' 当作断开处理，响应会被整段丢弃。
 *
 * @param {net.Socket} sock
 * @param {(reason: string) => void} onGone 仅在真正断开时回调一次
 * @returns {(reason: string) => void} 供调用方主动触发的 fire
 */
function watchClientGone(sock, onGone, onHalfClose) {
  let fired = false;
  const fire = (reason) => {
    if (fired) return;
    fired = true;
    onGone(reason);
  };
  // 半关：只关上行方向，不杀会话；下行继续，直到会话自然关闭。
  // 滞留风险由调用方的空闲兜底超时兜住。
  sock.on('end', () => {
    if (sock.__halfClosed) return;
    sock.__halfClosed = true;
    if (onHalfClose) onHalfClose();
  });
  sock.on('close', () => fire('client closed'));
  sock.on('error', () => fire('client socket error'));
  return fire;
}

/**
 * 让 socket 脱离 http.Server 的生命周期管理，改为由我们手工读写原始字节。
 *
 * 仅调 `res.detachSocket()` 不够：http.Server 会在 socket 上保留
 * `bound socketOnEnd` 监听器，客户端半关（FIN）时它会直接 `socket.end()`，
 * 把还在等响应的连接掐掉。这里一并摘除该监听器。
 *
 * @param {net.Socket} sock
 */
function detachFromHttpServer(sock) {
  for (const listener of sock.listeners('end')) {
    if (String(listener.name).includes('socketOnEnd')) {
      sock.removeListener('end', listener);
    }
  }
}

/** 给客户端回一条纯文本错误响应并断开 */
function replyError(socket, status, text) {
  const body = Buffer.from(`${status} ${text}\n`, 'utf8');
  socket.write(
    `HTTP/1.1 ${status} ${text}\r\n` +
      'Content-Type: text/plain; charset=utf-8\r\n' +
      `Content-Length: ${body.length}\r\n` +
      'Proxy-Agent: http-over-wss\r\n' +
      'Connection: close\r\n\r\n',
  );
  socket.end(body);
}

/**
 * 把一个本地客户端 socket 接到隧道会话上，做双向管道。
 * @param {net.Socket} clientSock
 * @param {import('./wss-tunnel.js').TunnelSession} session
 * @param {Buffer} [preamble] 建连前已读到的、需补发给目标的首段字节
 * @param {{ armIdleTimer?: () => void }} [hooks] 供调用方驱动的半关兜底钩子
 */
function pipeSession(clientSock, session, preamble, hooks = {}) {
  const idleMs = hooks.halfCloseIdleMs ?? DEFAULT_HALF_CLOSE_IDLE_MS;
  let closed = false;
  // 客户端半关写端后下行仍应继续；仅当长时间无下行数据才兜底回收，
  // 避免「客户端 FIN 后再也不读」导致会话滞留。
  let idleTimer = null;
  const clearIdleTimer = () => {
    clearTimeout(idleTimer);
    idleTimer = null;
  };
  const armIdleTimer = () => {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => teardown('client half-closed idle timeout'), idleMs);
    if (idleTimer.unref) idleTimer.unref();
  };

  const teardown = (reason) => {
    if (closed) return;
    closed = true;
    clearIdleTimer();
    clientSock.destroy();
    session.close(reason);
  };
  // 把空闲兜底超时交给调用方，让「断开 / 半关」由统一入口驱动
  hooks.armIdleTimer = armIdleTimer;

  session.on('data', (chunk) => {
    if (closed || clientSock.destroyed) return;
    // 半关后仍有下行数据 → 会话是活的，重置空闲兜底
    if (clientSock.__halfClosed) armIdleTimer();
    if (!clientSock.write(chunk)) clientSock.pause();
  });
  session.on('error', (err) => {
    // 会话建立失败：若还没给客户端回过任何东西，回 502
    if (!clientSock.headersSent && clientSock.writable && !closed) {
      try {
        replyError(clientSock, 502, `Bad Gateway: ${err.message}`);
      } catch { /* 忽略 */ }
    }
    teardown(`session error: ${err.message}`);
  });
  session.on('close', (reason) => {
    if (closed) return;
    closed = true;
    clearIdleTimer();
    clientSock.end();
    // 对端迟迟不发 FIN 时兜底强制释放
    const t = setTimeout(() => clientSock.destroy(), 5000);
    if (t.unref) t.unref();
    clientSock.once('close', () => clearTimeout(t));
  });

  // 上行：本地 → 隧道。
  // 半关（'end'）后不再有上行数据，但下行必须继续，直到会话关闭。
  // 断开 / 半关的监听由调用方（connect 分支）统一注册，避免重复注册。
  clientSock.on('data', (chunk) => {
    if (session.state === 'closed') return;
    session.push(chunk);
  });

  if (preamble && preamble.length) session.push(preamble);
}

/**
 * 创建本地 HTTP 代理服务器。
 *
 * @param {object} opts
 * @param {import('./wss-tunnel.js').WssTunnel} opts.tunnel
 * @param {(msg: string) => void} [opts.log]
 * @returns {http.Server}
 */
export function createHttpProxy({ tunnel, log = () => {}, halfCloseIdleMs = DEFAULT_HALF_CLOSE_IDLE_MS }) {
  const server = http.createServer();

  // ---- 普通明文 HTTP 请求 ----
  //
  // 关键：不通过 ServerResponse 回写响应体。
  // 上游返回的是「已带 Content-Length / chunked 分帧的原始 HTTP 响应」，
  // 若交给 ServerResponse 包装会被二次分帧，导致报文损坏、大响应解析失败。
  // 因此这里把响应**原样**写到客户端 socket 上，ServerResponse 仅用于
  // 在建立阶段回错误（此时还未接管 socket）。
  server.on('request', (req, res) => {
    const clientSock = res.socket;
    let target = null;

    if (/^https?:\/\//i.test(req.url)) {
      // 绝对形式 request-target（标准 HTTP 代理用法）
      target = parseAbsoluteTarget(req.url);
    }
    if (!target) {
      // 兜底：按 Host 头 + 默认端口
      target = parseHostHeader(req.headers.host, 80);
    }
    if (!target) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Bad Request: cannot determine target host\n');
      return;
    }

    const session = tunnel.openSession(target.host, target.port, MODE_TCP_OVER_WSS);
    if (!session) {
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end('Bad Gateway: tunnel not ready\n');
      return;
    }

    // 重建原始请求行 + 头部（原样透传，不改写 request-target）
    // 注意：必须剥离逐跳（hop-by-hop）头与代理专有头，否则会和上游连接语义冲突。
    const HOP_BY_HOP = /^(proxy-connection|proxy-authorization|proxy-authenticate|keep-alive|transfer-encoding|connection|upgrade|te|trailer)$/i;
    const lines = [`${req.method} ${req.url} HTTP/${req.httpVersion}`];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const name = req.rawHeaders[i];
      const value = req.rawHeaders[i + 1];
      if (HOP_BY_HOP.test(name)) continue;
      lines.push(`${name}: ${value}`);
    }
    // 明确要求上游关闭连接：本实现按「一个请求一条隧道会话」处理，
    // 不做上游 keep-alive 复用，避免响应边界错乱。
    lines.push('Connection: close');
    const head = Buffer.from(lines.join('\r\n') + '\r\n\r\n', 'latin1');

    // 立刻摘除 ServerResponse 对 socket 的控制权。
    // 我们已经改为手工透传原始报文字节，若让 res 继续管理 socket，
    // 它会在「响应结束时」自动写头 / end / 触发 keep-alive 超时，破坏报文。
    // 也顺带阻止 http.Server 在此连接上再解析后续请求。
    res.detachSocket?.(clientSock);
    // 逐 socket 开启半开：客户端发完请求后 FIN（半关写端）是合法用法，
    // 此时仍需把响应写回；默认行为会立即 end 掉写方向导致响应丢失。
    clientSock.allowHalfOpen = true;
    // 一并摘除 http.Server 挂在 socket 上的 `socketOnEnd`：
    // 它会在客户端半关时直接 end 掉 socket，导致响应无法回写。
    detachFromHttpServer(clientSock);

    // 建连期间的请求体先缓存，收到 connected 后再按序补发，
    // 避免「会话尚未就绪」时丢字节。
    let opened = false;
    const pending = [];

    session.on('open', () => {
      opened = true;
      // 上行：原始请求字节 → 隧道（顺序敏感：head → 已缓存请求体 → 最后的半关）
      session.push(head);
      for (const chunk of pending) session.push(chunk);
      pending.length = 0;
      // 会话就绪前客户端已半关：现在补发上行 EOF
      if (clientSock.__halfPending) onClientHalfClose();
    });

    req.on('data', (chunk) => {
      if (session.state === 'closed') return;
      if (opened) session.push(chunk);
      else pending.push(chunk);
    });
    req.on('error', () => session.close('client request error'));

    // 客户端半关写端（请求已发完、不再发数据）是合法用法：
    // 只停止上行，绝不能关会话 —— 否则响应整段丢失。
    // 半关后若无任何下行数据，用空闲兜底超时回收会话，防滞留。
    let halfCloseTimer = null;
    const clearHalfCloseTimer = () => {
      clearTimeout(halfCloseTimer);
      halfCloseTimer = null;
    };
    const armHalfCloseTimer = () => {
      clearTimeout(halfCloseTimer);
      halfCloseTimer = setTimeout(() => {
        if (session.state !== 'closed') session.close('client half-closed idle timeout');
        if (!clientSock.destroyed) clientSock.destroy();
      }, halfCloseIdleMs);
      if (halfCloseTimer.unref) halfCloseTimer.unref();
    };
    // 仅当**客户端 socket 半关**（收到 FIN）才向目标传播上行 EOF。
    // 注意不能用 `req 'end'`：请求体读完不代表连接关闭（keep-alive / 流水线），
    // 过早发 FIN 会让目标提前结束、响应丢失。
    // 注意：去重由 watchClientGone 负责（每个 socket 只会回调一次），
    // 这里不要再用 __halfClosed 判断，否则会导致半关被漏处理、
    // 上行 FIN 永远传不到目标。
    const onClientHalfClose = () => {
      if (clientSock.destroyed || session.state === 'closed') return;
      // 会话未就绪：等 open 回调里补发 head/pending 后再发半关，
      // 否则 FIN 可能早于请求字节到达目标。
      if (!opened) return;
      session.pushEnd();
      armHalfCloseTimer();
    };

    // 下行：隧道 → 客户端 socket（原样字节）
    session.on('data', (chunk) => {
      if (clientSock.destroyed) return;
      // 半关后仍有下行数据 → 会话活着，重置空闲兜底
      if (clientSock.__halfClosed) armHalfCloseTimer();
      clientSock.write(chunk);
    });
    session.on('close', () => {
      clearHalfCloseTimer();
      if (!clientSock.destroyed) clientSock.end();
    });
    session.on('error', (err) => {
      clearHalfCloseTimer();
      // 建连失败：此时还未向客户端写过任何东西，回 502
      if (!clientSock.destroyed && !opened) {
        try {
          replyError(clientSock, 502, `Bad Gateway: ${err.message}`);
        } catch { /* 忽略 */ }
      } else if (!clientSock.destroyed) {
        clientSock.destroy();
      }
    });

    // 客户端真正断开（非半关）：立即释放会话；
    // 半关（收到 FIN）则只传播上行 EOF，保留下行
    watchClientGone(
      clientSock,
      (reason) => {
        clearHalfCloseTimer();
        if (session.state !== 'closed') session.close(reason);
      },
      () => {
        if (!opened) {
          clientSock.__halfPending = true;
          return;
        }
        onClientHalfClose();
      },
    );
  });

  // ---- HTTPS / 任意 TCP 的 CONNECT 隧道 ----
  server.on('connect', (req, clientSock, head) => {
    const target = parseHostHeader(req.url, 443);
    if (!target) {
      replyError(clientSock, 400, 'Bad Request: invalid CONNECT target');
      return;
    }

    const session = tunnel.openSession(target.host, target.port, MODE_TCP_OVER_WSS);
    if (!session) {
      replyError(clientSock, 502, 'Bad Gateway: tunnel not ready');
      return;
    }
    clientSock.headersSent = false;
    // 逐 socket 开启半开：客户端 FIN（半关写端）后仍需接收下行，
    // 不能像默认那样立即 end 掉写方向。真正的关闭仍由 'close' 感知。
    clientSock.allowHalfOpen = true;
    detachFromHttpServer(clientSock);
    // 必须显式 resume：http.Server 接管过的 socket 默认处于暂停态，
    // 不恢复流动则对端 FIN 不会触发 'end'，会话无法回收。
    clientSock.resume();

    // 建连阶段与管道建立后共用同一套断开/半关处理，避免重复注册
    // 监听器导致「第一个 end 处理把标记吃掉、第二个收不到」。
    let piped = false;
    let pendingHalfClose = false;
    /** pipeSession 暴露的钩子（建立后填充）；同时把半关兜底超时传下去 */
    const hooks = { halfCloseIdleMs };

    watchClientGone(
      clientSock,
      (reason) => {
        // 真正断开：立即释放会话
        if (session.state !== 'closed') session.close(reason);
      },
      () => {
        // 客户端半关写端：只传播上行 EOF，保留下行直到会话关闭
        if (!piped) {
          pendingHalfClose = true;
          return;
        }
        session.pushEnd();
        // 半关后若无下行数据，用空闲兜底超时回收，防会话滞留
        hooks.armIdleTimer?.();
      },
    );

    session.on('open', () => {
      clientSock.headersSent = true;
      clientSock.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: http-over-wss\r\n\r\n');
      // 客户端在请求行后已发出的 TLS ClientHello 需补发给目标
      if (head && head.length) session.push(head);
      piped = true;
      pipeSession(clientSock, session, undefined, hooks);
      if (pendingHalfClose) {
        session.pushEnd();
        hooks.armIdleTimer?.();
      }
    });

    session.on('error', (err) => {
      if (clientSock.destroyed || clientSock.headersSent) return;
      replyError(clientSock, 502, `Bad Gateway: ${err.message}`);
    });
    session.on('close', () => clientSock.destroy());
  });

  // 非 HTTP 流量（理论上不会有）直接断开
  server.on('clientError', (_err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    else socket.destroy();
  });

  server.on('listening', () => log('local http proxy listening'));
  return server;
}
