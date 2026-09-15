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
 * 监听客户端 socket 的断开信号。
 * 必须同时处理 'end'（对端 FIN，半开）与 'close'：
 * http.Server 接管过的 socket 在对端 FIN 后不一定立刻 'close'，
 * 只监听 'close' 会导致会话长期滞留、资源泄漏。
 *
 * @param {net.Socket} sock
 * @param {(reason: string) => void} onGone
 */
function watchClientGone(sock, onGone) {
  let fired = false;
  const fire = (reason) => {
    if (fired) return;
    fired = true;
    onGone(reason);
  };
  sock.on('end', () => fire('client half-closed'));
  sock.on('close', () => fire('client closed'));
  sock.on('error', () => fire('client socket error'));
  return fire;
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
 */
function pipeSession(clientSock, session, preamble) {
  let closed = false;
  const teardown = (reason) => {
    if (closed) return;
    closed = true;
    clientSock.destroy();
    session.close(reason);
  };

  session.on('data', (chunk) => {
    if (closed || clientSock.destroyed) return;
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
    clientSock.end();
    // 对端迟迟不发 FIN 时兜底强制释放
    const t = setTimeout(() => clientSock.destroy(), 5000);
    if (t.unref) t.unref();
    clientSock.once('close', () => clearTimeout(t));
  });

  // 上行：本地 → 隧道
  clientSock.on('data', (chunk) => {
    if (session.state === 'closed') return;
    session.push(chunk);
  });
  watchClientGone(clientSock, (reason) => teardown(reason));

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
export function createHttpProxy({ tunnel, log = () => {} }) {
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

    // 建连期间的请求体先缓存，收到 connected 后再按序补发，
    // 避免「会话尚未就绪」时丢字节。
    let opened = false;
    const pending = [];

    session.on('open', () => {
      opened = true;
      // 上行：原始请求字节 → 隧道
      session.push(head);
      for (const chunk of pending) session.push(chunk);
      pending.length = 0;
    });

    req.on('data', (chunk) => {
      if (session.state === 'closed') return;
      if (opened) session.push(chunk);
      else pending.push(chunk);
    });
    req.on('error', () => session.close('client request error'));

    // 下行：隧道 → 客户端 socket（原样字节）
    session.on('data', (chunk) => {
      if (!clientSock.destroyed) clientSock.write(chunk);
    });
    session.on('close', () => {
      if (!clientSock.destroyed) clientSock.end();
    });
    session.on('error', (err) => {
      // 建连失败：此时还未向客户端写过任何东西，回 502
      if (!clientSock.destroyed && !opened) {
        try {
          replyError(clientSock, 502, `Bad Gateway: ${err.message}`);
        } catch { /* 忽略 */ }
      } else if (!clientSock.destroyed) {
        clientSock.destroy();
      }
    });

    // 客户端提前断开：立即释放会话
    watchClientGone(clientSock, (reason) => {
      if (session.state !== 'closed') session.close(reason);
    });
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
    // 必须显式 resume：http.Server 接管过的 socket 默认处于暂停态，
    // 不恢复流动则对端 FIN 不会触发 'end'，会话无法回收。
    clientSock.resume();

    session.on('open', () => {
      clientSock.headersSent = true;
      clientSock.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: http-over-wss\r\n\r\n');
      // 客户端在请求行后已发出的 TLS ClientHello 需补发给目标
      if (head && head.length) session.push(head);
      pipeSession(clientSock, session);
    });

    session.on('error', (err) => {
      if (clientSock.destroyed || clientSock.headersSent) return;
      replyError(clientSock, 502, `Bad Gateway: ${err.message}`);
    });
    session.on('close', () => clientSock.destroy());

    // 建连阶段（管道尚未建立）也要感知客户端断开
    watchClientGone(clientSock, (reason) => {
      if (session.state !== 'closed') session.close(reason);
    });
  });

  // 非 HTTP 流量（理论上不会有）直接断开
  server.on('clientError', (_err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    else socket.destroy();
  });

  server.on('listening', () => log('local http proxy listening'));
  return server;
}
