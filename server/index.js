#!/usr/bin/env node
/**
 * 代理服务端 —— 唯一入口 `wss://<host>/`
 *
 * 约束（方案固定不可修改项）：
 *   - 只有根路径一个入口，其余路由一律 400
 *   - 只接受 WebSocket Upgrade，普通 HTTP 请求返回 400
 *   - 不做 WSS 入口认证
 *   - 传输模式 tcp-over-wss：建立原始 TCP，不 TLS 握手、不解析、只透传
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import { WebSocketServer } from 'ws';
import { SessionManager } from './session.js';
import { parseControlMessage, isValidSessionId, isValidPort } from './protocol.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** 默认配置，可被 config.json / 环境变量覆盖 */
const DEFAULTS = {
  /** WSS/HTTPS 监听端口 */
  port: 8443,
  /** 监听地址 */
  host: '0.0.0.0',
  /** PEM 证书路径（同时提供 cert+key 才启用 HTTPS，否则降级为 HTTP，仅用于内网调试） */
  tlsCert: '',
  tlsKey: '',
  /** 目标连接超时 */
  connectTimeoutMs: 10000,
  /** 会话空闲超时（读写静默超过该时间回收） */
  idleTimeoutMs: 120000,
  /** 单条 WSS 连接最大并发会话数 */
  maxSessionsPerConnection: 256,
  /** 单客户端 IP 最大并发会话数（跨多条 WSS 连接累计） */
  maxSessionsPerIp: 512,
  /** DNS 解析函数，便于测试注入 */
  lookup: (host) => dns.promises.lookup(host, { all: true, verbatim: true }),
};

function loadConfig() {
  const file = process.env.PROXY_CONFIG || path.join(process.cwd(), 'server', 'config.json');
  let cfg = {};
  if (fs.existsSync(file)) {
    try {
      cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (err) {
      console.error(`[warn] config parse failed: ${file}: ${err.message}`);
    }
  }
  const merged = { ...DEFAULTS, ...cfg };
  if (process.env.PROXY_PORT) merged.port = Number(process.env.PROXY_PORT);
  if (process.env.PROXY_HOST) merged.host = process.env.PROXY_HOST;
  if (process.env.PROXY_TLS_CERT) merged.tlsCert = process.env.PROXY_TLS_CERT;
  if (process.env.PROXY_TLS_KEY) merged.tlsKey = process.env.PROXY_TLS_KEY;
  return merged;
}

/** 单 IP 并发计数 */
const perIpCount = new Map();

function incIp(ip) {
  perIpCount.set(ip, (perIpCount.get(ip) || 0) + 1);
}

function decIp(ip) {
  const n = (perIpCount.get(ip) || 0) - 1;
  if (n <= 0) perIpCount.delete(ip);
  else perIpCount.set(ip, n);
}

function getIp(req) {
  return (
    req.socket.remoteAddress ||
    req.headers['x-forwarded-for']?.toString().split(',')[0].trim() ||
    'unknown'
  );
}

export function createServer(config = loadConfig()) {
  const useTls = Boolean(config.tlsCert && config.tlsKey);
  let server;
  if (useTls) {
    server = https.createServer({
      cert: fs.readFileSync(config.tlsCert),
      key: fs.readFileSync(config.tlsKey),
    });
  } else {
    server = http.createServer();
    console.warn('[warn] TLS 未配置，降级为明文 HTTP/WS（仅供内网调试，禁止公网使用）');
  }

  /** 所有活跃 TCP 连接，close() 时统一强制释放，避免句柄滞留 */
  const openSockets = new Set();
  server.on('connection', (socket) => {
    openSockets.add(socket);
    socket.on('close', () => openSockets.delete(socket));
  });

  /** 唯一入口：`/`。其余路径 / 普通请求一律 400 */
  server.on('request', (req, res) => {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('400 Bad Request: this endpoint only accepts WebSocket upgrade on "/"\n');
  });

  const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 * 1024 });

  server.on('upgrade', (req, socket, head) => {
    const url = req.url || '/';
    const pathname = url.split('?')[0];
    if (pathname !== '/') {
      socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
  });

  wss.on('connection', (ws, req) => {
    const clientIp = getIp(req);
    const current = perIpCount.get(clientIp) || 0;
    if (current >= config.maxSessionsPerIp) {
      ws.close(1013, 'per-ip session limit reached');
      return;
    }
    incIp(clientIp);

    const manager = new SessionManager({ ws, clientIp, config });
    manager.start();
    console.log(`[conn] + ${clientIp} (ip sessions=${current + 1})`);

    ws.on('message', (data, isBinary) => {
      if (isBinary) {
        manager.handleData(Buffer.isBuffer(data) ? data : Buffer.from(data));
        return;
      }
      const msg = parseControlMessage(data.toString());
      if (!msg) return;
      switch (msg.type) {
        case 'connect':
          if (!isValidSessionId(msg.sessionId) || typeof msg.host !== 'string' || !isValidPort(msg.port)) {
            ws.send(JSON.stringify({ type: 'error', sessionId: msg.sessionId ?? 0, message: 'invalid connect message' }));
            return;
          }
          manager.handleConnect(msg).catch((err) => {
            ws.send(JSON.stringify({ type: 'error', sessionId: msg.sessionId, message: err.message }));
          });
          break;
        case 'half-close':
          if (isValidSessionId(msg.sessionId)) manager.handleHalfClose(msg);
          break;
        case 'close':
          if (isValidSessionId(msg.sessionId)) manager.handleClose(msg);
          break;
        default:
          ws.send(JSON.stringify({ type: 'error', sessionId: msg.sessionId ?? 0, message: `unknown type: ${msg.type}` }));
      }
    });

    ws.on('close', () => {
      const { sessions } = manager.stats();
      manager.stop();
      decIp(clientIp);
      console.log(`[conn] - ${clientIp} (released ${sessions} sessions)`);
    });

    ws.on('error', (err) => {
      console.error(`[conn] error ${clientIp}: ${err.message}`);
      manager.destroyAll('wss error');
      decIp(clientIp);
    });
  });

  const originalClose = server.close.bind(server);
  /** 关停：先终止所有 WSS 连接与会话，再销毁残留 socket，最后关闭监听 */
  server.close = (cb) => {
    for (const client of wss.clients) {
      try { client.terminate(); } catch { /* 忽略 */ }
    }
    for (const socket of openSockets) {
      try { socket.destroy(); } catch { /* 忽略 */ }
    }
    openSockets.clear();
    return originalClose(cb);
  };

  server.config = config;
  server.wss = wss;
  return server;
}

/** 直接运行时启动 */
const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const config = loadConfig();
  const server = createServer(config);
  server.listen(config.port, config.host, () => {
    const scheme = config.tlsCert && config.tlsKey ? 'wss' : 'ws';
    console.log(`[listen] ${scheme}://${config.host}:${config.port}/`);
  });
}
