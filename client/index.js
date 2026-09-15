#!/usr/bin/env node
/**
 * Windows 客户端入口
 *
 * 启动流程：
 *   1. 加载配置（本地端口、远端 WSS 地址、证书校验开关等）
 *   2. 建立 WSS 长连接隧道（自动重连 + 心跳）
 *   3. 启动本地用户态 HTTP 代理，监听 127.0.0.1:8080
 *
 * 纯用户态运行：不创建虚拟网卡、不装驱动、不改动全局路由表。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WssTunnel } from './wss-tunnel.js';
import { createHttpProxy } from './http-proxy.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const DEFAULTS = {
  /** 本地代理监听地址（方案固定项：127.0.0.1:8080） */
  listenHost: '127.0.0.1',
  listenPort: 8080,
  /** 远端代理服务端 WSS 地址（方案固定项：根路径 /） */
  serverUrl: 'wss://proxy.example.com/',
  /** 是否校验服务端证书，自签证书场景可置 false（生产建议 true） */
  rejectUnauthorized: true,
  /** WSS 建连超时 */
  connectTimeoutMs: 10000,
  /** 单会话隧道建连超时 */
  handshakeTimeoutMs: 15000,
  /** 重连退避 */
  reconnectDelayMs: 500,
  maxReconnectDelayMs: 15000,
  /** 应用层心跳间隔 */
  pingIntervalMs: 25000,
  /** 本地同时活跃会话上限 */
  maxSessions: 1024,
  /** 预置 extraCA 证书文件路径（企业自签 CA） */
  caFile: '',
};

function loadConfig() {
  const file = process.env.PROXY_CLIENT_CONFIG || path.join(__dirname, 'config.json');
  let cfg = {};
  if (fs.existsSync(file)) {
    try {
      cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (err) {
      console.error(`[warn] config parse failed: ${file}: ${err.message}`);
    }
  }
  const merged = { ...DEFAULTS, ...cfg };
  if (process.env.PROXY_SERVER_URL) merged.serverUrl = process.env.PROXY_SERVER_URL;
  if (process.env.PROXY_LISTEN_PORT) merged.listenPort = Number(process.env.PROXY_LISTEN_PORT);
  if (process.env.PROXY_LISTEN_HOST) merged.listenHost = process.env.PROXY_LISTEN_HOST;
  return merged;
}

/** 给 ws 客户端注入自定义 CA / TLS 选项 */
function buildWsOptions(cfg) {
  const opts = { handshakeTimeout: cfg.connectTimeoutMs };
  if (cfg.rejectUnauthorized === false) opts.rejectUnauthorized = false;
  if (cfg.caFile) {
    try {
      opts.ca = fs.readFileSync(cfg.caFile);
    } catch (err) {
      console.error(`[warn] read caFile failed: ${err.message}`);
    }
  }
  return opts;
}

export function startClient(cfg = loadConfig()) {
  const tunnel = new WssTunnel({
    url: cfg.serverUrl,
    connectTimeoutMs: cfg.connectTimeoutMs,
    handshakeTimeoutMs: cfg.handshakeTimeoutMs,
    reconnectDelayMs: cfg.reconnectDelayMs,
    maxReconnectDelayMs: cfg.maxReconnectDelayMs,
    pingIntervalMs: cfg.pingIntervalMs,
    maxSessions: cfg.maxSessions,
    wsOptions: buildWsOptions(cfg),
  });

  tunnel.on('ready', () => console.log(`[tunnel] connected -> ${cfg.serverUrl}`));
  tunnel.on('down', (reason) => console.warn(`[tunnel] down: ${reason} (auto reconnecting)`));
  tunnel.on('error', (err) => console.error(`[tunnel] error: ${err.message}`));

  tunnel.connect();

  const proxy = createHttpProxy({ tunnel, log: (m) => console.log(`[proxy] ${m}`) });
  proxy.on('error', (err) => console.error(`[proxy] error: ${err.message}`));

  return new Promise((resolve, reject) => {
    proxy.once('error', reject);
    proxy.listen(cfg.listenPort, cfg.listenHost, () => {
      console.log(`[proxy] listening on http://${cfg.listenHost}:${cfg.listenPort}`);
      console.log('[hint] 在 Windows「设置 → 网络和 Internet → 代理」中开启手动代理并填入上述地址');
      resolve({ proxy, tunnel, config: cfg });
    });
  });
}

function shutdown({ proxy, tunnel }) {
  console.log('\n[exit] shutting down ...');
  try { tunnel.close(); } catch { /* 忽略 */ }
  try { proxy.close(); } catch { /* 忽略 */ }
  process.exit(0);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const running = await startClient();
  process.on('SIGINT', () => shutdown(running));
  process.on('SIGTERM', () => shutdown(running));
}
