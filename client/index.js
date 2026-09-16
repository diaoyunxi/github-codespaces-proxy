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
  /**
   * 客户端半关写端后的空闲兜底超时（毫秒）。
   * TCP 无法区分「半关仍在等响应」与「进程已退出」，故以
   * 「无任何下行数据持续该时长」判定连接已死并回收会话。
   */
  halfCloseIdleMs: 3000,
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

  const proxy = createHttpProxy({
    tunnel,
    log: (m) => console.log(`[proxy] ${m}`),
    halfCloseIdleMs: cfg.halfCloseIdleMs,
  });
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

/**
 * 优雅关停。
 *
 * 顺序很关键：
 *   1. 先关隧道 —— 主动向服务端回收所有会话，让在途连接收到 close 而不是被硬切
 *   2. 再关本地监听 —— 停止接受新连接（不会关闭已建立连接）
 *   3. 给一个短超时的优雅窗口，等待在途会话自然结束
 *   4. 最后退出；窗口超时则强制退出
 *
 * 去重：连按 Ctrl+C 不应重复执行。
 */
const SHUTDOWN_GRACE_MS = 1500;
let shuttingDown = false;

async function shutdown({ proxy, tunnel }) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log('\n[exit] shutting down ...');

  // 1) 关隧道：服务端据此回收全部会话
  try { tunnel.close(); } catch { /* 忽略 */ }

  // 2) 关本地监听，停止接受新连接
  await new Promise((resolve) => {
    try {
      proxy.close(() => resolve());
    } catch {
      resolve();
    }
  });

  // 3) 优雅窗口：给在途会话一点收尾时间，超时则强制退出
  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      console.warn(`[exit] graceful window (${SHUTDOWN_GRACE_MS}ms) elapsed, forcing exit`);
      resolve();
    }, SHUTDOWN_GRACE_MS);
    timer.unref?.();
    // 若没有活跃连接，事件循环已空，直接结束
    if (proxy.listening === false && tunnel.sessions.size === 0) {
      clearTimeout(timer);
      resolve();
    }
  });
  console.log('[exit] bye');
  process.exit(0);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));
if (isMain) {
  // 顶层 await 失败要给出友好错误而非未捕获异常
  // （tunnel.connect() 的失败是事件而非 reject，因此这里主要兜住 listen 失败等）
  let running;
  try {
    running = await startClient();
  } catch (err) {
    console.error(`[fatal] 客户端启动失败: ${err.message}`);
    process.exit(1);
  }
  process.on('SIGINT', () => { shutdown(running); });
  process.on('SIGTERM', () => { shutdown(running); });
}
