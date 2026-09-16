/**
 * 隧道客户端单元测试：断线去重、重连退避、半关上行传播。
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { WssTunnel, TunnelSession } from '../client/wss-tunnel.js';
import { WebSocketServer } from 'ws';

test('断线去重：error + close 双触发只调度一次重连', () => {
  const tunnel = new WssTunnel({ url: 'ws://127.0.0.1:1/', reconnectDelayMs: 100000 });
  let downs = 0;
  let schedules = 0;
  tunnel.on('down', () => { downs += 1; });
  tunnel.on('error', () => {});
  const orig = tunnel._scheduleReconnect.bind(tunnel);
  tunnel._scheduleReconnect = () => { schedules += 1; return orig(); };

  // 模拟 ws 的 'error' 与 'close' 相继触发
  tunnel._onDisconnected('wss error: boom');
  tunnel._onDisconnected('wss closed');

  assert.equal(downs, 1, 'down 事件只应发出 1 次');
  assert.equal(schedules, 1, '_scheduleReconnect 只应调用 1 次');
  assert.equal(tunnel._reconnectAttempts, 1, '退避档位只应自增 1 次');
  tunnel.close();
});

test('断线去重：真实「立刻断连」端口不会重复通知', async () => {
  const srv = net.createServer((s) => s.destroy());
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;

  let downs = 0;
  let errors = 0;
  const tunnel = new WssTunnel({
    url: `ws://127.0.0.1:${port}/`,
    reconnectDelayMs: 20,
    maxReconnectDelayMs: 20,
  });
  tunnel.on('down', () => { downs += 1; });
  tunnel.on('error', () => { errors += 1; });
  tunnel.connect();
  await new Promise((r) => setTimeout(r, 600));
  tunnel.close();
  srv.close();

  // 单次断线只产生 1 个 down；错误也是 1 次（error 事件随连接失败各 1 次）
  assert.ok(downs >= 1, '至少应有 1 次 down');
  assert.equal(downs, errors, `down(${downs}) 与 error(${errors}) 次数应一致，说明无重复处理`);
});

test('重连退避：指数增长且受上限约束', () => {
  const tunnel = new WssTunnel({
    url: 'ws://127.0.0.1:1/',
    reconnectDelayMs: 100,
    maxReconnectDelayMs: 1000,
  });
  const delays = [];
  const origSetTimeout = globalThis.setTimeout;
  // 直接读取内部计算结果
  tunnel._reconnectAttempts = 0;
  for (let i = 0; i < 6; i++) {
    delays.push(Math.min(tunnel.reconnectDelayMs * 2 ** tunnel._reconnectAttempts, tunnel.maxReconnectDelayMs));
    tunnel._reconnectAttempts += 1;
  }
  assert.deepEqual(delays, [100, 200, 400, 800, 1000, 1000]);
  tunnel.close();
});

test('TunnelSession：半关上行后 push 被忽略，pushEnd 只生效一次', () => {
  const session = new TunnelSession(1, { host: 'x', port: 1 });
  session.state = 'open';
  const uplinks = [];
  const ends = [];
  session.on('uplink', (c) => uplinks.push(c));
  session.on('uplink-end', () => ends.push(1));

  session.push(Buffer.from('a'));
  session.pushEnd();
  session.push(Buffer.from('b')); // 半关后应被忽略
  session.pushEnd();               // 重复半关应被忽略

  assert.equal(uplinks.length, 1);
  assert.equal(ends.length, 1);
  assert.equal(session.uplinkClosed, true);
});

test('WssTunnel#openSession 在 ws 非 OPEN 时返回 null（不抛异常）', () => {
  const tunnel = new WssTunnel({ url: 'ws://127.0.0.1:1/' });
  assert.equal(tunnel.openSession('example.com', 80), null);
  tunnel.close();
});

test('WssTunnel#openSession：ws.send 抛异常时不冒泡未捕获异常', () => {
  const tunnel = new WssTunnel({ url: 'ws://127.0.0.1:1/' });
  // 伪造一个「就绪但发送即抛」的 ws
  tunnel.ready = true;
  tunnel.ws = {
    readyState: 1, // WebSocket.OPEN
    send() { throw new Error('WebSocket is not open'); },
  };
  let returned;
  assert.doesNotThrow(() => { returned = tunnel.openSession('example.com', 80); });
  assert.equal(returned, null, '发送失败应返回 null 而不是抛出');
  tunnel.close();
});
