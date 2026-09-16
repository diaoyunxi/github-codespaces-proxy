/**
 * SessionManager 单元测试：超时、上限、帧路由、生命周期。
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { SessionManager } from '../server/session.js';
import { encodeDataFrame, decodeDataFrame } from '../server/protocol.js';

/** 造一个假 ws，收集发出的内容 */
function fakeWs() {
  const sent = [];
  return {
    readyState: 1,
    sent,
    send(data, opts) {
      sent.push({ data, binary: Boolean(opts && opts.binary) });
    },
    /** 全部控制消息 */
    get controls() {
      return sent.filter((m) => !m.binary).map((m) => JSON.parse(m.data));
    },
    /** 最后一次控制消息 */
    get lastControl() {
      for (let i = sent.length - 1; i >= 0; i--) {
        if (!sent[i].binary) return JSON.parse(sent[i].data);
      }
      return null;
    },
    /** 收到的所有数据帧 */
    get dataFrames() {
      return sent.filter((m) => m.binary).map((m) => decodeDataFrame(m.data));
    },
  };
}

function makeConfig(overrides = {}) {
  return {
    idleTimeoutMs: 60000,
    connectTimeoutMs: 5000,
    maxSessionsPerConnection: 4,
    lookup: async () => [{ address: '203.0.113.10', family: 4 }],
    connectOverride: () => '127.0.0.1',
    ...overrides,
  };
}

/** 轮询等待条件成立 */
function waitFor(pred, timeoutMs = 3000) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const tick = () => {
      if (pred()) return resolve();
      if (Date.now() - start > timeoutMs) return reject(new Error('waitFor timeout'));
      setTimeout(tick, 20);
    };
    tick();
  });
}

/** 起一个目标服务器 */
async function startTarget(handler) {
  const server = net.createServer(handler || ((sock) => sock.on('data', (d) => sock.write(d))));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, port: server.address().port };
}

test('会话建立：SSRF 通过后建连并回 connected', async (t) => {
  const { server, port } = await startTarget();
  t.after(() => server.close());
  const ws = fakeWs();
  const mgr = new SessionManager({ ws, clientIp: '1.2.3.4', config: makeConfig() });
  mgr.start();
  t.after(() => mgr.stop());

  await mgr.handleConnect({ sessionId: 1, host: 'example.com', port });
  await new Promise((r) => setTimeout(r, 100));
  assert.deepEqual(ws.lastControl, { type: 'connected', sessionId: 1 });
  assert.equal(mgr.stats().open, 1);
});

test('数据帧路由：按 sessionId 分发到对应目标套接字', async (t) => {
  const { server, port } = await startTarget((sock) => {
    sock.on('data', (d) => sock.write(Buffer.concat([Buffer.from('T:'), d])));
  });
  t.after(() => server.close());
  const ws = fakeWs();
  const mgr = new SessionManager({ ws, clientIp: '1.2.3.4', config: makeConfig() });
  mgr.start();
  t.after(() => mgr.stop());

  await mgr.handleConnect({ sessionId: 11, host: 'example.com', port });
  await new Promise((r) => setTimeout(r, 100));
  mgr.handleData(encodeDataFrame(11, Buffer.from('abc')));
  await new Promise((r) => setTimeout(r, 100));

  const frames = ws.dataFrames;
  assert.equal(frames.length, 1);
  assert.equal(frames[0].sessionId, 11);
  assert.equal(frames[0].payload.toString(), 'T:abc');
});

test('数据帧路由：未知 sessionId 静默忽略，不抛错', async (t) => {
  const ws = fakeWs();
  const mgr = new SessionManager({ ws, clientIp: '1.2.3.4', config: makeConfig() });
  mgr.start();
  t.after(() => mgr.stop());

  assert.doesNotThrow(() => mgr.handleData(encodeDataFrame(999, Buffer.from('x'))));
  assert.doesNotThrow(() => mgr.handleData(Buffer.from([1, 2]))); // 帧过短
  assert.doesNotThrow(() => mgr.handleData(Buffer.alloc(0)));
  assert.equal(ws.sent.length, 0);
});

test('SSRF：字面私有 IP 被拒，回 error 且不占用会话', async (t) => {
  const ws = fakeWs();
  const mgr = new SessionManager({ ws, clientIp: '1.2.3.4', config: makeConfig() });
  mgr.start();
  t.after(() => mgr.stop());

  await mgr.handleConnect({ sessionId: 5, host: '192.168.1.1', port: 80 });
  assert.equal(ws.lastControl.type, 'error');
  assert.match(ws.lastControl.message, /blocked range/);
  assert.equal(mgr.stats().sessions, 0);
});

test('SSRF：域名解析到私有地址被拒', async (t) => {
  const ws = fakeWs();
  const mgr = new SessionManager({
    ws,
    clientIp: '1.2.3.4',
    config: makeConfig({ lookup: async () => [{ address: '10.9.9.9', family: 4 }] }),
  });
  mgr.start();
  t.after(() => mgr.stop());

  await mgr.handleConnect({ sessionId: 6, host: 'internal.example', port: 443 });
  assert.equal(ws.lastControl.type, 'error');
  assert.match(ws.lastControl.message, /blocked range/);
  assert.equal(mgr.stats().sessions, 0);
});

test('重复 sessionId 被拒绝', async (t) => {
  const { server, port } = await startTarget();
  t.after(() => server.close());
  const ws = fakeWs();
  const mgr = new SessionManager({ ws, clientIp: '1.2.3.4', config: makeConfig() });
  mgr.start();
  t.after(() => mgr.stop());

  await mgr.handleConnect({ sessionId: 7, host: 'example.com', port });
  await new Promise((r) => setTimeout(r, 50));
  await mgr.handleConnect({ sessionId: 7, host: 'example.com', port });
  assert.equal(ws.lastControl.type, 'error');
  assert.match(ws.lastControl.message, /duplicate sessionId/);
});

test('超单连接会话上限被拒绝', async (t) => {
  const { server, port } = await startTarget();
  t.after(() => server.close());
  const ws = fakeWs();
  const mgr = new SessionManager({
    ws,
    clientIp: '1.2.3.4',
    config: makeConfig({ maxSessionsPerConnection: 2 }),
  });
  mgr.start();
  t.after(() => mgr.stop());

  await mgr.handleConnect({ sessionId: 1, host: 'example.com', port });
  await mgr.handleConnect({ sessionId: 2, host: 'example.com', port });
  await new Promise((r) => setTimeout(r, 50));
  await mgr.handleConnect({ sessionId: 3, host: 'example.com', port });
  assert.equal(ws.lastControl.type, 'error');
  assert.match(ws.lastControl.message, /limit reached/);
});

test('不支持的 mode 被拒绝', async (t) => {
  const ws = fakeWs();
  const mgr = new SessionManager({ ws, clientIp: '1.2.3.4', config: makeConfig() });
  mgr.start();
  t.after(() => mgr.stop());

  await mgr.handleConnect({ sessionId: 8, host: 'example.com', port: 443, mode: 'udp-over-wss' });
  assert.equal(ws.lastControl.type, 'error');
  assert.match(ws.lastControl.message, /unsupported mode/);
});

test('目标建连失败回 error 并回收会话', async (t) => {
  // 占一个端口后立刻关掉，制造 connection refused
  const tmp = net.createServer();
  await new Promise((r) => tmp.listen(0, '127.0.0.1', r));
  const deadPort = tmp.address().port;
  await new Promise((r) => tmp.close(r));

  const ws = fakeWs();
  const mgr = new SessionManager({ ws, clientIp: '1.2.3.4', config: makeConfig() });
  mgr.start();
  t.after(() => mgr.stop());

  await mgr.handleConnect({ sessionId: 9, host: 'example.com', port: deadPort });
  await new Promise((r) => setTimeout(r, 300));

  const types = ws.controls.map((m) => m.type);
  assert.deepEqual(types, ['error', 'close'], '建连失败应先回 error，再回 close 收尾');
  assert.match(ws.controls[0].message, /target socket error|ECONNREFUSED/);
  assert.equal(mgr.stats().sessions, 0);
});

test('客户端 close：目标套接字被销毁，回 close', async (t) => {
  let targetSock = null;
  const { server, port } = await startTarget((sock) => {
    targetSock = sock;
    sock.on('data', (d) => sock.write(d));
  });
  t.after(() => server.close());
  const ws = fakeWs();
  const mgr = new SessionManager({ ws, clientIp: '1.2.3.4', config: makeConfig() });
  mgr.start();
  t.after(() => mgr.stop());

  await mgr.handleConnect({ sessionId: 10, host: 'example.com', port });
  await new Promise((r) => setTimeout(r, 100));
  assert.ok(targetSock);

  mgr.handleClose({ sessionId: 10 });
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(targetSock.destroyed, true);
  assert.equal(mgr.stats().sessions, 0);
  assert.equal(ws.lastControl.type, 'close');
});

test('目标主动关闭：回 close 并回收会话', async (t) => {
  const { server, port } = await startTarget((sock) => {
    sock.on('data', () => sock.end()); // 收到数据就关闭
  });
  t.after(() => server.close());
  const ws = fakeWs();
  const mgr = new SessionManager({ ws, clientIp: '1.2.3.4', config: makeConfig() });
  mgr.start();
  t.after(() => mgr.stop());

  await mgr.handleConnect({ sessionId: 12, host: 'example.com', port });
  await new Promise((r) => setTimeout(r, 80));
  mgr.handleData(encodeDataFrame(12, Buffer.from('go')));
  await new Promise((r) => setTimeout(r, 300));

  assert.equal(ws.lastControl.type, 'close');
  assert.equal(mgr.stats().sessions, 0);
});

test('空闲超时：sweepIdle 回收长时间无活动的会话', async (t) => {
  const { server, port } = await startTarget();
  t.after(() => server.close());
  const ws = fakeWs();
  const mgr = new SessionManager({
    ws,
    clientIp: '1.2.3.4',
    config: makeConfig({ idleTimeoutMs: 60000 }),
  });
  mgr.start();
  t.after(() => mgr.stop());

  await mgr.handleConnect({ sessionId: 13, host: 'example.com', port });
  await new Promise((r) => setTimeout(r, 80));
  assert.equal(mgr.stats().sessions, 1);

  // 手动把 lastActiveAt 推到过去，模拟空闲
  const session = mgr.sessions.get(13);
  session.lastActiveAt = Date.now() - 120000;
  mgr.sweepIdle();
  await new Promise((r) => setTimeout(r, 80));

  assert.equal(mgr.stats().sessions, 0);
  assert.equal(ws.lastControl.type, 'close');
  assert.match(ws.lastControl.reason, /idle timeout/);
});

test('destroyAll：WSS 断开时全部会话释放', async (t) => {
  const { server, port } = await startTarget();
  t.after(() => server.close());
  const ws = fakeWs();
  const mgr = new SessionManager({
    ws,
    clientIp: '1.2.3.4',
    config: makeConfig({ maxSessionsPerConnection: 16 }),
  });
  mgr.start();
  t.after(() => mgr.stop());

  await mgr.handleConnect({ sessionId: 21, host: 'example.com', port });
  await mgr.handleConnect({ sessionId: 22, host: 'example.com', port });
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(mgr.stats().sessions, 2);

  mgr.destroyAll('wss closed');
  await new Promise((r) => setTimeout(r, 80));
  assert.equal(mgr.stats().sessions, 0);
  assert.equal(mgr.closed, true);
});

test('建连后 connect 超时切换为空闲超时', async (t) => {
  const { server, port } = await startTarget();
  t.after(() => server.close());
  const ws = fakeWs();
  const mgr = new SessionManager({
    ws,
    clientIp: '1.2.3.4',
    config: makeConfig({ connectTimeoutMs: 5, idleTimeoutMs: 30000 }),
  });
  mgr.start();
  t.after(() => mgr.stop());

  await mgr.handleConnect({ sessionId: 31, host: 'example.com', port });
  await new Promise((r) => setTimeout(r, 150));
  // connectTimeoutMs=5ms 若未切换成 idleTimeout，会话会被误杀
  assert.equal(mgr.stats().sessions, 1, '建连成功后不应因 connectTimeout 被回收');
  assert.equal(mgr.stats().open, 1);
});

test('half-close：上行 EOF 向目标发 FIN，但保留下行继续读取', async (t) => {
  // 目标半开：收到 FIN 后仍写回一段数据
  const halfOpen = net.createServer({ allowHalfOpen: true }, (sock) => {
    sock.on('end', () => sock.write('AFTER-FIN'));
  });
  await new Promise((r) => halfOpen.listen(0, '127.0.0.1', r));
  t.after(() => halfOpen.close());
  const halfPort = halfOpen.address().port;

  const ws = fakeWs();
  const mgr = new SessionManager({ ws, clientIp: '1.2.3.4', config: makeConfig() });
  mgr.start();
  t.after(() => mgr.stop());

  await mgr.handleConnect({ sessionId: 1, host: 'example.com', port: halfPort });
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(mgr.stats().open, 1);

  mgr.handleHalfClose({ sessionId: 1 });
  const session = mgr.sessions.get(1);
  assert.equal(session.uplinkClosed, true, '会话应标记上行已关');

  // 半关后到达的数据帧应被丢弃，不再写给目标
  assert.equal(session.write(Buffer.from('late')), false);

  // 下行仍应送达客户端
  await waitFor(() => ws.dataFrames.some((f) => f.payload.toString() === 'AFTER-FIN'), 2000);
});

test('half-close：未知 / 非法 sessionId 调用不抛异常', async (t) => {
  const ws = fakeWs();
  const mgr = new SessionManager({ ws, clientIp: '1.2.3.4', config: makeConfig() });
  mgr.start();
  t.after(() => mgr.stop());
  assert.doesNotThrow(() => mgr.handleHalfClose({ sessionId: 999 }));
  assert.doesNotThrow(() => mgr.handleHalfClose({}));
});

test('背压：WSS 缓冲超上限时暂停目标读取，回落后恢复', async (t) => {
  const ws = fakeWs();
  const { server, port } = await startTarget((sock) => sock.write('seed'));
  t.after(() => server.close());

  const mgr = new SessionManager({
    ws,
    clientIp: '1.2.3.4',
    config: makeConfig({ wsBufferedHighWaterMark: 10, wsBufferedLowWaterMark: 2 }),
  });
  mgr.start();
  t.after(() => mgr.stop());

  await mgr.handleConnect({ sessionId: 7, host: 'example.com', port });
  await new Promise((r) => setTimeout(r, 100));
  const session = mgr.sessions.get(7);

  let resumeCalled = 0;
  let pauseCalled = 0;
  session.socket.pause = () => { pauseCalled += 1; };
  session.socket.resume = () => { resumeCalled += 1; };

  // 缓冲越过上限 → 暂停
  ws.bufferedAmount = 100;
  session._onData(Buffer.from('x'));
  assert.equal(session._paused, true, '超上限应暂停读取');
  assert.ok(pauseCalled >= 1);

  // 回落到低水位以下 → 恢复
  ws.bufferedAmount = 0;
  await waitFor(() => resumeCalled >= 1, 2000);
  assert.equal(session._paused, false);
});
