/**
 * 端到端集成测试：本地 HTTP 代理 → WSS 隧道 → 服务端 → 目标服务器
 *
 * 测试夹具说明：
 *   - 「目标服务器」跑在 127.0.0.1 上，属于 SSRF 拦截网段，因此服务端注入
 *     connectOverride 把「校验通过的 IP」映射到本地目标，仅用于测试。
 *   - lookup 注入为固定的公网 IP，模拟正常 DNS 解析结果。
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import { createServer } from '../server/index.js';
import { startClient } from '../client/index.js';

const FAKE_PUBLIC_IP = '203.0.113.10';

/** 搭建一套完整链路 */
async function setup() {
  // 目标：TCP echo + HTTP server
  const echo = net.createServer((sock) => {
    sock.on('data', (d) => sock.write(Buffer.concat([Buffer.from('ECHO:'), d])));
  });
  await new Promise((r) => echo.listen(0, '127.0.0.1', r));
  const echoPort = echo.address().port;

  const web = http.createServer((req, res) => {
    if (req.method === 'POST') {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`POST-ECHO:${Buffer.concat(chunks).toString()}`);
      });
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`WEB-OK target=${req.url}`);
  });
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const webPort = web.address().port;

  // 代理服务端（明文 WS 仅测试用）
  const proxyServer = createServer({
    port: 0,
    host: '127.0.0.1',
    idleTimeoutMs: 30000,
    maxSessionsPerConnection: 64,
    maxSessionsPerIp: 64,
    lookup: async () => [{ address: FAKE_PUBLIC_IP, family: 4 }],
    connectOverride: () => '127.0.0.1',
  });
  await new Promise((r) => proxyServer.listen(0, '127.0.0.1', r));
  const serverPort = proxyServer.address().port;

  // 客户端：本地代理 127.0.0.1:0（随机端口）
  const { proxy, tunnel } = await startClient({
    listenHost: '127.0.0.1',
    listenPort: 0,
    serverUrl: `ws://127.0.0.1:${serverPort}/`,
    rejectUnauthorized: false,
    pingIntervalMs: 60000,
    reconnectDelayMs: 100,
  });
  const proxyPort = proxy.address().port;
  await waitFor(() => tunnel.ready, 3000);

  return {
    echoPort, webPort, proxyPort, proxy, tunnel, proxyServer, echo, web,
    async close() {
      tunnel.close();
      await new Promise((r) => proxy.close(r));
      await new Promise((r) => proxyServer.close(r));
      await new Promise((r) => echo.close(r));
      await new Promise((r) => web.close(r));
    },
  };
}

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

/** 发一条 CONNECT，返回 { banner, sock } */
function connectVia(proxyPort, target) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(proxyPort, '127.0.0.1');
    sock.on('connect', () => sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    sock.once('data', (banner) => resolve({ banner: banner.toString(), sock }));
    sock.once('error', reject);
    setTimeout(() => reject(new Error('CONNECT timeout')), 5000);
  });
}

test('CONNECT：原始 TCP 双向透传', async (t) => {
  const env = await setup();
  t.after(() => env.close());

  const { banner, sock } = await connectVia(env.proxyPort, `any.public.test:${env.echoPort}`);
  assert.match(banner, /^HTTP\/1\.1 200 Connection Established/);

  sock.write('HELLO');
  const echoed = await new Promise((r) => sock.once('data', r));
  assert.equal(echoed.toString(), 'ECHO:HELLO');
  sock.destroy();
});

test('CONNECT：二进制字节零损耗（不做 Base64）', async (t) => {
  const env = await setup();
  t.after(() => env.close());

  const { sock } = await connectVia(env.proxyPort, `any.public.test:${env.echoPort}`);
  // 覆盖全部 256 种字节值
  const payload = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
  sock.write(payload);
  const resp = await new Promise((r) => sock.once('data', r));
  assert.equal(resp.subarray(0, 5).toString(), 'ECHO:');
  assert.deepEqual(resp.subarray(5), payload);
  sock.destroy();
});

test('普通明文 HTTP：绝对 URL 原样透传', async (t) => {
  const env = await setup();
  t.after(() => env.close());

  const body = await new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: env.proxyPort,
        method: 'GET',
        path: `http://any.public.test:${env.webPort}/some/path`,
        headers: { Host: `any.public.test:${env.webPort}` },
      },
      (res) => {
        let b = '';
        res.on('data', (d) => (b += d));
        res.on('end', () => resolve(b));
      },
    );
    req.on('error', reject);
    req.end();
  });
  assert.match(body, /WEB-OK/);
  assert.match(body, /http:\/\/any\.public\.test/);
});

test('多路复用：一条 WSS 连接承载多个并发会话', async (t) => {
  const env = await setup();
  t.after(() => env.close());

  const ids = await Promise.all(
    [1, 2, 3, 4, 5, 6, 7, 8].map(
      (i) =>
        new Promise((resolve, reject) => {
          const sock = net.connect(env.proxyPort, '127.0.0.1');
          let buf = '';
          sock.on('connect', () =>
            sock.write(`CONNECT any.public.test:${env.echoPort} HTTP/1.1\r\n\r\n`),
          );
          sock.on('data', (d) => {
            buf += d.toString();
            if (buf.includes('Connection Established') && !buf.includes('SENT')) {
              buf += 'SENT';
              sock.write(`MSG-${i}`);
            }
            if (buf.includes(`ECHO:MSG-${i}`)) {
              sock.destroy();
              resolve(i);
            }
          });
          sock.on('error', reject);
          setTimeout(() => reject(new Error(`session ${i} timeout`)), 8000);
        }),
    ),
  );
  assert.equal(ids.length, 8);
  // 会话回收是异步的（客户端 destroy → FIN → 会话关闭），等待归零
  await waitFor(() => env.tunnel.sessions.size === 0, 5000);
  assert.equal(env.tunnel.sessions.size, 0, '所有会话应已释放');
});

test('会话回收：客户端断开后隧道会话归零', async (t) => {
  const env = await setup();
  t.after(() => env.close());

  const { sock } = await connectVia(env.proxyPort, `any.public.test:${env.echoPort}`);
  assert.equal(env.tunnel.sessions.size, 1);
  sock.destroy();
  await waitFor(() => env.tunnel.sessions.size === 0, 3000);
  assert.equal(env.tunnel.sessions.size, 0);
});

test('服务端回收：客户端发 close 后服务端删除会话', async (t) => {
  const env = await setup();
  t.after(() => env.close());

  const { sock } = await connectVia(env.proxyPort, `any.public.test:${env.echoPort}`);
  await waitFor(() => env.tunnel.sessions.size === 1, 2000);
  sock.destroy();
  await waitFor(() => env.tunnel.sessions.size === 0, 3000);
  assert.equal(env.tunnel.sessions.size, 0);
});

test('SSRF：私有地址被拦截，客户端收到 502', async (t) => {
  const env = await setup();
  t.after(() => env.close());

  for (const target of ['10.0.0.5:80', '192.168.1.1:80', '127.0.0.1:80', '[::1]:80']) {
    const { banner, sock } = await connectVia(env.proxyPort, target);
    assert.match(banner, /502/, `${target} 应被拦截`);
    assert.match(banner, /blocked range/);
    sock.destroy();
  }
});

test('SSRF：域名解析到私有地址同样被拦截', async (t) => {
  const env = await setup();
  t.after(() => env.close());
  // 复用服务端配置的 lookup（返回公网 IP），这里临时换成解析到内网
  env.proxyServer.config.lookup = async () => [{ address: '10.1.2.3', family: 4 }];

  const { banner, sock } = await connectVia(env.proxyPort, 'internal.corp:443');
  assert.match(banner, /502/);
  assert.match(banner, /blocked range/);
  sock.destroy();
});

test('隧道未就绪：CONNECT 返回 502', async (t) => {
  const env = await setup();
  t.after(() => env.close());
  // 强断隧道，模拟未连接状态
  env.tunnel.ready = false;
  const { banner, sock } = await connectVia(env.proxyPort, `any.public.test:${env.echoPort}`);
  assert.match(banner, /502/);
  sock.destroy();
});

test('隧道重连：WSS 断开后会话断流且自动恢复', async (t) => {
  const env = await setup();
  t.after(() => env.close());

  env.tunnel.ws.close(); // 模拟链路中断
  await waitFor(() => !env.tunnel.ready, 3000);
  assert.equal(env.tunnel.sessions.size, 0, '断线后全部会话应释放');

  await waitFor(() => env.tunnel.ready, 8000); // 自动重连
  assert.equal(env.tunnel.ready, true);

  // 重连后仍可正常代理
  const { banner, sock } = await connectVia(env.proxyPort, `any.public.test:${env.echoPort}`);
  assert.match(banner, /200/);
  sock.destroy();
});

test('服务端入口：非根路径 Upgrade 一律 400', async (t) => {
  const env = await setup();
  t.after(() => env.close());

  const status = await new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port: env.proxyServer.address().port, path: '/other' },
      (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
      },
    );
    req.on('error', reject);
    req.end();
  });
  assert.equal(status, 400);
});

test('普通明文 HTTP：POST 请求体完整透传（建连期间不丢字节）', async (t) => {
  const env = await setup();
  t.after(() => env.close());

  // 大体积请求体，覆盖「建连尚未就绪」窗口期
  const payload = 'X'.repeat(256 * 1024);
  const body = await new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: env.proxyPort,
        method: 'POST',
        path: `http://any.public.test:${env.webPort}/upload`,
        headers: {
          Host: `any.public.test:${env.webPort}`,
          'Content-Type': 'text/plain',
          'Content-Length': Buffer.byteLength(payload),
        },
      },
      (res) => {
        let b = '';
        res.on('data', (d) => (b += d));
        res.on('end', () => resolve(b));
      },
    );
    req.on('error', reject);
    req.end(payload);
  });
  // 响应走 chunked 编码，这里按「内容是否完整」校验，避免与传输层分帧耦合
  assert.ok(body.startsWith('POST-ECHO:'), `响应应为 POST-ECHO 开头，实际前缀: ${body.slice(0, 40)}`);
  assert.equal(body.length, 'POST-ECHO:'.length + payload.length, '请求体字节数必须一致');
  assert.ok(body.endsWith('X'.repeat(1024)), '请求体尾部必须完整');
});

test('大流量：1MB 双向透传字节零损耗', async (t) => {
  const env = await setup();
  t.after(() => env.close());

  // echo 服务端按「收到的每个 chunk」回一份，因此用固定长度回显来校验字节完整性
  const sink = net.createServer((sock) => {
    let received = 0;
    const target = 1024 * 1024;
    const chunks = [];
    sock.on('data', (d) => {
      received += d.length;
      chunks.push(d);
      if (received >= target) {
        // 把收到的原始字节原样回吐
        sock.end(Buffer.concat(chunks));
      }
    });
  });
  await new Promise((r) => sink.listen(0, '127.0.0.1', r));
  const sinkPort = sink.address().port;
  t.after(() => sink.close());

  const payload = Buffer.alloc(1024 * 1024);
  for (let i = 0; i < payload.length; i++) payload[i] = i & 0xff;

  const { sock } = await connectVia(env.proxyPort, `any.public.test:${sinkPort}`);
  sock.write(payload);

  const chunks = [];
  let total = 0;
  await new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error('timeout')), 20000);
    sock.on('data', (d) => {
      chunks.push(d);
      total += d.length;
      if (total >= payload.length) {
        clearTimeout(to);
        resolve();
      }
    });
    sock.on('error', reject);
    sock.on('end', () => {
      clearTimeout(to);
      resolve();
    });
  });

  const got = Buffer.concat(chunks);
  assert.equal(got.length, payload.length, '回吐字节数应与发送一致');
  assert.ok(got.equals(payload), '1MB 数据必须逐字节一致');
  sock.destroy();
});

test('并发会话：一条 WSS 连接同时承载 32 个会话', async (t) => {
  const env = await setup();
  t.after(() => env.close());
  env.proxyServer.config.maxSessionsPerConnection = 64;

  const N = 32;
  const done = await Promise.all(
    Array.from({ length: N }, (_, i) =>
      new Promise((resolve, reject) => {
        const sock = net.connect(env.proxyPort, '127.0.0.1');
        let buf = '';
        sock.on('connect', () =>
          sock.write(`CONNECT any.public.test:${env.echoPort} HTTP/1.1\r\n\r\n`),
        );
        sock.on('data', (d) => {
          buf += d.toString();
          if (buf.includes('Connection Established') && !buf.includes('SENT')) {
            buf += 'SENT';
            sock.write(`N${i}`);
          }
          if (buf.includes(`ECHO:N${i}`)) {
            sock.destroy();
            resolve(i);
          }
        });
        sock.on('error', reject);
        setTimeout(() => reject(new Error(`session ${i} timeout`)), 15000);
      }),
    ),
  );
  assert.equal(done.length, N);
  await waitFor(() => env.tunnel.sessions.size === 0, 8000);
});

test('CONNECT：客户端在建连完成前发送的数据不丢失', async (t) => {
  const env = await setup();
  t.after(() => env.close());

  const sock = net.connect(env.proxyPort, '127.0.0.1');
  t.after(() => sock.destroy());
  await new Promise((r) => sock.on('connect', r));

  // 请求行与首段数据一次性写入（模拟浏览器 TLS ClientHello 紧随 CONNECT 发出）
  sock.write(
    `CONNECT any.public.test:${env.echoPort} HTTP/1.1\r\nHost: x\r\n\r\nEARLY-BYTES`,
  );

  const chunks = [];
  await new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error('timeout')), 8000);
    sock.on('data', (d) => {
      chunks.push(d);
      const text = Buffer.concat(chunks).toString();
      if (text.includes('ECHO:EARLY-BYTES')) {
        clearTimeout(to);
        resolve();
      }
    });
    sock.on('error', reject);
  });
  assert.match(Buffer.concat(chunks).toString(), /ECHO:EARLY-BYTES/);
});
