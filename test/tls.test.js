/**
 * 真实 TLS/WSS 链路测试：验证 https + wss 下隧道可用、证书可校验。
 * 使用临时自签证书（SAN: localhost / 127.0.0.1）。
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../server/index.js';
import { startClient } from '../client/index.js';

function hasOpenssl() {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function makeCert(dir) {
  const key = path.join(dir, 'key.pem');
  const cert = path.join(dir, 'cert.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', key, '-out', cert, '-days', '1',
    '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
  ], { stdio: 'ignore' });
  return { key, cert };
}

test('TLS：https + wss 真实链路，证书校验通过且隧道可用', { skip: !hasOpenssl() && 'openssl 不可用' }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'proxy-tls-'));
  const { key, cert } = makeCert(dir);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const echo = net.createServer((sock) => {
    sock.on('data', (d) => sock.write(Buffer.concat([Buffer.from('TLS:'), d])));
  });
  await new Promise((r) => echo.listen(0, '127.0.0.1', r));
  const echoPort = echo.address().port;
  t.after(() => echo.close());

  const proxyServer = createServer({
    port: 0,
    host: '127.0.0.1',
    idleTimeoutMs: 30000,
    maxSessionsPerConnection: 16,
    maxSessionsPerIp: 16,
    tlsCert: cert,
    tlsKey: key,
    lookup: async () => [{ address: '203.0.113.10', family: 4 }],
    connectOverride: () => '127.0.0.1',
  });
  await new Promise((r) => proxyServer.listen(0, '127.0.0.1', r));
  t.after(() => new Promise((r) => proxyServer.close(r)));

  const { proxy, tunnel } = await startClient({
    listenHost: '127.0.0.1',
    listenPort: 0,
    serverUrl: `wss://127.0.0.1:${proxyServer.address().port}/`,
    caFile: cert,
    rejectUnauthorized: true, // 严格校验，用自签 CA 作为信任根
    pingIntervalMs: 60000,
  });
  t.after(async () => {
    tunnel.close();
    await new Promise((r) => proxy.close(r));
  });

  await new Promise((r) => setTimeout(r, 300));
  assert.equal(tunnel.ready, true, 'wss 握手应成功');

  const sock = net.connect(proxy.address().port, '127.0.0.1');
  t.after(() => sock.destroy());
  await new Promise((r) => sock.on('connect', r));
  sock.write(`CONNECT any.public.test:${echoPort} HTTP/1.1\r\n\r\n`);
  const banner = await new Promise((r) => sock.once('data', r));
  assert.match(banner.toString(), /^HTTP\/1\.1 200 Connection Established/);

  sock.write('SECURE');
  const echoed = await new Promise((r) => sock.once('data', r));
  assert.equal(echoed.toString(), 'TLS:SECURE');
});

test('TLS：证书不受信时握手失败，不会静默降级', { skip: !hasOpenssl() && 'openssl 不可用' }, async (t) => {
  const dirA = fs.mkdtempSync(path.join(os.tmpdir(), 'proxy-a-'));
  const dirB = fs.mkdtempSync(path.join(os.tmpdir(), 'proxy-b-'));
  const a = makeCert(dirA);
  const b = makeCert(dirB);
  t.after(() => {
    fs.rmSync(dirA, { recursive: true, force: true });
    fs.rmSync(dirB, { recursive: true, force: true });
  });

  const proxyServer = createServer({
    port: 0, host: '127.0.0.1', tlsCert: a.cert, tlsKey: a.key,
  });
  await new Promise((r) => proxyServer.listen(0, '127.0.0.1', r));
  t.after(() => new Promise((r) => proxyServer.close(r)));

  const { proxy, tunnel } = await startClient({
    listenHost: '127.0.0.1',
    listenPort: 0,
    serverUrl: `wss://127.0.0.1:${proxyServer.address().port}/`,
    caFile: b.cert,        // 错误的 CA
    rejectUnauthorized: true,
    pingIntervalMs: 60000,
    reconnectDelayMs: 60000, // 避免测试期间反复重连刷日志
  });
  t.after(async () => {
    tunnel.close();
    await new Promise((r) => proxy.close(r));
  });

  await new Promise((r) => setTimeout(r, 500));
  assert.equal(tunnel.ready, false, '不受信证书不应握手成功');
});

test('TLS：端到端 TLS 透传，服务端不劫持解密', { skip: !hasOpenssl() && 'openssl 不可用' }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'proxy-mitm-'));
  const { key, cert } = makeCert(dir);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  // 目标是一个真实的 TLS 服务器
  const tlsTarget = tls.createServer(
    { key: fs.readFileSync(key), cert: fs.readFileSync(cert) },
    (sock) => sock.on('data', (d) => sock.write(Buffer.concat([Buffer.from('TARGET:'), d]))),
  );
  await new Promise((r) => tlsTarget.listen(0, '127.0.0.1', r));
  const targetPort = tlsTarget.address().port;
  t.after(() => tlsTarget.close());

  const proxyServer = createServer({
    port: 0,
    host: '127.0.0.1',
    tlsCert: cert,
    tlsKey: key,
    lookup: async () => [{ address: '203.0.113.10', family: 4 }],
    connectOverride: () => '127.0.0.1',
  });
  await new Promise((r) => proxyServer.listen(0, '127.0.0.1', r));
  t.after(() => new Promise((r) => proxyServer.close(r)));

  const { proxy, tunnel } = await startClient({
    listenHost: '127.0.0.1',
    listenPort: 0,
    serverUrl: `wss://127.0.0.1:${proxyServer.address().port}/`,
    caFile: cert,
    rejectUnauthorized: true,
    pingIntervalMs: 60000,
  });
  t.after(async () => {
    tunnel.close();
    await new Promise((r) => proxy.close(r));
  });
  await new Promise((r) => setTimeout(r, 300));

  // 经隧道 CONNECT 后，在隧道内再套一层 TLS —— 客户端与目标端到端加密
  const raw = net.connect(proxy.address().port, '127.0.0.1');
  t.after(() => raw.destroy());
  await new Promise((r) => raw.on('connect', r));
  raw.write(`CONNECT any.public.test:${targetPort} HTTP/1.1\r\n\r\n`);
  const banner = await new Promise((r) => raw.once('data', r));
  assert.match(banner.toString(), /^HTTP\/1\.1 200 Connection Established/);

  const inner = await new Promise((resolve, reject) => {
    const s = tls.connect(
      { socket: raw, ca: fs.readFileSync(cert), servername: 'localhost' },
      () => resolve(s),
    );
    s.on('error', reject);
  });
  t.after(() => inner.destroy());

  // 证书链由客户端自行校验通过 → 服务端只透传字节，没有中间人
  assert.equal(inner.authorized, true, '隧道内 TLS 应由客户端与目标端到端完成');
  assert.equal(inner.getPeerCertificate().subject.CN, 'localhost');

  inner.write('PING');
  const echoed = await new Promise((r) => inner.once('data', r));
  assert.equal(echoed.toString(), 'TARGET:PING');
});
