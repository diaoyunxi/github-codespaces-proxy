import test from 'node:test';
import assert from 'node:assert/strict';
import { isBlockedIp, guardTarget } from '../server/ssrf.js';

test('IPv4：10.0.0.0/8 被拦截', () => {
  for (const ip of ['10.0.0.0', '10.0.0.1', '10.255.255.255', '10.1.2.3']) {
    assert.equal(isBlockedIp(ip).blocked, true, ip);
  }
  assert.equal(isBlockedIp('11.0.0.1').blocked, false);
});

test('IPv4：172.16.0.0/12 被拦截，172.32 不拦', () => {
  for (const ip of ['172.16.0.0', '172.16.0.1', '172.31.255.255']) {
    assert.equal(isBlockedIp(ip).blocked, true, ip);
  }
  for (const ip of ['172.15.255.255', '172.32.0.0', '172.32.0.1']) {
    assert.equal(isBlockedIp(ip).blocked, false, ip);
  }
});

test('IPv4：192.168.0.0/16 被拦截', () => {
  assert.equal(isBlockedIp('192.168.0.1').blocked, true);
  assert.equal(isBlockedIp('192.168.255.255').blocked, true);
  assert.equal(isBlockedIp('192.169.0.1').blocked, false);
});

test('IPv4：127.0.0.0/8 被拦截', () => {
  assert.equal(isBlockedIp('127.0.0.1').blocked, true);
  assert.equal(isBlockedIp('127.1.2.3').blocked, true);
  assert.equal(isBlockedIp('126.255.255.255').blocked, false);
});

test('公网 IPv4 不拦截', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '203.0.113.10', '93.184.216.34']) {
    assert.equal(isBlockedIp(ip).blocked, false, ip);
  }
});

test('IPv6：::1/128 fc00::/7 fe80::/10 被拦截', () => {
  assert.equal(isBlockedIp('::1').blocked, true);
  assert.equal(isBlockedIp('fc00::1').blocked, true);
  assert.equal(isBlockedIp('fd00::1').blocked, true);
  assert.equal(isBlockedIp('fdff:ffff::1').blocked, true);
  assert.equal(isBlockedIp('fe80::1').blocked, true);
  assert.equal(isBlockedIp('febf::1').blocked, true);
});

test('IPv6：公网地址不拦截', () => {
  for (const ip of ['2606:4700::1111', '2001:4860:4860::8888', 'fec0::1']) {
    assert.equal(isBlockedIp(ip).blocked, false, ip);
  }
});

test('IPv6：zone id 可解析', () => {
  assert.equal(isBlockedIp('fe80::1%eth0').blocked, true);
});

test('IPv4-mapped IPv6 按 IPv4 语义判定', () => {
  assert.equal(isBlockedIp('::ffff:127.0.0.1').blocked, true);
  assert.equal(isBlockedIp('::ffff:10.0.0.1').blocked, true);
  assert.equal(isBlockedIp('::ffff:192.168.1.1').blocked, true);
  assert.equal(isBlockedIp('::ffff:8.8.8.8').blocked, false);
});

test('非 IP 字面量：isBlockedIp 视为需先解析', () => {
  assert.equal(isBlockedIp('example.com').blocked, true);
  assert.equal(isBlockedIp('').blocked, true);
});

test('guardTarget：字面 IP 直接校验', async () => {
  const shouldNotBeCalled = async () => { throw new Error('lookup 不应被调用'); };
  const bad = await guardTarget('10.0.0.1', shouldNotBeCalled);
  assert.equal(bad.ok, false);
  assert.match(bad.reason, /blocked range/);

  const good = await guardTarget('8.8.8.8', shouldNotBeCalled);
  assert.equal(good.ok, true);
  assert.deepEqual(good.addresses, ['8.8.8.8']);
});

test('guardTarget：域名解析出的全部地址都必须通过', async () => {
  const ok = await guardTarget('example.com', async () => [
    { address: '93.184.216.34' },
    { address: '2606:2800:220:1:248:1893:25c8:1946' },
  ]);
  assert.equal(ok.ok, true);

  const mixed = await guardTarget('evil.com', async () => [
    { address: '93.184.216.34' },
    { address: '127.0.0.1' },
  ]);
  assert.equal(mixed.ok, false);
  assert.match(mixed.reason, /blocked range/);
});

test('guardTarget：DNS 失败返回错误', async () => {
  const err = new Error('dns fail');
  err.code = 'ENOTFOUND';
  const r = await guardTarget('nowhere.invalid', async () => { throw err; });
  assert.equal(r.ok, false);
  assert.match(r.reason, /DNS resolve failed/);
});

test('guardTarget：空 host 拒绝', async () => {
  assert.equal((await guardTarget('', async () => [])).ok, false);
  assert.equal((await guardTarget(null, async () => [])).ok, false);
});

test('IPv4：0.0.0.0/8 被拦截（本机语义地址）', () => {
  for (const ip of ['0.0.0.0', '0.0.0.1', '0.255.255.255']) {
    assert.equal(isBlockedIp(ip).blocked, true, ip);
    assert.equal(isBlockedIp(ip).cidr, '0.0.0.0/8');
  }
});

test('IPv4：169.254.0.0/16 被拦截（链路本地 / 云元数据）', () => {
  for (const ip of ['169.254.0.1', '169.254.169.254', '169.254.255.255']) {
    assert.equal(isBlockedIp(ip).blocked, true, ip);
  }
  assert.equal(isBlockedIp('169.253.0.1').blocked, false);
  assert.equal(isBlockedIp('169.255.0.1').blocked, false);
});

test('IPv4：100.64.0.0/10 被拦截（CGNAT），边界外不拦', () => {
  for (const ip of ['100.64.0.0', '100.64.0.1', '100.127.255.255']) {
    assert.equal(isBlockedIp(ip).blocked, true, ip);
  }
  assert.equal(isBlockedIp('100.63.255.255').blocked, false);
  assert.equal(isBlockedIp('100.128.0.0').blocked, false);
});

test('IPv4：224.0.0.0/4 与 240.0.0.0/4 被拦截', () => {
  assert.equal(isBlockedIp('224.0.0.0').blocked, true);
  assert.equal(isBlockedIp('239.255.255.255').blocked, true);
  assert.equal(isBlockedIp('223.255.255.255').blocked, false);
  assert.equal(isBlockedIp('240.0.0.1').blocked, true);
  assert.equal(isBlockedIp('255.255.255.255').blocked, true);
});

test('IPv6：::/128、64:ff9b::/96、2002::/16 被拦截', () => {
  assert.equal(isBlockedIp('::').blocked, true);
  assert.equal(isBlockedIp('::').cidr, '::/128');
  assert.equal(isBlockedIp('64:ff9b::1').blocked, true);
  assert.equal(isBlockedIp('64:ff9b::192.0.2.1').blocked, true);
  assert.equal(isBlockedIp('2002::1').blocked, true);
  assert.equal(isBlockedIp('2002:c000:0201::1').blocked, true);
});

test('IPv4-mapped IPv6 按 IPv4 语义拦截新增网段', () => {
  assert.equal(isBlockedIp('::ffff:169.254.169.254').blocked, true);
  assert.equal(isBlockedIp('::ffff:100.64.0.1').blocked, true);
  assert.equal(isBlockedIp('::ffff:0.0.0.0').blocked, true);
});
