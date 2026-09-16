/**
 * SSRF 拦截 —— 只拦最核心的私有 / 回环地址。
 *
 * 设计要点（方案固定不可修改项）：
 *   1. 只校验「解析后的 IP」，不做域名黑名单。
 *   2. 域名 → 先解析，所有解析结果全部通过才允许建连。
 *   3. 字面 IP → 直接对该 IP 校验。
 */

import { isIP } from 'node:net';

/**
 * IPv4 非公网 / 保留网段。
 *
 * 覆盖范围说明：本表按「不该被外部访问的地址」而非仅「私有地址」来列。
 * 除 RFC1918 与回环外，还包含：
 *   - 0.0.0.0/8     ：本机语义地址，部分系统上等价 127.0.0.1
 *   - 169.254.0.0/16：链路本地，含云厂商元数据 169.254.169.254
 *   - 100.64.0.0/10 ：CGNAT / 运营商级内网
 *   - 224.0.0.0/4   ：组播
 *   - 240.0.0.0/4   ：保留（含 255.255.255.255）
 */
const IPV4_BLOCKS = [
  { cidr: '0.0.0.0/8', base: [0, 0, 0, 0], bits: 8 },
  { cidr: '10.0.0.0/8', base: [10, 0, 0, 0], bits: 8 },
  { cidr: '100.64.0.0/10', base: [100, 64, 0, 0], bits: 10 },
  { cidr: '127.0.0.0/8', base: [127, 0, 0, 0], bits: 8 },
  { cidr: '169.254.0.0/16', base: [169, 254, 0, 0], bits: 16 },
  { cidr: '172.16.0.0/12', base: [172, 16, 0, 0], bits: 12 },
  { cidr: '192.168.0.0/16', base: [192, 168, 0, 0], bits: 16 },
  { cidr: '224.0.0.0/4', base: [224, 0, 0, 0], bits: 4 },
  { cidr: '240.0.0.0/4', base: [240, 0, 0, 0], bits: 4 },
];

/**
 * IPv6 非公网 / 保留网段，用规范化后前 N 字节 + 前缀长度表示。
 * 除回环 / ULA / 链路本地外，额外覆盖：
 *   - ::/128         ：未指定地址
 *   - 64:ff9b::/96   ：NAT64
 *   - 2002::/16      ：6to4
 */
const IPV6_BLOCKS = [
  { cidr: '::/128', bytes: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], bits: 128 },
  { cidr: '::1/128', bytes: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], bits: 128 },
  { cidr: '64:ff9b::/96', bytes: [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], bits: 96 },
  { cidr: '2002::/16', bytes: [0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], bits: 16 },
  { cidr: 'fc00::/7', bytes: [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], bits: 7 },
  { cidr: 'fe80::/10', bytes: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], bits: 10 },
];

/** 把 IPv4 字符串转成 4 字节数组 */
function ipv4ToBytes(ip) {
  return ip.split('.').map((x) => Number(x) & 0xff);
}

/**
 * 把 IPv6 字符串转成 16 字节数组。
 * 支持 `::` 压缩、IPv4 混合写法（::ffff:1.2.3.4）。
 */
export function ipv6ToBytes(ip) {
  let str = ip;
  // 去掉 zone id，如 fe80::1%eth0
  const zone = str.indexOf('%');
  if (zone !== -1) str = str.slice(0, zone);

  let v4Mapped = null;
  const lastColon = str.lastIndexOf(':');
  if (lastColon !== -1 && str.slice(lastColon + 1).includes('.')) {
    const v4part = str.slice(lastColon + 1);
    const b = ipv4ToBytes(v4part);
    v4Mapped = b;
    str = str.slice(0, lastColon + 1) + [((b[0] << 8) | b[1]).toString(16), ((b[2] << 8) | b[3]).toString(16)].join(':');
  }

  const parts = str.split('::');
  let head = parts[0] ? parts[0].split(':') : [];
  let tail = parts.length > 1 ? (parts[1] ? parts[1].split(':') : []) : [];
  if (parts.length > 2) return null;

  const missing = 8 - head.length - tail.length;
  if (missing < 0) return null;

  const groups =
    parts.length > 1
      ? [...head, ...Array(missing).fill('0'), ...tail]
      : head;

  if (groups.length !== 8) return null;

  const bytes = [];
  for (const g of groups) {
    if (g === '') return null;
    const n = parseInt(g, 16);
    if (Number.isNaN(n) || n < 0 || n > 0xffff) return null;
    bytes.push((n >> 8) & 0xff, n & 0xff);
  }
  return Uint8Array.from(bytes);
}

/** 按前缀长度比较两个字节数组是否同网段 */
function inBlock(actual, base, bits) {
  const fullBytes = Math.floor(bits / 8);
  const restBits = bits % 8;
  for (let i = 0; i < fullBytes; i++) {
    if (actual[i] !== base[i]) return false;
  }
  if (restBits > 0) {
    const mask = (0xff << (8 - restBits)) & 0xff;
    if ((actual[fullBytes] & mask) !== (base[fullBytes] & mask)) return false;
  }
  return true;
}

/**
 * 判断单个字面 IP 是否命中 SSRF 拦截网段。
 * @param {string} ip
 * @returns {{blocked: boolean, cidr?: string}}
 */
export function isBlockedIp(ip) {
  const family = isIP(ip);
  if (family === 4) {
    const bytes = ipv4ToBytes(ip);
    for (const b of IPV4_BLOCKS) {
      if (inBlock(bytes, b.base, b.bits)) return { blocked: true, cidr: b.cidr };
    }
    return { blocked: false };
  }
  if (family === 6) {
    const bytes = ipv6ToBytes(ip);
    if (!bytes) return { blocked: true, cidr: 'invalid' };
    // IPv4-mapped IPv6（::ffff:x.x.x.x）按其 IPv4 语义校验
    const isV4Mapped =
      bytes.slice(0, 10).every((x) => x === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
    if (isV4Mapped) {
      const v4 = [bytes[12], bytes[13], bytes[14], bytes[15]].join('.');
      return isBlockedIp(v4);
    }
    for (const b of IPV6_BLOCKS) {
      if (inBlock(bytes, b.bytes, b.bits)) return { blocked: true, cidr: b.cidr };
    }
    return { blocked: false };
  }
  // 非 IP 字面量，交由调用方先解析
  return { blocked: true, cidr: 'not-an-ip' };
}

/**
 * 校验一个目标 host（域名或字面 IP）。
 * 字面 IP 直接校验；域名解析出全部地址，任一命中拦截网段则整体拒绝。
 *
 * @param {string} host
 * @param {(host: string) => Promise<Array<{address: string, family: number}>>} lookup
 * @returns {Promise<{ok: true, addresses: string[]} | {ok: false, reason: string}>}
 */
export async function guardTarget(host, lookup) {
  if (typeof host !== 'string' || host.length === 0) {
    return { ok: false, reason: 'empty host' };
  }
  const literal = isIP(host);
  if (literal !== 0) {
    const r = isBlockedIp(host);
    if (r.blocked) {
      return { ok: false, reason: `target IP ${host} is in blocked range ${r.cidr}` };
    }
    return { ok: true, addresses: [host] };
  }

  let records;
  try {
    records = await lookup(host);
  } catch (err) {
    return { ok: false, reason: `DNS resolve failed for ${host}: ${err.code || err.message}` };
  }
  if (!records || records.length === 0) {
    return { ok: false, reason: `DNS resolve returned no address for ${host}` };
  }

  const addresses = [];
  for (const rec of records) {
    const r = isBlockedIp(rec.address);
    if (r.blocked) {
      return { ok: false, reason: `target ${host} resolves to blocked range ${r.cidr}` };
    }
    addresses.push(rec.address);
  }
  return { ok: true, addresses };
}
