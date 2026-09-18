#pragma once
/**
 * SSRF 拦截 —— 与 Node 版 server/ssrf.js 行为完全一致。
 *
 * 设计要点（方案固定不可修改项）：
 *   1. 只校验「解析后的 IP」，不做域名黑名单。
 *   2. 域名 → 先解析，所有解析结果全部通过才允许建连。
 *   3. 字面 IP → 直接对该 IP 校验。
 */
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace hwp {

struct DnsRecord {
  std::string address;
  int family = 4;  // 4 / 6
};

/** 解析函数签名：域名 → 全部地址；失败抛异常 / 返回空 */
using LookupFn = std::function<std::vector<DnsRecord>(const std::string& host)>;

struct BlockResult {
  bool blocked = false;
  std::string cidr;
};

/** 判断单个字面 IP 是否命中 SSRF 拦截网段 */
BlockResult isBlockedIp(const std::string& ip);

/** 校验目标 host：字面 IP 直接校验；域名解析全部结果，任一命中即拒绝 */
struct GuardResult {
  bool ok = false;
  std::string reason;
  std::vector<std::string> addresses;
};
GuardResult guardTarget(const std::string& host, const LookupFn& lookup);

/** 判断字符串是否为 IP 字面量（返回 4 / 6 / 0） */
int isIpLiteral(const std::string& s);

/** IPv6 字符串 → 16 字节；失败返回 false */
bool ipv6ToBytes(const std::string& ip, uint8_t out[16]);

}  // namespace hwp
