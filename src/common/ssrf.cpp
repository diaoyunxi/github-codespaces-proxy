#include "ssrf.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace hwp {
namespace {

struct V4Block {
  const char* cidr;
  uint8_t base[4];
  int bits;
};

struct V6Block {
  const char* cidr;
  uint8_t bytes[16];
  int bits;
};

// 与 ssrf.js IPV4_BLOCKS 一致
const V4Block kIpv4Blocks[] = {
    {"0.0.0.0/8", {0, 0, 0, 0}, 8},
    {"10.0.0.0/8", {10, 0, 0, 0}, 8},
    {"100.64.0.0/10", {100, 64, 0, 0}, 10},
    {"127.0.0.0/8", {127, 0, 0, 0}, 8},
    {"169.254.0.0/16", {169, 254, 0, 0}, 16},
    {"172.16.0.0/12", {172, 16, 0, 0}, 12},
    {"192.168.0.0/16", {192, 168, 0, 0}, 16},
    {"224.0.0.0/4", {224, 0, 0, 0}, 4},
    {"240.0.0.0/4", {240, 0, 0, 0}, 4},
};

// 与 ssrf.js IPV6_BLOCKS 一致
const V6Block kIpv6Blocks[] = {
    {"::/128", {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 128},
    {"::1/128", {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}, 128},
    {"64:ff9b::/96", {0,0x64,0xff,0x9b,0,0,0,0,0,0,0,0,0,0,0,0}, 96},
    {"2002::/16", {0x20,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 16},
    {"fc00::/7", {0xfc,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 7},
    {"fe80::/10", {0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 10},
};

bool inBlock(const uint8_t* actual, const uint8_t* base, int bits) {
  const int fullBytes = bits / 8;
  const int restBits = bits % 8;
  for (int i = 0; i < fullBytes; i++) {
    if (actual[i] != base[i]) return false;
  }
  if (restBits > 0) {
    const uint8_t mask = static_cast<uint8_t>((0xff << (8 - restBits)) & 0xff);
    if ((actual[fullBytes] & mask) != (base[fullBytes] & mask)) return false;
  }
  return true;
}

bool parseIpv4(const std::string& ip, uint8_t out[4]) {
  int part = 0;
  size_t i = 0;
  while (part < 4) {
    if (i >= ip.size()) return false;
    if (!std::isdigit(static_cast<unsigned char>(ip[i]))) return false;
    int value = 0;
    int digits = 0;
    while (i < ip.size() && std::isdigit(static_cast<unsigned char>(ip[i]))) {
      value = value * 10 + (ip[i] - '0');
      digits++;
      if (digits > 3) return false;
      i++;
    }
    if (value > 255) return false;
    out[part++] = static_cast<uint8_t>(value);
    if (part == 4) break;
    if (i >= ip.size() || ip[i] != '.') return false;
    i++;
  }
  return i == ip.size();
}

}  // namespace

bool ipv6ToBytes(const std::string& ip, uint8_t out[16]) {
  std::string str = ip;
  // 去掉 zone id，如 fe80::1%eth0
  const auto zone = str.find('%');
  if (zone != std::string::npos) str = str.substr(0, zone);
  if (str.empty() || str.size() > 45) return false;

  // IPv4 混合写法：只有最后一段含 '.'
  const auto lastColon = str.rfind(':');
  if (lastColon != std::string::npos && str.find('.', lastColon) != std::string::npos) {
    uint8_t v4[4];
    if (!parseIpv4(str.substr(lastColon + 1), v4)) return false;
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%x:%x", (v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
    str = str.substr(0, lastColon + 1) + buf;
  }

  // 拆分 `::`
  const auto pos = str.find("::");
  if (pos != std::string::npos && str.find("::", pos + 1) != std::string::npos) return false;

  auto splitGroups = [](const std::string& s) {
    std::vector<std::string> groups;
    if (s.empty()) return groups;
    size_t start = 0;
    while (true) {
      const auto c = s.find(':', start);
      if (c == std::string::npos) {
        groups.push_back(s.substr(start));
        break;
      }
      groups.push_back(s.substr(start, c - start));
      start = c + 1;
    }
    return groups;
  };

  std::vector<std::string> head, tail;
  if (pos != std::string::npos) {
    head = splitGroups(str.substr(0, pos));
    tail = splitGroups(str.substr(pos + 2));
  } else {
    head = splitGroups(str);
  }

  const long total = static_cast<long>(head.size()) + static_cast<long>(tail.size());
  if (total > 8) return false;

  std::vector<std::string> groups = head;
  if (pos != std::string::npos) {
    for (long i = total; i < 8; i++) groups.push_back("0");
    groups.insert(groups.end(), tail.begin(), tail.end());
  }
  if (groups.size() != 8) return false;

  for (size_t i = 0; i < 8; i++) {
    const std::string& g = groups[i];
    if (g.empty() || g.size() > 4) return false;
    unsigned n = 0;
    for (char c : g) {
      n <<= 4;
      if (c >= '0' && c <= '9') n |= static_cast<unsigned>(c - '0');
      else if (c >= 'a' && c <= 'f') n |= static_cast<unsigned>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') n |= static_cast<unsigned>(c - 'A' + 10);
      else return false;
    }
    out[i * 2] = static_cast<uint8_t>((n >> 8) & 0xff);
    out[i * 2 + 1] = static_cast<uint8_t>(n & 0xff);
  }
  return true;
}

int isIpLiteral(const std::string& s) {
  uint8_t v4[4];
  if (parseIpv4(s, v4)) return 4;
  uint8_t v6[16];
  if (s.find(':') != std::string::npos && ipv6ToBytes(s, v6)) return 6;
  return 0;
}

BlockResult isBlockedIp(const std::string& ip) {
  uint8_t v4[4];
  if (parseIpv4(ip, v4)) {
    for (const auto& b : kIpv4Blocks) {
      if (inBlock(v4, b.base, b.bits)) return {true, b.cidr};
    }
    return {false, {}};
  }
  uint8_t v6[16];
  if (ip.find(':') != std::string::npos && ipv6ToBytes(ip, v6)) {
    // IPv4-mapped IPv6（::ffff:x.x.x.x）按其 IPv4 语义校验
    bool isV4Mapped = true;
    for (int i = 0; i < 10; i++)
      if (v6[i] != 0) isV4Mapped = false;
    if (isV4Mapped && v6[10] == 0xff && v6[11] == 0xff) {
      char v4str[32];
      std::snprintf(v4str, sizeof(v4str), "%u.%u.%u.%u", v6[12], v6[13], v6[14], v6[15]);
      return isBlockedIp(v4str);
    }
    for (const auto& b : kIpv6Blocks) {
      if (inBlock(v6, b.bytes, b.bits)) return {true, b.cidr};
    }
    return {false, {}};
  }
  // 非 IP 字面量，交由调用方先解析
  return {true, "not-an-ip"};
}

GuardResult guardTarget(const std::string& host, const LookupFn& lookup) {
  if (host.empty()) return {false, "empty host", {}};

  if (isIpLiteral(host) != 0) {
    const auto r = isBlockedIp(host);
    if (r.blocked) {
      return {false, "target IP " + host + " is in blocked range " + r.cidr, {}};
    }
    return {true, {}, {host}};
  }

  std::vector<DnsRecord> records;
  try {
    records = lookup ? lookup(host) : std::vector<DnsRecord>{};
  } catch (const std::exception& e) {
    return {false, "DNS resolve failed for " + host + ": " + e.what(), {}};
  }
  if (records.empty()) {
    return {false, "DNS resolve returned no address for " + host, {}};
  }

  std::vector<std::string> addresses;
  for (const auto& rec : records) {
    const auto r = isBlockedIp(rec.address);
    if (r.blocked) {
      return {false, "target " + host + " resolves to blocked range " + r.cidr, {}};
    }
    addresses.push_back(rec.address);
  }
  return {true, {}, addresses};
}

}  // namespace hwp
