// 单元自测：帧协议 / SSRF 规则 / WebSocket 握手 / SHA1 / Base64
#include <cassert>
#include <cstdio>
#include <string>

#include "../src/common/base64.hpp"
#include "../src/common/protocol.hpp"
#include "../src/common/sha1.hpp"
#include "../src/common/ssrf.hpp"
#include "../src/common/websocket.hpp"

using namespace hwp;

static int g_failed = 0;
static int g_passed = 0;

#define CHECK(cond, name)                                                      \
  do {                                                                         \
    if (cond) {                                                                \
      g_passed++;                                                              \
    } else {                                                                   \
      g_failed++;                                                              \
      std::fprintf(stderr, "FAIL: %s (%s:%d)\n", std::string(name).c_str(),    \
                   __FILE__, __LINE__);                                        \
    }                                                                          \
  } while (0)

static void testProtocol() {
  const Bytes payload = {'h', 'i'};
  const Bytes frame = encodeDataFrame(0x12345678u, payload);
  CHECK(frame.size() == 6, "frame size");
  CHECK(frame[0] == 0x12 && frame[1] == 0x34 && frame[2] == 0x56 && frame[3] == 0x78,
        "frame big-endian sessionId");
  const auto d = decodeDataFrame(frame.data(), frame.size());
  CHECK(d.has_value(), "decode ok");
  CHECK(d->sessionId == 0x12345678u, "decoded sessionId");
  CHECK(d->len == 2 && d->payload[0] == 'h', "decoded payload");
  CHECK(!decodeDataFrame(frame.data(), 3).has_value(), "short frame rejected");
  CHECK(!decodeDataFrame(nullptr, 0).has_value(), "null frame rejected");

  const auto msg = parseControlMessage(
      R"({"type":"connect","sessionId":305419896,"host":"example.com","port":443,"mode":"tcp-over-wss"})");
  CHECK(msg.has_value(), "parse connect");
  CHECK(msg->at("type").str == "connect", "type field");
  CHECK(msg->at("sessionId").num == 305419896, "sessionId number");
  CHECK(msg->at("host").str == "example.com", "host string");
  CHECK(msg->at("port").num == 443, "port number");
  CHECK(!parseControlMessage("not json").has_value(), "invalid json rejected");
  CHECK(!parseControlMessage(R"({"foo":1})").has_value(), "missing type rejected");
  CHECK(!parseControlMessage(R"({"sessionId":1})").has_value(), "missing type (num only) rejected");

  // 未知字段 / 嵌套对象也要能解析
  const auto msg2 = parseControlMessage(
      R"({"type":"close","sessionId":7,"reason":"target closed","extra":{"a":[1,2]}})");
  CHECK(msg2.has_value(), "parse close with nested field");
  CHECK(msg2->at("reason").str == "target closed", "reason field");

  CHECK(isValidSessionId(1) && isValidSessionId(0xffffffffu), "valid sessionIds");
  CHECK(isValidPort(1) && isValidPort(65535) && !isValidPort(0), "port validation");

  const std::string cm = controlMessage("close", {{"sessionId", "5"}});
  CHECK(cm.find("\"type\":\"close\"") != std::string::npos, "controlMessage type");
  CHECK(cm.find("\"sessionId\":\"5\"") != std::string::npos, "controlMessage field");
}

static void testSsrf() {
  const char* blocked[] = {
      "0.0.0.0", "0.1.2.3", "10.0.0.5", "100.64.0.1", "127.0.0.1", "169.254.169.254",
      "172.16.0.1", "172.31.255.255", "192.168.1.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
      "::", "::1", "64:ff9b::1", "2002::1", "fc00::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1",
      "::ffff:10.0.0.1",
  };
  for (const char* ip : blocked) {
    const auto r = isBlockedIp(ip);
    CHECK(r.blocked, std::string("blocked: ") + ip);
  }
  const char* allowed[] = {"8.8.8.8", "1.1.1.1", "172.15.0.1", "172.32.0.1", "100.63.0.1",
                           "100.128.0.1", "11.0.0.1", "2001:4860:4860::8888", "2606:4700::1",
                           "::ffff:8.8.8.8"};
  for (const char* ip : allowed) {
    const auto r = isBlockedIp(ip);
    CHECK(!r.blocked, std::string("allowed: ") + ip);
  }

  CHECK(isIpLiteral("1.2.3.4") == 4, "ipv4 literal");
  CHECK(isIpLiteral("::1") == 6, "ipv6 literal");
  CHECK(isIpLiteral("example.com") == 0, "not a literal");

  // guardTarget：字面私有 IP 直接拒绝
  auto g1 = guardTarget("10.0.0.5", nullptr);
  CHECK(!g1.ok && g1.reason.find("blocked range 10.0.0.0/8") != std::string::npos,
        "guard rejects private literal");
  // 字面公网 IP 放行
  auto g2 = guardTarget("8.8.8.8", nullptr);
  CHECK(g2.ok && g2.addresses.size() == 1, "guard allows public literal");
  // 域名解析到私有地址 → 拒绝
  auto g3 = guardTarget("evil.example", [](const std::string&) {
    return std::vector<DnsRecord>{{"192.168.1.1", 4}};
  });
  CHECK(!g3.ok && g3.reason.find("resolves to blocked range") != std::string::npos,
        "guard rejects domain resolving to private");
  // 域名解析全部公网 → 放行
  auto g4 = guardTarget("good.example", [](const std::string&) {
    return std::vector<DnsRecord>{{"1.1.1.1", 4}, {"2606:4700::1", 6}};
  });
  CHECK(g4.ok && g4.addresses.size() == 2, "guard allows public domain");
  // 解析失败 → 拒绝
  auto g5 = guardTarget("bad.example", [](const std::string&) -> std::vector<DnsRecord> {
    throw std::runtime_error("ENOTFOUND");
  });
  CHECK(!g5.ok && g5.reason.find("DNS resolve failed") != std::string::npos,
        "guard handles dns failure");
  // 空 host
  CHECK(!guardTarget("", nullptr).ok, "guard rejects empty host");
}

static void testHashAndBase64() {
  uint8_t digest[20];
  Sha1::hash("abc", digest);
  const std::string hex = [] (const uint8_t* d) {
    char buf[41];
    for (int i = 0; i < 20; i++) std::snprintf(buf + i * 2, 3, "%02x", d[i]);
    return std::string(buf, 40);
  }(digest);
  CHECK(hex == "a9993e364706816aba3e25717850c26c9cd0d89d", "sha1(abc)");

  // RFC 6455 示例：Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
  CHECK(WebSocket::acceptKey("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        "websocket accept key (RFC6455 sample)");

  CHECK(base64Encode("f") == "Zg==", "base64 f");
  CHECK(base64Encode("fo") == "Zm8=", "base64 fo");
  CHECK(base64Encode("foo") == "Zm9v", "base64 foo");
  CHECK(base64Encode("foob") == "Zm9vYg==", "base64 foob");
  CHECK(base64Encode("fooba") == "Zm9vYmE=", "base64 fooba");
  CHECK(base64Encode("foobar") == "Zm9vYmFy", "base64 foobar");
  std::vector<uint8_t> dec;
  CHECK(base64Decode("Zm9vYmFy", dec) && std::string(dec.begin(), dec.end()) == "foobar",
        "base64 decode");
}

int main() {
  testProtocol();
  testSsrf();
  testHashAndBase64();
  std::printf("passed=%d failed=%d\n", g_passed, g_failed);
  return g_failed == 0 ? 0 : 1;
}
