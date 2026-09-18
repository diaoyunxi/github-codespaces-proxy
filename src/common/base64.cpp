#include "base64.hpp"

namespace hwp {
namespace {
const char kTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int decodeChar(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}
}  // namespace

std::string base64Encode(const uint8_t* data, size_t len) {
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  size_t i = 0;
  while (i + 3 <= len) {
    const uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                       (static_cast<uint32_t>(data[i + 1]) << 8) | data[i + 2];
    out += kTable[(n >> 18) & 0x3f];
    out += kTable[(n >> 12) & 0x3f];
    out += kTable[(n >> 6) & 0x3f];
    out += kTable[n & 0x3f];
    i += 3;
  }
  const size_t rem = len - i;
  if (rem == 1) {
    const uint32_t n = static_cast<uint32_t>(data[i]) << 16;
    out += kTable[(n >> 18) & 0x3f];
    out += kTable[(n >> 12) & 0x3f];
    out += "==";
  } else if (rem == 2) {
    const uint32_t n = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8);
    out += kTable[(n >> 18) & 0x3f];
    out += kTable[(n >> 12) & 0x3f];
    out += kTable[(n >> 6) & 0x3f];
    out += '=';
  }
  return out;
}

bool base64Decode(const std::string& in, std::vector<uint8_t>& out) {
  int buf = 0, bits = 0;
  for (char c : in) {
    if (c == '=' ) break;
    if (c == '\r' || c == '\n' || c == ' ') continue;
    const int v = decodeChar(c);
    if (v < 0) return false;
    buf = (buf << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<uint8_t>((buf >> bits) & 0xff));
    }
  }
  return true;
}

}  // namespace hwp
