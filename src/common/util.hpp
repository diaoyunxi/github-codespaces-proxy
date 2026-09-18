#pragma once
// 公共小工具：字符串、时间、字节序、随机数、日志
#include <cstdint>
#include <string>
#include <vector>

namespace hwp {

using Bytes = std::vector<uint8_t>;

std::string toLower(std::string s);
std::string trim(const std::string& s);
bool iequals(const std::string& a, const std::string& b);
int64_t nowMs();

/** 写 4 字节大端 */
inline void putU32BE(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>((v >> 24) & 0xff);
  p[1] = static_cast<uint8_t>((v >> 16) & 0xff);
  p[2] = static_cast<uint8_t>((v >> 8) & 0xff);
  p[3] = static_cast<uint8_t>(v & 0xff);
}

/** 读 4 字节大端 */
inline uint32_t getU32BE(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

uint32_t randomSessionId();
void logLine(const std::string& tag, const std::string& msg);

}  // namespace hwp
