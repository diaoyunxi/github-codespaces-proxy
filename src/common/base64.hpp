#pragma once
#include <string>
#include <cstdint>
#include <vector>

namespace hwp {

std::string base64Encode(const uint8_t* data, size_t len);
inline std::string base64Encode(const std::string& s) {
  return base64Encode(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
/** 解码；失败返回 false */
bool base64Decode(const std::string& in, std::vector<uint8_t>& out);

}  // namespace hwp
