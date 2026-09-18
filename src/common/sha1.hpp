#pragma once
// 内嵌 SHA-1（RFC 3174）—— 仅用于 WebSocket 握手校验
#include <cstdint>
#include <cstddef>
#include <string>

namespace hwp {

class Sha1 {
 public:
  Sha1() { reset(); }
  void reset();
  void update(const void* data, size_t len);
  /** 输出 20 字节摘要 */
  void final(uint8_t out[20]);
  static void hash(const std::string& data, uint8_t out[20]);

 private:
  void processBlock(const uint8_t* block);
  uint32_t h_[5]{};
  uint64_t totalLen_ = 0;
  uint8_t buf_[64]{};
  size_t bufLen_ = 0;
};

}  // namespace hwp
