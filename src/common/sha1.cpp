#include "sha1.hpp"

#include <cstring>

namespace hwp {
namespace {

inline uint32_t rol(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

}  // namespace

void Sha1::reset() {
  h_[0] = 0x67452301;
  h_[1] = 0xEFCDAB89;
  h_[2] = 0x98BADCFE;
  h_[3] = 0x10325476;
  h_[4] = 0xC3D2E1F0;
  totalLen_ = 0;
  bufLen_ = 0;
}

void Sha1::processBlock(const uint8_t* block) {
  uint32_t w[80];
  for (int i = 0; i < 16; i++) {
    w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
           (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
           (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
           static_cast<uint32_t>(block[i * 4 + 3]);
  }
  for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

  uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
  for (int i = 0; i < 80; i++) {
    uint32_t f, k;
    if (i < 20) {
      f = (b & c) | ((~b) & d);
      k = 0x5A827999;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDC;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6;
    }
    const uint32_t tmp = rol(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = rol(b, 30);
    b = a;
    a = tmp;
  }
  h_[0] += a;
  h_[1] += b;
  h_[2] += c;
  h_[3] += d;
  h_[4] += e;
}

void Sha1::update(const void* data, size_t len) {
  const uint8_t* p = static_cast<const uint8_t*>(data);
  totalLen_ += len;
  while (len > 0) {
    const size_t take = (len < (64 - bufLen_)) ? len : (64 - bufLen_);
    std::memcpy(buf_ + bufLen_, p, take);
    bufLen_ += take;
    p += take;
    len -= take;
    if (bufLen_ == 64) {
      processBlock(buf_);
      bufLen_ = 0;
    }
  }
}

void Sha1::final(uint8_t out[20]) {
  const uint64_t bitLen = totalLen_ * 8;
  const uint8_t pad = 0x80;
  update(&pad, 1);
  const uint8_t zero = 0;
  while (bufLen_ != 56) update(&zero, 1);
  uint8_t lenBuf[8];
  for (int i = 0; i < 8; i++) lenBuf[i] = static_cast<uint8_t>((bitLen >> (56 - i * 8)) & 0xff);
  update(lenBuf, 8);
  for (int i = 0; i < 5; i++) {
    out[i * 4] = static_cast<uint8_t>((h_[i] >> 24) & 0xff);
    out[i * 4 + 1] = static_cast<uint8_t>((h_[i] >> 16) & 0xff);
    out[i * 4 + 2] = static_cast<uint8_t>((h_[i] >> 8) & 0xff);
    out[i * 4 + 3] = static_cast<uint8_t>(h_[i] & 0xff);
  }
}

void Sha1::hash(const std::string& data, uint8_t out[20]) {
  Sha1 s;
  s.update(data.data(), data.size());
  s.final(out);
}

}  // namespace hwp
