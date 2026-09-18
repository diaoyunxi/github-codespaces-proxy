#include "websocket.hpp"

#include <algorithm>
#include <cstring>
#include <random>

#include "base64.hpp"
#include "sha1.hpp"
#include "stream.hpp"

namespace hwp {
namespace {

constexpr uint8_t kOpContinuation = 0x0;
constexpr uint8_t kOpText = 0x1;
constexpr uint8_t kOpBinary = 0x2;
constexpr uint8_t kOpClose = 0x8;
constexpr uint8_t kOpPing = 0x9;
constexpr uint8_t kOpPong = 0xA;

std::string randomKey() {
  uint8_t rnd[16];
  std::random_device rd;
  for (size_t i = 0; i < sizeof(rnd); i++) rnd[i] = static_cast<uint8_t>(rd() & 0xff);
  return base64Encode(rnd, sizeof(rnd));
}

/** 依据流实现一个通用 WebSocket */
class WsImpl : public WebSocket {
 public:
  WsImpl(std::shared_ptr<Stream> stream, std::shared_ptr<TcpSocket> sock, bool serverSide)
      : stream_(std::move(stream)), sock_(std::move(sock)), serverSide_(serverSide) {
    setServerSide(serverSide);
  }

  /** 客户端：发送 HTTP Upgrade 请求并校验 101 响应 */
  bool clientHandshake(const std::string& host, const std::string& path,
                       const std::string& extraHeaders) {
    const std::string key = randomKey();
    std::string req = "GET " + (path.empty() ? "/" : path) + " HTTP/1.1\r\n";
    req += "Host: " + host + "\r\n";
    req += "Upgrade: websocket\r\n";
    req += "Connection: Upgrade\r\n";
    req += "Sec-WebSocket-Key: " + key + "\r\n";
    req += "Sec-WebSocket-Version: 13\r\n";
    if (!extraHeaders.empty()) req += extraHeaders;
    req += "\r\n";
    if (!stream_->writeAll(reinterpret_cast<const uint8_t*>(req.data()), req.size())) return false;

    std::string resp;
    if (!stream_->readUntil("\r\n\r\n", resp, 32 * 1024, 15000)) return false;
    const auto firstLineEnd = resp.find("\r\n");
    const std::string statusLine = resp.substr(0, firstLineEnd);
    if (statusLine.find(" 101") == std::string::npos) return false;
    // 校验 Accept（大小写不敏感）
    const std::string expect = acceptKey(key);
    std::string lower = toLower(resp);
    if (lower.find("sec-websocket-accept:") == std::string::npos) return false;
    if (lower.find(toLower(expect)) == std::string::npos) return false;
    state_.store(WsState::Open);
    return true;
  }

  void runReadLoop() override {
    Bytes header(2);
    while (state_.load() != WsState::Closed) {
      uint8_t h[2];
      if (!readFull(h, 2)) break;
      const bool fin = (h[0] & 0x80) != 0;
      const uint8_t opcode = h[0] & 0x0F;
      const bool masked = (h[1] & 0x80) != 0;
      uint64_t payloadLen = h[1] & 0x7F;
      if (payloadLen == 126) {
        uint8_t ext[2];
        if (!readFull(ext, 2)) break;
        payloadLen = (static_cast<uint64_t>(ext[0]) << 8) | ext[1];
      } else if (payloadLen == 127) {
        uint8_t ext[8];
        if (!readFull(ext, 8)) break;
        payloadLen = 0;
        for (int i = 0; i < 8; i++) payloadLen = (payloadLen << 8) | ext[i];
      }
      if (payloadLen > 64ull * 1024 * 1024) {
        failConnection("payload too large", true);
        break;
      }
      uint8_t maskKey[4] = {0, 0, 0, 0};
      if (masked && !readFull(maskKey, 4)) break;
      Bytes payload(static_cast<size_t>(payloadLen));
      if (payloadLen && !readFull(payload.data(), payload.size())) break;
      if (masked) {
        for (size_t i = 0; i < payload.size(); i++) payload[i] ^= maskKey[i % 4];
      }
      // 控制帧不可分片
      if (opcode >= 0x8) {
        handleControl(opcode, payload);
        if (opcode == kOpClose) break;
        continue;
      }
      dispatchFrame(opcode, payload, fin);
    }
    if (state_.load() != WsState::Closed) failConnection("connection closed", false);
  }

  bool sendText(const std::string& text) override {
    return sendFrame(kOpText, reinterpret_cast<const uint8_t*>(text.data()), text.size(), true);
  }

  bool sendBinary(const uint8_t* data, size_t len) override {
    if (state_.load() != WsState::Open) return false;
    if (len <= kWsSendChunk) return sendFrame(kOpBinary, data, len, true);
    size_t off = 0;
    bool first = true;
    while (off < len) {
      const size_t take = std::min(kWsSendChunk, len - off);
      const bool last = (off + take) >= len;
      const uint8_t op = first ? kOpBinary : kOpContinuation;
      if (!sendFrame(op, data + off, take, last)) return false;
      first = false;
      off += take;
    }
    return true;
  }

  bool sendPing() override { return sendFrame(kOpPing, nullptr, 0, true); }

  void close(uint16_t code, const std::string& reason) override {
    WsState expected = WsState::Open;
    if (!state_.compare_exchange_strong(expected, WsState::Closing)) {
      if (state_.load() == WsState::Closed) return;
    }
    uint8_t payload[2 + 125];
    payload[0] = static_cast<uint8_t>((code >> 8) & 0xff);
    payload[1] = static_cast<uint8_t>(code & 0xff);
    const size_t rlen = std::min<size_t>(reason.size(), 123);
    std::memcpy(payload + 2, reason.data(), rlen);
    sendFrame(kOpClose, payload, 2 + rlen, true);
    statusCode_ = code;
    closeReason_ = reason;
  }

  void terminate() override {
    state_.store(WsState::Closed);
    if (stream_) stream_->close();
    emitClose(closeReason_.empty() ? "terminated" : closeReason_);
  }

  size_t bufferedBytesImpl() const { return 0; }

 protected:
  bool writeRaw(const uint8_t* data, size_t len) override {
    std::lock_guard<std::mutex> lk(writeMutex_);
    if (!stream_) return false;
    const bool ok = stream_->writeAll(data, len);
    return ok;
  }
  void shutdownStream() override {
    if (stream_) stream_->shutdownWrite();
  }

 private:
  bool readFull(uint8_t* buf, size_t n) {
    if (!stream_) return false;
    size_t off = 0;
    while (off < n) {
      const ssize_t r = stream_->read(buf + off, n - off, -1);
      if (r <= 0) return false;
      off += static_cast<size_t>(r);
    }
    return true;
  }

  void handleControl(uint8_t opcode, const Bytes& payload) {
    if (opcode == kOpPing) {
      sendFrame(kOpPong, payload.data(), payload.size(), true);
      return;
    }
    if (opcode == kOpPong) return;
    if (opcode == kOpClose) {
      WsState s = state_.load();
      if (s != WsState::Closed) {
        if (s == WsState::Open) {
          // 回一个 close 帧
          state_.store(WsState::Closing);
          sendFrame(kOpClose, payload.data(), payload.size(), true);
        }
        if (payload.size() >= 2) statusCode_ = static_cast<uint16_t>((payload[0] << 8) | payload[1]);
        if (payload.size() > 2)
          closeReason_ = std::string(reinterpret_cast<const char*>(payload.data() + 2),
                                     payload.size() - 2);
      }
    }
  }

  void failConnection(const std::string& reason, bool notifyError) {
    if (state_.exchange(WsState::Closed) == WsState::Closed) return;
    if (stream_) stream_->close();
    if (notifyError && errorHandler_) errorHandler_(reason);
    emitClose(reason);
  }

  std::shared_ptr<Stream> stream_;
  std::shared_ptr<TcpSocket> sock_;
  bool serverSide_ = false;
  uint16_t statusCode_ = 1006;
  std::string closeReason_;
};

}  // namespace

size_t WebSocket::bufferedBytes() const { return 0; }

std::string WebSocket::acceptKey(const std::string& clientKey) {
  static const char* kGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  uint8_t digest[20];
  Sha1::hash(clientKey + kGuid, digest);
  return base64Encode(digest, 20);
}

bool WebSocket::sendFrame(uint8_t opcode, const uint8_t* payload, size_t len, bool fin) {
  if (state_.load() != WsState::Open && opcode < 0x8) return false;
  Bytes frame;
  frame.reserve(len + 14);
  frame.push_back(static_cast<uint8_t>((fin ? 0x80 : 0x00) | (opcode & 0x0F)));
  // 服务端发出的帧不加掩码（客户端发出的帧必须加掩码，RFC 6455）
  const bool mask = !serverSideFlag_;
  if (len < 126) {
    frame.push_back(static_cast<uint8_t>((mask ? 0x80 : 0x00) | len));
  } else if (len <= 0xFFFF) {
    frame.push_back(static_cast<uint8_t>((mask ? 0x80 : 0x00) | 126));
    frame.push_back(static_cast<uint8_t>((len >> 8) & 0xff));
    frame.push_back(static_cast<uint8_t>(len & 0xff));
  } else {
    frame.push_back(static_cast<uint8_t>((mask ? 0x80 : 0x00) | 127));
    for (int i = 7; i >= 0; i--)
      frame.push_back(static_cast<uint8_t>((static_cast<uint64_t>(len) >> (i * 8)) & 0xff));
  }
  if (mask) {
    uint8_t key[4];
    std::random_device rd;
    for (size_t i = 0; i < 4; i++) key[i] = static_cast<uint8_t>(rd() & 0xff);
    frame.insert(frame.end(), key, key + 4);
    const size_t headLen = frame.size();
    frame.resize(headLen + len);
    for (size_t i = 0; i < len; i++)
      frame[headLen + i] = payload ? static_cast<uint8_t>(payload[i] ^ key[i % 4]) : 0;
  } else {
    if (len && payload) frame.insert(frame.end(), payload, payload + len);
  }
  return writeRaw(frame.data(), frame.size());
}

void WebSocket::dispatchFrame(uint8_t opcode, const Bytes& payload, bool fin) {
  if (opcode == kOpContinuation) {
    if (fragOpcode_ == 0) return;  // 无起始帧，忽略
    fragBuf_.insert(fragBuf_.end(), payload.begin(), payload.end());
    if (!fin) return;
    const uint8_t op = fragOpcode_;
    Bytes full = std::move(fragBuf_);
    fragBuf_.clear();
    fragOpcode_ = 0;
    dispatchFrame(op, full, true);
    return;
  }
  if (!fin) {
    fragOpcode_ = opcode;
    fragBuf_ = payload;
    return;
  }
  if (opcode == kOpText) {
    if (textHandler_) textHandler_(std::string(reinterpret_cast<const char*>(payload.data()), payload.size()));
  } else if (opcode == kOpBinary) {
    if (binaryHandler_) binaryHandler_(payload.data(), payload.size());
  }
}

void WebSocket::emitClose(const std::string& reason) {
  if (closeEmitted_) return;
  closeEmitted_ = true;
  if (closeHandler_) closeHandler_(reason);
}

std::shared_ptr<WebSocket> WebSocket::connectClient(std::shared_ptr<TcpSocket> sock,
                                                    std::shared_ptr<TlsStream> tls,
                                                    const std::string& host,
                                                    const std::string& path,
                                                    const std::string& extraHeaders) {
  auto impl = std::make_shared<WsImpl>(
      tls ? std::static_pointer_cast<Stream>(tls) : makePlainStream(sock), sock, false);
  impl->setServerSide(false);
  if (!impl->clientHandshake(host, path, extraHeaders)) return nullptr;
  return impl;
}

std::shared_ptr<WebSocket> WebSocket::fromServerStream(std::shared_ptr<TcpSocket> sock,
                                                        std::shared_ptr<TlsStream> tls,
                                                        const std::string& acceptKeyValue) {
  (void)acceptKeyValue;
  auto impl = std::make_shared<WsImpl>(
      tls ? std::static_pointer_cast<Stream>(tls) : makePlainStream(sock), sock, true);
  impl->setServerSide(true);
  impl->setStateOpen();
  return impl;
}

}  // namespace hwp
