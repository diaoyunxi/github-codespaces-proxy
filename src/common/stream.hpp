#pragma once
/**
 * 字节流抽象：统一 明文 TCP 与 TLS 的读写。
 * WebSocket 只依赖本接口，因此 ws:// 与 wss:// 走同一套帧编解码。
 */
#include <cstdint>
#include <memory>
#include <string>

#include "tcpsocket.hpp"

namespace hwp {

class Stream {
 public:
  virtual ~Stream() = default;
  /** 读取直到出现 delim（含 delim），供 HTTP/WS 握手使用 */
  bool readUntil(const std::string& delim, std::string& out, size_t maxBytes = 64 * 1024,
                 int timeoutMs = 15000);
  /** 读：>0 字节数，0 = EOF，-1 = 错误 / 超时 */
  virtual ssize_t read(uint8_t* buf, size_t len, int timeoutMs = -1) = 0;
  virtual bool writeAll(const uint8_t* data, size_t len) = 0;
  virtual void shutdownWrite() = 0;
  virtual void close() = 0;
  virtual std::string peerAddress() const = 0;
};

/** 明文 TCP 流 */
class PlainStream : public Stream {
 public:
  explicit PlainStream(std::shared_ptr<TcpSocket> s) : sock_(std::move(s)) {}
  ssize_t read(uint8_t* buf, size_t len, int timeoutMs) override {
    return sock_->readSome(buf, len, timeoutMs);
  }
  bool writeAll(const uint8_t* data, size_t len) override { return sock_->writeAll(data, len); }
  void shutdownWrite() override { sock_->shutdownWrite(); }
  void close() override { sock_->close(); }
  std::string peerAddress() const override { return sock_->peerAddress(); }
  std::shared_ptr<TcpSocket> socket() const { return sock_; }

 private:
  std::shared_ptr<TcpSocket> sock_;
};

/** TLS 流（OpenSSL）*/
class TlsStream : public Stream {
 public:
  static std::shared_ptr<TlsStream> serverHandshake(std::shared_ptr<TcpSocket> sock,
                                                    const std::string& certFile,
                                                    const std::string& keyFile,
                                                    std::string* err);
  static std::shared_ptr<TlsStream> clientHandshake(std::shared_ptr<TcpSocket> sock,
                                                    const std::string& sniHost,
                                                    bool verifyPeer,
                                                    const std::string& caFile,
                                                    std::string* err);
  ~TlsStream() override;
  ssize_t read(uint8_t* buf, size_t len, int timeoutMs) override;
  bool writeAll(const uint8_t* data, size_t len) override;
  void shutdownWrite() override;
  void close() override;
  std::string peerAddress() const override;

 private:
  TlsStream() = default;
  void* ssl_ = nullptr;  // SSL*
  std::shared_ptr<TcpSocket> sock_;
};

}  // namespace hwp

namespace hwp {
/** 构造明文流的便捷函数 */
std::shared_ptr<Stream> makePlainStream(std::shared_ptr<TcpSocket> sock);
}  // namespace hwp
