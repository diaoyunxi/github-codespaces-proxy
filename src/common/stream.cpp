#include "stream.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cstring>
#include <mutex>

#include "util.hpp"

namespace hwp {
namespace {

void ensureSslInit() {
  static std::once_flag once;
  std::call_once(once, [] {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
  });
}

std::string lastSslError() {
  const unsigned long e = ERR_get_error();
  if (!e) return "unknown TLS error";
  char buf[256];
  ERR_error_string_n(e, buf, sizeof(buf));
  return std::string(buf);
}

}  // namespace

bool Stream::readUntil(const std::string& delim, std::string& out, size_t maxBytes,
                      int timeoutMs) {
  out.clear();
  uint8_t buf[4096];
  while (out.size() < maxBytes) {
    const ssize_t n = read(buf, sizeof(buf), timeoutMs);
    if (n <= 0) return false;
    out.append(reinterpret_cast<char*>(buf), static_cast<size_t>(n));
    const auto pos = out.find(delim);
    if (pos != std::string::npos) {
      out.resize(pos + delim.size());
      return true;
    }
  }
  return false;
}

TlsStream::~TlsStream() {
  if (ssl_) {
    SSL_free(static_cast<SSL*>(ssl_));
    ssl_ = nullptr;
  }
}

std::shared_ptr<TlsStream> TlsStream::serverHandshake(std::shared_ptr<TcpSocket> sock,
                                                      const std::string& certFile,
                                                      const std::string& keyFile,
                                                      std::string* err) {
  ensureSslInit();
  SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx) {
    if (err) *err = "SSL_CTX_new failed";
    return nullptr;
  }
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  if (SSL_CTX_use_certificate_chain_file(ctx, certFile.c_str()) != 1) {
    if (err) *err = "load cert failed: " + certFile + " (" + lastSslError() + ")";
    SSL_CTX_free(ctx);
    return nullptr;
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) != 1) {
    if (err) *err = "load key failed: " + keyFile + " (" + lastSslError() + ")";
    SSL_CTX_free(ctx);
    return nullptr;
  }
  SSL* ssl = SSL_new(ctx);
  SSL_CTX_free(ctx);
  if (!ssl) {
    if (err) *err = "SSL_new failed";
    return nullptr;
  }
  SSL_set_fd(ssl, static_cast<int>(sock->fd()));
  if (SSL_accept(ssl) != 1) {
    if (err) *err = "TLS accept failed (" + lastSslError() + ")";
    SSL_free(ssl);
    return nullptr;
  }
  auto t = std::shared_ptr<TlsStream>(new TlsStream());
  t->ssl_ = ssl;
  t->sock_ = std::move(sock);
  return t;
}

std::shared_ptr<TlsStream> TlsStream::clientHandshake(std::shared_ptr<TcpSocket> sock,
                                                      const std::string& sniHost,
                                                      bool verifyPeer,
                                                      const std::string& caFile,
                                                      std::string* err) {
  ensureSslInit();
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) {
    if (err) *err = "SSL_CTX_new failed";
    return nullptr;
  }
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  if (verifyPeer) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    if (!caFile.empty()) {
      if (SSL_CTX_load_verify_locations(ctx, caFile.c_str(), nullptr) != 1) {
        if (err) *err = "load ca failed: " + caFile;
        SSL_CTX_free(ctx);
        return nullptr;
      }
    } else {
      SSL_CTX_set_default_verify_paths(ctx);
    }
  } else {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
  }
  SSL* ssl = SSL_new(ctx);
  SSL_CTX_free(ctx);
  if (!ssl) {
    if (err) *err = "SSL_new failed";
    return nullptr;
  }
  SSL_set_fd(ssl, static_cast<int>(sock->fd()));
  if (!sniHost.empty()) SSL_set_tlsext_host_name(ssl, sniHost.c_str());
  if (verifyPeer && !sniHost.empty()) {
    X509_VERIFY_PARAM* param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set1_host(param, sniHost.c_str(), 0);
  }
  if (SSL_connect(ssl) != 1) {
    if (err) *err = "TLS connect failed (" + lastSslError() + ")";
    SSL_free(ssl);
    return nullptr;
  }
  auto t = std::shared_ptr<TlsStream>(new TlsStream());
  t->ssl_ = ssl;
  t->sock_ = std::move(sock);
  return t;
}

ssize_t TlsStream::read(uint8_t* buf, size_t len, int timeoutMs) {
  if (!ssl_ || !sock_) return -1;
  SSL* ssl = static_cast<SSL*>(ssl_);
  /*
   * 关键：绝不能在 SSL_read 之前先对底层 socket 做「可读判断」。
   * TLS 记录可能被 TCP 分片，socket 可读不代表一条完整记录已到齐；
   * 此时 SSL_read 只吃下部分记录并缓存，若我们把它当失败丢弃，
   * 后续帧头就会错位。
   * 正确做法：只有当 SSL 内部缓冲为空、且本次已真正读到过数据/等待超时时，
   * 才依赖底层 socket 超时来结束等待；其余情况一律直接 SSL_read。
   */
  const int64_t deadline = timeoutMs < 0 ? 0 : nowMs() + timeoutMs;
  for (;;) {
    const int n = SSL_read(ssl, buf, static_cast<int>(len));
    if (n > 0) return n;
    const int e = SSL_get_error(ssl, n);
    if (e == SSL_ERROR_ZERO_RETURN) return 0;
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
      // 需要更多底层字节：等 socket。无限阻塞场景下也切片等待以便响应退出。
      const int slice = timeoutMs < 0 ? 200 : 200;
      int waitMs = slice;
      if (timeoutMs >= 0) {
        const int64_t left = deadline - nowMs();
        if (left <= 0) return -1;
        if (left < slice) waitMs = static_cast<int>(left);
      }
      const int ready = sock_->waitReadable(waitMs);
      if (ready < 0) return -1;
      if (ready == 0 && timeoutMs >= 0) return -1;
      continue;
    }
    return -1;
  }
}

bool TlsStream::writeAll(const uint8_t* data, size_t len) {
  if (!ssl_) return false;
  size_t off = 0;
  while (off < len) {
    const int n = SSL_write(static_cast<SSL*>(ssl_), data + off, static_cast<int>(len - off));
    if (n <= 0) return false;
    off += static_cast<size_t>(n);
  }
  return true;
}

void TlsStream::shutdownWrite() {
  if (ssl_) SSL_shutdown(static_cast<SSL*>(ssl_));
  if (sock_) sock_->shutdownWrite();
}

void TlsStream::close() {
  if (ssl_) {
    SSL_free(static_cast<SSL*>(ssl_));
    ssl_ = nullptr;
  }
  if (sock_) sock_->close();
}

std::string TlsStream::peerAddress() const { return sock_ ? sock_->peerAddress() : "unknown"; }

// ---- 明文流工厂（避免在头文件里引入细节）----
std::shared_ptr<Stream> makePlainStream(std::shared_ptr<TcpSocket> sock) {
  return std::make_shared<PlainStream>(std::move(sock));
}

}  // namespace hwp
