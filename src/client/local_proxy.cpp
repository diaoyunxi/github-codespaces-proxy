#include "local_proxy.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

#include "../common/util.hpp"

namespace hwp {

bool parseHostHeader(const std::string& hostHeader, uint16_t defaultPort, std::string& host,
                     uint16_t& port) {
  const std::string value = trim(hostHeader);
  if (value.empty()) return false;
  if (value.front() == '[') {
    const auto end = value.find(']');
    if (end == std::string::npos) return false;
    host = value.substr(1, end - 1);
    if (end + 1 < value.size() && value[end + 1] == ':') {
      try {
        port = static_cast<uint16_t>(std::stoi(value.substr(end + 2)));
      } catch (...) {
        return false;
      }
    } else {
      port = defaultPort;
    }
    return !host.empty();
  }
  const auto colon = value.rfind(':');
  if (colon != std::string::npos && colon + 1 < value.size() &&
      value.find(':') == colon && std::isdigit(static_cast<unsigned char>(value[colon + 1]))) {
    host = value.substr(0, colon);
    try {
      port = static_cast<uint16_t>(std::stoi(value.substr(colon + 1)));
    } catch (...) {
      return false;
    }
  } else {
    host = value;
    port = defaultPort;
  }
  return !host.empty();
}

bool parseAbsoluteTarget(const std::string& target, std::string& host, uint16_t& port) {
  std::string rest;
  uint16_t def = 80;
  if (target.rfind("http://", 0) == 0) {
    rest = target.substr(7);
    def = 80;
  } else if (target.rfind("https://", 0) == 0) {
    rest = target.substr(8);
    def = 443;
  } else {
    return false;
  }
  const auto slash = rest.find('/');
  std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
  if (authority.empty()) return false;
  return parseHostHeader(authority, def, host, port);
}

namespace {

/** 从 HTTP 头解析请求行与头部 */
bool parseRequestHead(const std::string& head, std::string& method, std::string& target,
                      std::string& version, std::vector<std::pair<std::string, std::string>>& headers) {
  std::istringstream ss(head);
  std::string line;
  if (!std::getline(ss, line)) return false;
  if (!line.empty() && line.back() == '\r') line.pop_back();
  std::istringstream ls(line);
  ls >> method >> target >> version;
  if (method.empty() || target.empty()) return false;
  while (std::getline(ss, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    const auto c = line.find(':');
    if (c == std::string::npos) continue;
    headers.emplace_back(line.substr(0, c), trim(line.substr(c + 1)));
  }
  return true;
}

bool isHopByHop(const std::string& name) {
  static const char* kNames[] = {"proxy-connection", "proxy-authorization", "proxy-authenticate",
                                 "keep-alive",       "transfer-encoding",   "connection",
                                 "upgrade",          "te",                  "trailer"};
  const std::string lower = toLower(name);
  for (const char* n : kNames) {
    if (lower == n) return true;
  }
  return false;
}

void replyError(const std::shared_ptr<TcpSocket>& sock, int status, const std::string& text) {
  const std::string body = std::to_string(status) + " " + text + "\n";
  const std::string resp = "HTTP/1.1 " + std::to_string(status) + " " + text +
                           "\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: " +
                           std::to_string(body.size()) +
                           "\r\nProxy-Agent: http-over-wss\r\nConnection: close\r\n\r\n" + body;
  sock->writeAll(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
  sock->shutdownWrite();
}

}  // namespace

LocalProxy::LocalProxy(ProxyOptions opts) : opts_(std::move(opts)) {}

LocalProxy::~LocalProxy() { stop(); }

bool LocalProxy::listen(const std::string& host, uint16_t port, std::string* err) {
  listener_ = TcpSocket::listenOn(host, port, err);
  if (!listener_) return false;
  running_.store(true);
  std::thread([this] { acceptLoop(); }).detach();
  if (opts_.log) opts_.log("listening on http://" + host + ":" + std::to_string(port));
  return true;
}

void LocalProxy::stop() {
  if (stopping_.exchange(true)) return;
  running_.store(false);
  if (listener_) {
    listener_->close();
    listener_.reset();
  }
}

void LocalProxy::acceptLoop() {
  while (running_.load() && listener_) {
    auto conn = listener_->acceptConn(500);
    if (!conn) continue;
    try {
      handleConn(conn);
    } catch (const std::exception& e) {
      if (opts_.log) opts_.log(std::string("conn handler error: ") + e.what());
      conn->close();
    }
  }
}

void LocalProxy::handleConn(std::shared_ptr<TcpSocket> sock) {
  sock->setNoDelay(true);
  std::string head;
  if (!sock->readUntil("\r\n\r\n", head, 64 * 1024, 30000)) {
    sock->close();
    return;
  }
  // 去掉尾部空行
  const size_t headEnd = head.find("\r\n\r\n");
  std::string headOnly = head.substr(0, headEnd);

  std::string method, target, version;
  std::vector<std::pair<std::string, std::string>> headers;
  if (!parseRequestHead(headOnly, method, target, version, headers)) {
    replyError(sock, 400, "Bad Request");
    sock->close();
    return;
  }

  // ---- CONNECT 隧道 ----
  if (iequals(method, "CONNECT")) {
    std::string host;
    uint16_t port = 443;
    if (!parseHostHeader(target, 443, host, port)) {
      replyError(sock, 400, "Bad Request: invalid CONNECT target");
      sock->close();
      return;
    }
    auto session = opts_.tunnel->openSession(host, port);
    if (!session) {
      replyError(sock, 502, "Bad Gateway: tunnel not ready");
      sock->close();
      return;
    }
    handleConnectTunnel(sock, headOnly, {}, session);
    return;
  }

  // ---- 普通明文 HTTP ----
  std::string host;
  uint16_t port = 80;
  bool ok = false;
  if (target.rfind("http://", 0) == 0 || target.rfind("https://", 0) == 0) {
    ok = parseAbsoluteTarget(target, host, port);
  }
  if (!ok) {
    for (const auto& [name, value] : headers) {
      if (iequals(name, "host")) {
        ok = parseHostHeader(value, 80, host, port);
        break;
      }
    }
  }
  if (!ok) {
    replyError(sock, 400, "Bad Request: cannot determine target host");
    sock->close();
    return;
  }

  auto session = opts_.tunnel->openSession(host, port);
  if (!session) {
    replyError(sock, 502, "Bad Gateway: tunnel not ready");
    sock->close();
    return;
  }

  // 重建请求行 + 头部（剥离逐跳头，追加 Connection: close）
  std::string rebuilt = method + " " + target + " HTTP/1.1\r\n";
  for (const auto& [name, value] : headers) {
    if (isHopByHop(name)) continue;
    rebuilt += name + ": " + value + "\r\n";
  }
  rebuilt += "Connection: close\r\n\r\n";
  const Bytes headBytes(rebuilt.begin(), rebuilt.end());

  handlePlainHttp(sock, rebuilt, headBytes, session);
}

/**
 * 建连前的缓存字节：会话未就绪时先缓存，收到 connected 后按序补发。
 * 这是协议要求（服务端在 connecting 状态丢弃数据帧）。
 */
void LocalProxy::handleConnectTunnel(std::shared_ptr<TcpSocket> sock, const std::string& head,
                                     const Bytes& headPrefix,
                                     std::shared_ptr<TunnelSession> session) {
  (void)head;
  (void)headPrefix;
  auto sharedSock = sock;
  auto pending = std::make_shared<std::vector<Bytes>>();
  auto opened = std::make_shared<std::atomic<bool>>(false);
  auto halfPending = std::make_shared<std::atomic<bool>>(false);
  auto closed = std::make_shared<std::atomic<bool>>(false);
  auto idleTimerStop = std::make_shared<std::atomic<bool>>(false);

  session->onError = [sharedSock, session, opened](const std::string& message) {
    if (!sharedSock->valid()) return;
    if (!opened->load()) replyError(sharedSock, 502, "Bad Gateway: " + message);
    else sharedSock->close();
  };

  session->onOpen = [this, sharedSock, session, pending, opened, halfPending] {
    opened->store(true);
    sharedSock->writeAll(reinterpret_cast<const uint8_t*>(
                             "HTTP/1.1 200 Connection Established\r\nProxy-Agent: http-over-wss\r\n\r\n"),
                         sizeof("HTTP/1.1 200 Connection Established\r\nProxy-Agent: http-over-wss\r\n\r\n") - 1);
    for (auto& chunk : *pending) opts_.tunnel->push(session, chunk.data(), chunk.size());
    pending->clear();
    if (halfPending->load()) opts_.tunnel->pushEnd(session);
  };

  session->onData = [sharedSock](const uint8_t* data, size_t len) {
    if (!sharedSock->valid()) return;
    sharedSock->writeAll(data, len);
  };

  session->onClose = [sharedSock, closed](const std::string&) {
    if (closed->exchange(true)) return;
    if (sharedSock->valid()) {
      sharedSock->shutdownWrite();
      sharedSock->close();
    }
  };

  // 客户端 → 隧道 搬运线程
  std::thread pump([this, sharedSock, session, pending, opened, halfPending, closed] {
    Bytes buf(64 * 1024);
    while (sharedSock->valid()) {
      const ssize_t n = sharedSock->readSome(buf.data(), buf.size(), 500);
      if (n == 0) {
        // 客户端半关写端：只传播上行 EOF，保留下行
        if (opened->load()) opts_.tunnel->pushEnd(session);
        else halfPending->store(true);
        break;
      }
      if (n < 0) {
        if (closed->load()) break;
        continue;
      }
      if (opened->load()) {
        if (!opts_.tunnel->push(session, buf.data(), static_cast<size_t>(n))) break;
      } else {
        pending->emplace_back(buf.begin(), buf.begin() + n);
      }
    }
  });
  pump.join();

  if (!closed->exchange(true)) {
    opts_.tunnel->closeSession(session, "client closed", true);
    if (sharedSock->valid()) sharedSock->close();
  }
}

void LocalProxy::handlePlainHttp(std::shared_ptr<TcpSocket> sock, const std::string& head,
                                 const Bytes& headBytes, std::shared_ptr<TunnelSession> session) {
  (void)head;
  auto sharedSock = sock;
  auto pending = std::make_shared<std::vector<Bytes>>();
  auto opened = std::make_shared<std::atomic<bool>>(false);
  auto halfPending = std::make_shared<std::atomic<bool>>(false);
  auto closed = std::make_shared<std::atomic<bool>>(false);

  session->onError = [sharedSock, opened](const std::string& message) {
    if (!sharedSock->valid()) return;
    if (!opened->load()) replyError(sharedSock, 502, "Bad Gateway: " + message);
    else sharedSock->close();
  };

  session->onOpen = [this, sharedSock, session, pending, opened, halfPending, headBytes] {
    opened->store(true);
    opts_.tunnel->push(session, headBytes.data(), headBytes.size());
    for (auto& chunk : *pending) opts_.tunnel->push(session, chunk.data(), chunk.size());
    pending->clear();
    if (halfPending->load()) opts_.tunnel->pushEnd(session);
  };

  session->onData = [sharedSock](const uint8_t* data, size_t len) {
    if (!sharedSock->valid()) return;
    // 响应字节原样透传，不经任何二次分帧
    sharedSock->writeAll(data, len);
  };

  session->onClose = [sharedSock, closed](const std::string&) {
    if (closed->exchange(true)) return;
    if (sharedSock->valid()) {
      sharedSock->shutdownWrite();
      sharedSock->close();
    }
  };

  std::thread pump([this, sharedSock, session, pending, opened, halfPending, closed] {
    Bytes buf(64 * 1024);
    while (sharedSock->valid()) {
      const ssize_t n = sharedSock->readSome(buf.data(), buf.size(), 500);
      if (n == 0) {
        if (opened->load()) opts_.tunnel->pushEnd(session);
        else halfPending->store(true);
        break;
      }
      if (n < 0) {
        if (closed->load()) break;
        continue;
      }
      if (opened->load()) {
        if (!opts_.tunnel->push(session, buf.data(), static_cast<size_t>(n))) break;
      } else {
        pending->emplace_back(buf.begin(), buf.begin() + n);
      }
    }
  });
  pump.join();

  if (!closed->exchange(true)) {
    opts_.tunnel->closeSession(session, "client closed", true);
    if (sharedSock->valid()) sharedSock->close();
  }
}

}  // namespace hwp
