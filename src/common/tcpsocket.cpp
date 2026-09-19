#include "tcpsocket.hpp"

#ifdef _WIN32
#include <mstcpip.h>
#else
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <atomic>
#include <cstring>
#include <mutex>

#include "util.hpp"

namespace hwp {
namespace {

#ifdef _WIN32
bool inProgress() {
  const int e = WSAGetLastError();
  return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == WSAEINVAL || e == WSAENOTCONN;
}
void closeFd(socket_t fd) { closesocket(fd); }
#else
bool inProgress() { return errno == EINPROGRESS || errno == EAGAIN || errno == EWOULDBLOCK; }
void closeFd(socket_t fd) { ::close(fd); }
#endif

bool setNonBlocking(socket_t fd, bool on) {
#ifdef _WIN32
  u_long mode = on ? 1 : 0;
  return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
  const int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return false;
  return fcntl(fd, F_SETFL, on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK)) == 0;
#endif
}

void setTimeoutOpt(socket_t fd, int timeoutMs) {
#ifdef _WIN32
  DWORD tv = static_cast<DWORD>(timeoutMs < 0 ? 0 : timeoutMs);
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
  timeval tv{};
  if (timeoutMs >= 0) {
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
  }
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

}  // namespace

void socketInitGlobal() {
#ifdef _WIN32
  static std::once_flag once;
  std::call_once(once, [] {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
  });
#else
  // 忽略 SIGPIPE：写已关闭的 socket 不应终止进程
  static std::once_flag once;
  std::call_once(once, [] { signal(SIGPIPE, SIG_IGN); });
#endif
}

void socketCleanupGlobal() {
#ifdef _WIN32
  WSACleanup();
#endif
}

std::vector<AddrInfo> resolveAll(const std::string& host) {
  std::vector<AddrInfo> out;
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* res = nullptr;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) return out;
  for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
    AddrInfo a;
    if (p->ai_family == AF_INET) {
      char buf[INET_ADDRSTRLEN] = {0};
      auto* sin = reinterpret_cast<sockaddr_in*>(p->ai_addr);
      inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
      a.address = buf;
      a.family = 4;
    } else if (p->ai_family == AF_INET6) {
      char buf[INET6_ADDRSTRLEN] = {0};
      auto* sin6 = reinterpret_cast<sockaddr_in6*>(p->ai_addr);
      inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
      a.address = buf;
      a.family = 6;
      a.scopeId = sin6->sin6_scope_id;
    } else {
      continue;
    }
    // 去重
    bool dup = false;
    for (const auto& e : out)
      if (e.address == a.address && e.family == a.family) dup = true;
    if (!dup) out.push_back(a);
  }
  freeaddrinfo(res);
  return out;
}

std::string sockaddrToString(const void* storage, size_t len) {
  (void)len;
  const auto* sa = static_cast<const sockaddr*>(storage);
  if (!sa) return "unknown";
  char buf[INET6_ADDRSTRLEN + 16] = {0};
  if (sa->sa_family == AF_INET) {
    auto* sin = reinterpret_cast<const sockaddr_in*>(sa);
    inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
    return buf;
  }
  if (sa->sa_family == AF_INET6) {
    auto* sin6 = reinterpret_cast<const sockaddr_in6*>(sa);
    inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
    return buf;
  }
  return "unknown";
}

bool parseSockAddr(const std::string& host, uint16_t port, void* outStorage, int* outLen) {
  // IPv4 字面量
  if (host.find(':') == std::string::npos) {
    auto* sin = static_cast<sockaddr_in*>(outStorage);
    std::memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &sin->sin_addr) == 1) {
      *outLen = sizeof(*sin);
      return true;
    }
    return false;
  }
  auto* sin6 = static_cast<sockaddr_in6*>(outStorage);
  std::memset(sin6, 0, sizeof(*sin6));
  sin6->sin6_family = AF_INET6;
  sin6->sin6_port = htons(port);
  std::string h = host;
  const auto zone = h.find('%');
  if (zone != std::string::npos) h = h.substr(0, zone);
  if (inet_pton(AF_INET6, h.c_str(), &sin6->sin6_addr) != 1) return false;
  *outLen = sizeof(*sin6);
  return true;
}

TcpSocket::~TcpSocket() { close(); }

std::shared_ptr<TcpSocket> TcpSocket::adopt(socket_t fd) {
  auto s = std::shared_ptr<TcpSocket>(new TcpSocket(fd));
  sockaddr_storage ss{};
  socklen_t l = sizeof(ss);
  if (getpeername(fd, reinterpret_cast<sockaddr*>(&ss), &l) == 0)
    s->peer_ = sockaddrToString(&ss, l);
  l = sizeof(ss);
  if (getsockname(fd, reinterpret_cast<sockaddr*>(&ss), &l) == 0)
    s->local_ = sockaddrToString(&ss, l);
  return s;
}

std::shared_ptr<TcpSocket> TcpSocket::connectToAddr(const std::string& ip, uint16_t port,
                                                   int timeoutMs, uint32_t scopeId) {
  sockaddr_storage ss{};
  int len = 0;
  if (!parseSockAddr(ip, port, &ss, &len)) {
    // 非字面量：走 DNS
    return connectTo(ip, port, timeoutMs);
  }
  if (ss.ss_family == AF_INET6 && scopeId)
    reinterpret_cast<sockaddr_in6*>(&ss)->sin6_scope_id = scopeId;

  socket_t fd = ::socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
  if (fd == kInvalidSocket) return nullptr;
  setNonBlocking(fd, true);
  const int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&ss), len);
  if (rc != 0) {
    if (!inProgress()) {
      closeFd(fd);
      return nullptr;
    }
#ifdef _WIN32
    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(fd, &wset);
    timeval tv{};
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    if (select(0, nullptr, &wset, nullptr, &tv) <= 0) {
      closeFd(fd);
      return nullptr;
    }
    int err = 0;
    int elen = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &elen) != 0 || err != 0) {
      closeFd(fd);
      return nullptr;
    }
#else
    pollfd pfd{fd, POLLOUT, 0};
    if (poll(&pfd, 1, timeoutMs) <= 0 || (pfd.revents & (POLLERR | POLLHUP))) {
      closeFd(fd);
      return nullptr;
    }
    int err = 0;
    socklen_t elen = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
      closeFd(fd);
      return nullptr;
    }
#endif
  }
  // 恢复阻塞模式
  setNonBlocking(fd, false);
  setTimeoutOpt(fd, -1);
  int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
  return adopt(fd);
}

std::shared_ptr<TcpSocket> TcpSocket::connectTo(const std::string& host, uint16_t port,
                                               int timeoutMs) {
  const auto addrs = resolveAll(host);
  for (const auto& a : addrs) {
    auto s = connectToAddr(a.address, port, timeoutMs, a.scopeId);
    if (s) return s;
  }
  return nullptr;
}

std::shared_ptr<TcpSocket> TcpSocket::listenOn(const std::string& host, uint16_t port,
                                               std::string* err) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* res = nullptr;
  const char* node = host.empty() ? nullptr : host.c_str();
  const std::string portStr = std::to_string(port);
  if (getaddrinfo(node, portStr.c_str(), &hints, &res) != 0) {
    if (err) *err = "getaddrinfo failed";
    return nullptr;
  }
  socket_t fd = kInvalidSocket;
  for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
    fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd == kInvalidSocket) continue;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one), sizeof(one));
    if (p->ai_family == AF_INET6) {
      int v6only = 0;
      setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&v6only), sizeof(v6only));
    }
    if (::bind(fd, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0 && ::listen(fd, 128) == 0)
      break;
    closeFd(fd);
    fd = kInvalidSocket;
  }
  if (fd == kInvalidSocket && err) *err = "bind/listen failed";
  freeaddrinfo(res);
  if (fd == kInvalidSocket) return nullptr;
  return adopt(fd);
}

std::shared_ptr<TcpSocket> TcpSocket::acceptConn(int timeoutMs) {
  if (!valid()) return nullptr;
  if (timeoutMs >= 0) {
#ifdef _WIN32
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(fd_, &rset);
    timeval tv{};
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    if (select(0, &rset, nullptr, nullptr, &tv) <= 0) return nullptr;
#else
    pollfd pfd{fd_, POLLIN, 0};
    if (poll(&pfd, 1, timeoutMs) <= 0) return nullptr;
#endif
  }
  sockaddr_storage ss{};
  socklen_t l = sizeof(ss);
  socket_t c = ::accept(fd_, reinterpret_cast<sockaddr*>(&ss), &l);
  if (c == kInvalidSocket) return nullptr;
  auto s = std::shared_ptr<TcpSocket>(new TcpSocket(c));
  s->peer_ = sockaddrToString(&ss, l);
  return s;
}

std::string TcpSocket::peerAddress() const { return peer_; }
std::string TcpSocket::localAddress() const { return local_; }

int TcpSocket::waitReadable(int timeoutMs) {
  if (!valid()) return -1;
  if (timeoutMs < 0) {
    // 无限等待
#ifdef _WIN32
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(fd_, &rset);
    return select(0, &rset, nullptr, nullptr, nullptr) > 0 ? 1 : -1;
#else
    pollfd pfd{fd_, POLLIN, 0};
    return poll(&pfd, 1, -1) > 0 ? 1 : -1;
#endif
  }
  int waited = 0;
  const int slice = 200;
  while (waited <= timeoutMs) {
#ifdef _WIN32
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(fd_, &rset);
    timeval tv{};
    tv.tv_sec = slice / 1000;
    tv.tv_usec = (slice % 1000) * 1000;
    const int s = select(0, &rset, nullptr, nullptr, &tv);
#else
    pollfd pfd{fd_, POLLIN, 0};
    const int s = poll(&pfd, 1, slice);
#endif
    if (s > 0) return 1;
    if (s < 0) return -1;
    waited += slice;
  }
  return 0;
}

ssize_t TcpSocket::readSome(uint8_t* buf, size_t len, int timeoutMs) {
  if (!valid()) return -1;
  if (timeoutMs >= 0) {
    int waited = 0;
    const int slice = 200;
    while (waited <= timeoutMs) {
#ifdef _WIN32
      fd_set rset;
      FD_ZERO(&rset);
      FD_SET(fd_, &rset);
      timeval tv{};
      tv.tv_sec = slice / 1000;
      tv.tv_usec = (slice % 1000) * 1000;
      const int s = select(0, &rset, nullptr, nullptr, &tv);
#else
      pollfd pfd{fd_, POLLIN, 0};
      const int s = poll(&pfd, 1, slice);
#endif
      if (s > 0) break;
      if (s < 0) return -1;
      waited += slice;
      if (timeoutMs == 0) return -1;
    }
    if (waited > timeoutMs) return -1;
  }
#ifdef _WIN32
  const int n = recv(fd_, reinterpret_cast<char*>(buf), static_cast<int>(len), 0);
#else
  const ssize_t n = ::recv(fd_, buf, len, 0);
#endif
  if (n > 0) return n;
  if (n == 0) return 0;
  return -1;
}

bool TcpSocket::writeAll(const uint8_t* data, size_t len) {
  if (!valid()) return false;
  size_t off = 0;
  while (off < len) {
#ifdef _WIN32
    const int n = send(fd_, reinterpret_cast<const char*>(data + off),
                       static_cast<int>(len - off), 0);
#else
    const ssize_t n = ::send(fd_, data + off, len - off, MSG_NOSIGNAL);
#endif
    if (n <= 0) return false;
    off += static_cast<size_t>(n);
  }
  return true;
}

bool TcpSocket::readExact(uint8_t* buf, size_t n, int timeoutMs) {
  size_t off = 0;
  int remaining = timeoutMs;
  while (off < n) {
    const ssize_t r = readSome(buf + off, n - off, remaining);
    if (r <= 0) return false;
    off += static_cast<size_t>(r);
  }
  return true;
}

bool TcpSocket::readUntil(const std::string& delim, std::string& out, size_t maxBytes,
                          int timeoutMs) {
  out.clear();
  uint8_t buf[4096];
  while (out.size() < maxBytes) {
    const ssize_t n = readSome(buf, sizeof(buf), timeoutMs);
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

void TcpSocket::shutdownWrite() {
  if (!valid()) return;
#ifdef _WIN32
  ::shutdown(fd_, SD_SEND);
#else
  ::shutdown(fd_, SHUT_WR);
#endif
}

void TcpSocket::close() {
  if (fd_ == kInvalidSocket) return;
  closeFd(fd_);
  fd_ = kInvalidSocket;
}

void TcpSocket::setNoDelay(bool on) {
  if (!valid()) return;
  int v = on ? 1 : 0;
  setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&v), sizeof(v));
}

void TcpSocket::setKeepAlive(bool on) {
  if (!valid()) return;
  int v = on ? 1 : 0;
  setsockopt(fd_, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&v), sizeof(v));
}

}  // namespace hwp
