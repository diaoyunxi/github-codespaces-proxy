#pragma once
/**
 * 跨平台 socket 封装（阻塞式）：
 *   - Windows：winsock2 + WSAStartup
 *   - Linux/macOS：BSD socket
 *
 * 提供：连接（带超时）、监听、接受、读写（带超时）、关闭、shutdown。
 * 所有 API 出错返回 false / nullptr，不抛异常。
 */
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#ifdef _WIN32
// 防止 windows.h 引入 min/max 宏
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <basetsd.h>  // SSIZE_T
using socket_t = SOCKET;
inline constexpr socket_t kInvalidSocket = INVALID_SOCKET;
// MSVC 只提供大写 SSIZE_T，没有 POSIX 的 ssize_t；本项目公共接口统一用 ssize_t，
// 这里补一个平台别名，保证 Windows / Linux 头文件语义一致。
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
using ssize_t = SSIZE_T;
#endif
#else
#include <sys/types.h>  // ssize_t
using socket_t = int;
inline constexpr socket_t kInvalidSocket = -1;
#endif

namespace hwp {

/** 进程级初始化（Windows 上调用 WSAStartup），幂等 */
void socketInitGlobal();
void socketCleanupGlobal();

/** 本机 IP 枚举（用于 DNS 解析兜底与 SSRF 校验） */
struct AddrInfo {
  std::string address;
  int family = 0;  // 4 / 6
  uint32_t scopeId = 0;
};

/** 字符串网络地址 → sockaddr_storage；失败返回 false */
bool parseSockAddr(const std::string& host, uint16_t port, void* outStorage, int* outLen);

class TcpSocket {
 public:
  static std::shared_ptr<TcpSocket> adopt(socket_t fd);
  /** 建立到 host:port 的连接（DNS 解析内置），超时 time 毫秒 */
  static std::shared_ptr<TcpSocket> connectTo(const std::string& host, uint16_t port,
                                              int timeoutMs);
  /** 连接已解析好的 IP（避免 TOCTOU：校验地址即连接地址） */
  static std::shared_ptr<TcpSocket> connectToAddr(const std::string& ip, uint16_t port,
                                                  int timeoutMs, uint32_t scopeId = 0);
  /** 创建监听 socket */
  static std::shared_ptr<TcpSocket> listenOn(const std::string& host, uint16_t port,
                                             std::string* err = nullptr);
  /** 接受一个连接；超时返回 nullptr */
  std::shared_ptr<TcpSocket> acceptConn(int timeoutMs = -1);
  /** 本端 / 对端地址字符串展示 */
  std::string peerAddress() const;
  std::string localAddress() const;

  /** 读：返回读取字节数；0 = 对端关闭；-1 = 错误 / 超时 */
  ssize_t readSome(uint8_t* buf, size_t len, int timeoutMs = -1);
  /** 等待可读；>0 可读，0 超时，<0 错误 */
  int waitReadable(int timeoutMs);
  /** 确保写完全部字节 */
  bool writeAll(const uint8_t* data, size_t len);
  /** 读取直到出现 delim 或超过 maxBytes；返回已读数据（含 delim） */
  bool readUntil(const std::string& delim, std::string& out, size_t maxBytes = 64 * 1024,
                 int timeoutMs = 15000);
  /** 读满 n 字节 */
  bool readExact(uint8_t* buf, size_t n, int timeoutMs = 15000);

  void shutdownWrite();
  void close();
  bool valid() const { return fd_ != kInvalidSocket; }
  ~TcpSocket();
  socket_t fd() const { return fd_; }
  void setNoDelay(bool on);
  void setKeepAlive(bool on);

 private:
  explicit TcpSocket(socket_t fd) : fd_(fd) {}
  socket_t fd_ = kInvalidSocket;
  std::string peer_;
  std::string local_;
};

/** DNS 解析：返回全部地址（含 IPv6），失败返回空 */
std::vector<AddrInfo> resolveAll(const std::string& host);
/** sockaddr → 可读字符串 */
std::string sockaddrToString(const void* storage, size_t len);

}  // namespace hwp
