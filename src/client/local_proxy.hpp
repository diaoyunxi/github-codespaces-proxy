#pragma once
/**
 * 本地用户态 HTTP 代理（127.0.0.1:8080）—— 与 Node 版 client/http-proxy.js 等价。
 *
 * 关键约束：
 *   - 纯用户态，无网卡、无驱动、无全局路由劫持
 *   - 不本地建立到目标的 TCP 连接，全部经 WSS 隧道
 *   - 同时处理 CONNECT 与普通 HTTP 请求
 *
 * 普通明文 HTTP：只取目标 host:port 与报文边界，原始请求字节原样透传
 * （保留绝对 URL 形式，不改写 request-target）。
 */
#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "../common/tcpsocket.hpp"
#include "tunnel.hpp"

namespace hwp {

struct ProxyOptions {
  std::shared_ptr<WssTunnel> tunnel;
  int halfCloseIdleMs = 3000;
  std::function<void(const std::string&)> log;
};

class LocalProxy {
 public:
  explicit LocalProxy(ProxyOptions opts);
  ~LocalProxy();

  /** 开始监听；失败返回 false */
  bool listen(const std::string& host, uint16_t port, std::string* err = nullptr);
  void stop();
  bool running() const { return running_.load(); }

 private:
  void acceptLoop();
  void handleConn(std::shared_ptr<TcpSocket> sock);
  void handleConnectTunnel(std::shared_ptr<TcpSocket> sock, const std::string& head, const Bytes& headPrefix,
                           std::shared_ptr<TunnelSession> session);
  void handlePlainHttp(std::shared_ptr<TcpSocket> sock, const std::string& head,
                       const Bytes& bodyPrefix, std::shared_ptr<TunnelSession> session);

  ProxyOptions opts_;
  std::shared_ptr<TcpSocket> listener_;
  std::atomic<bool> running_{false};
  std::atomic<bool> stopping_{false};
  std::vector<std::thread> workers_;
};

/** 解析 Host 头 → host:port */
bool parseHostHeader(const std::string& hostHeader, uint16_t defaultPort, std::string& host,
                     uint16_t& port);
/** 解析绝对形式 request-target（http://host:port/path） */
bool parseAbsoluteTarget(const std::string& target, std::string& host, uint16_t& port);

}  // namespace hwp
