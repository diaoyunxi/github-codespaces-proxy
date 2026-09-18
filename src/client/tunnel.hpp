#pragma once
/**
 * WSS 隧道客户端 —— 与 Node 版 client/wss-tunnel.js 语义一致。
 *
 * 一条 WSS 长连接承载全部 TCP 会话：自动重连、心跳、sessionId 分配、
 * 本地 TCP 字节 ↔ WSS 二进制帧双向搬运。
 */
#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "../common/protocol.hpp"
#include "../common/stream.hpp"
#include "../common/tcpsocket.hpp"
#include "../common/websocket.hpp"

namespace hwp {

struct TunnelOptions {
  std::string url;  // wss://host:port/path
  int connectTimeoutMs = 10000;
  int handshakeTimeoutMs = 15000;
  int reconnectDelayMs = 500;
  int maxReconnectDelayMs = 15000;
  int pingIntervalMs = 25000;
  int maxSessions = 1024;
  bool rejectUnauthorized = true;
  std::string caFile;
};

/** 一个隧道会话 */
class TunnelSession {
 public:
  TunnelSession(uint32_t id, std::string host, uint16_t port)
      : id_(id), host_(std::move(host)), port_(port) {}

  uint32_t id() const { return id_; }
  const std::string& host() const { return host_; }
  uint16_t port() const { return port_; }
  bool isOpen() const { return state_ == State::Open; }
  bool isClosed() const { return state_ == State::Closed; }

  /** 会话 → 本地 TCP 方向的数据到达 */
  std::function<void(const uint8_t*, size_t)> onData;
  /** 建连成功（收到 connected） */
  std::function<void()> onOpen;
  /** 会话关闭 */
  std::function<void(const std::string& reason)> onClose;
  /** 会话错误 */
  std::function<void(const std::string& message)> onError;

 private:
  friend class WssTunnel;
  enum class State { Connecting, Open, Closed };
  uint32_t id_;
  std::string host_;
  uint16_t port_;
  State state_ = State::Connecting;
  std::atomic<bool> closed_{false};
  std::atomic<bool> uplinkClosed_{false};
  /** 本地 → 隧道 的写锁：保证分片顺序 */
};

class WssTunnel {
 public:
  explicit WssTunnel(TunnelOptions opts);
  ~WssTunnel();

  void connect();
  void close();
  bool isReady() const { return ready_.load(); }

  /** 打开一个到 host:port 的隧道会话；未就绪返回 nullptr */
  std::shared_ptr<TunnelSession> openSession(const std::string& host, uint16_t port);

  /** 上行 EOF：通知服务端向目标发 FIN，保留下行 */
  void pushEnd(std::shared_ptr<TunnelSession> session);
  /** 主动关闭会话 */
  void closeSession(std::shared_ptr<TunnelSession> session, const std::string& reason, bool notifyServer);
  /** 上行：本地字节 → 隧道 */
  bool push(std::shared_ptr<TunnelSession> session, const uint8_t* data, size_t len);

  std::function<void()> onReady;
  std::function<void(const std::string& reason)> onDown;
  std::function<void(const std::string& message)> onError;

  size_t sessionCount();
  const std::string& url() const { return opts_.url; }

 private:
  void runLoop();
  void handleControl(const JsonObject& msg);
  void onDisconnected(const std::string& reason);
  uint32_t allocId();

  TunnelOptions opts_;
  std::shared_ptr<WebSocket> ws_;
  std::mutex wsMutex_;
  std::mutex sessionsMutex_;
  std::map<uint32_t, std::shared_ptr<TunnelSession>> sessions_;
  std::atomic<bool> ready_{false};
  std::atomic<bool> stopped_{false};
  std::atomic<bool> disconnected_{false};
  uint32_t nextId_ = 1;
  int reconnectAttempts_ = 0;
  std::thread loopThread_;
  std::mutex sendMutex_;
};

/** 解析 wss://host:port/path */
struct ParsedUrl {
  bool tls = true;
  std::string host;
  uint16_t port = 443;
  std::string path = "/";
  std::string hostHeader;
};
bool parseWsUrl(const std::string& url, ParsedUrl& out);

}  // namespace hwp
