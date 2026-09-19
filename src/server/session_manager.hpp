#pragma once
/**
 * 一条 WSS 连接上的会话管理器 —— 与 Node 版 server/session.js 语义一致。
 *
 * 绑定关系：(WSS 连接, sessionId) ↔ 外网目标 TCP 套接字 —— 一对一。
 * 职责：建连、双向透传、空闲超时回收、断线全量释放、下行背压。
 */
#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "../common/protocol.hpp"
#include "../common/ssrf.hpp"
#include "../common/tcpsocket.hpp"
#include "../common/websocket.hpp"

namespace hwp {

struct ServerConfig {
  std::string host = "127.0.0.1"  // 默认仅本地监听，生产环境如需对外暴露请配合反向代理使用;
  uint16_t port = 8443;
  std::string tlsCert;
  std::string tlsKey;
  int connectTimeoutMs = 10000;
  int idleTimeoutMs = 120000;
  int maxSessionsPerConnection = 256;
  int maxSessionsPerIp = 512;
  size_t wsBufferedHighWaterMark = 4 * 1024 * 1024;
  size_t wsBufferedLowWaterMark = 1 * 1024 * 1024;
  /** 测试注入：覆盖实际连接地址 */
  std::function<std::string(const std::string& guardedIp, const std::string& host)> connectOverride;
};

/** 单条会话 */
class Session {
 public:
  Session(uint32_t id, std::string host, uint16_t port, std::string mode)
      : id_(id), host_(std::move(host)), port_(port), mode_(std::move(mode)) {}

  uint32_t id() const { return id_; }
  const std::string& host() const { return host_; }
  uint16_t port() const { return port_; }
  bool uplinkClosed() const { return uplinkClosed_; }

 private:
  friend class SessionManager;
  uint32_t id_;
  std::string host_;
  uint16_t port_;
  std::string mode_;
  std::atomic<bool> uplinkClosed_{false};
  std::shared_ptr<TcpSocket> socket_;
  int64_t lastActiveMs_ = nowMs();
};

/**
 * 单条 WSS 连接上的全部会话。
 * 每个会话一个读线程（把目标 socket 字节 → WSS 二进制帧）。
 */
class SessionManager {
 public:
  SessionManager(std::shared_ptr<WebSocket> ws, std::string clientIp, const ServerConfig& cfg);
  ~SessionManager();

  void start();
  void stop();

  void handleConnect(const JsonObject& msg);
  void handleData(const uint8_t* data, size_t len);
  void handleHalfClose(const JsonObject& msg);
  void handleClose(const JsonObject& msg);
  void sweepIdle();
  void destroyAll(const std::string& reason);
  /** 移除已结束的读线程句柄 */
  void reapWorkers(bool blocking = false);
  size_t sessionCount();

 private:
  void sendJson(const std::string& json);
  void sendError(uint32_t sessionId, const std::string& message);
  void targetReadLoop(std::shared_ptr<Session> session);
  void promoteSession(std::shared_ptr<Session> session);
  void closeSession(std::shared_ptr<Session> session, const std::string& reason,
                    bool notifyClient);

  std::shared_ptr<WebSocket> ws_;
  std::string clientIp_;
  ServerConfig cfg_;
  std::mutex mutex_;
  std::map<uint32_t, std::shared_ptr<Session>> sessions_;
  std::vector<std::thread> workers_;
  std::set<std::thread::id> finishedWorkers_;
  std::atomic<bool> closed_{false};
  std::atomic<bool> stopped_{false};
  std::condition_variable cv_;

  /** 清理已结束线程句柄（需已持锁） */
  void reapWorkersLocked();
};

}  // namespace hwp
