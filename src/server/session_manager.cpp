#include "session_manager.hpp"

#include <algorithm>
#include <cstring>
#include <set>

#include "../common/tcpsocket.hpp"
#include "../common/util.hpp"

namespace hwp {
namespace {

std::vector<DnsRecord> lookupAll(const std::string& host) {
  std::vector<DnsRecord> out;
  for (const auto& a : resolveAll(host)) out.push_back({a.address, a.family});
  return out;
}

}  // namespace

SessionManager::SessionManager(std::shared_ptr<WebSocket> ws, std::string clientIp,
                               const ServerConfig& cfg)
    : ws_(std::move(ws)), clientIp_(std::move(clientIp)), cfg_(cfg) {}

SessionManager::~SessionManager() { stop(); }

void SessionManager::start() {
  // 空闲巡检线程
  workers_.emplace_back([this] {
    while (!stopped_.load()) {
      std::unique_lock<std::mutex> lk(mutex_);
      cv_.wait_for(lk, std::chrono::seconds(5), [this] { return stopped_.load(); });
      if (stopped_.load()) break;
      lk.unlock();
      sweepIdle();
    }
  });
}

void SessionManager::stop() {
  if (stopped_.exchange(true)) return;
  cv_.notify_all();
  destroyAll("manager stopped");
  for (auto& t : workers_) {
    if (t.joinable()) t.join();
  }
  workers_.clear();
}

size_t SessionManager::sessionCount() {
  std::lock_guard<std::mutex> lk(mutex_);
  return sessions_.size();
}

void SessionManager::sendJson(const std::string& json) {
  if (ws_ && ws_->state() == WsState::Open) ws_->sendText(json);
}

void SessionManager::sendError(uint32_t sessionId, const std::string& message) {
  std::unordered_map<std::string, std::string> fields;
  if (sessionId != 0) fields["sessionId"] = std::to_string(sessionId);
  fields["message"] = message;
  // sessionId 需要是数字而非字符串：手工拼接
  std::string out = "{\"type\":\"error\",\"sessionId\":" + std::to_string(sessionId) +
                    ",\"message\":\"" + jsonEscape(message) + "\"}";
  sendJson(out);
}

void SessionManager::handleConnect(const JsonObject& msg) {
  const auto itId = msg.find("sessionId");
  const auto itHost = msg.find("host");
  const auto itPort = msg.find("port");
  if (itId == msg.end() || !itId->second.isNumber || itHost == msg.end() ||
      !itHost->second.isString || itPort == msg.end() || !itPort->second.isNumber) {
    sendJson("{\"type\":\"error\",\"sessionId\":0,\"message\":\"invalid connect message\"}");
    return;
  }
  const uint32_t sessionId = static_cast<uint32_t>(itId->second.num);
  const std::string host = itHost->second.str;
  const uint16_t port = static_cast<uint16_t>(itPort->second.num);

  if (closed_.load()) return;

  {
    std::lock_guard<std::mutex> lk(mutex_);
    if (sessions_.count(sessionId)) {
      sendError(sessionId, "duplicate sessionId");
      return;
    }
    if (static_cast<int>(sessions_.size()) >= cfg_.maxSessionsPerConnection) {
      sendError(sessionId, "per-connection session limit reached");
      return;
    }
  }

  std::string mode = kModeTcpOverWss;
  if (auto it = msg.find("mode"); it != msg.end() && it->second.isString) mode = it->second.str;
  if (mode != kModeTcpOverWss) {
    sendError(sessionId, "unsupported mode: " + mode);
    return;
  }

  auto session = std::make_shared<Session>(sessionId, host, port, mode);
  {
    std::lock_guard<std::mutex> lk(mutex_);
    sessions_[sessionId] = session;
  }

  // SSRF 校验（与 Node 版一致：校验解析后的全部 IP）
  const GuardResult guard = guardTarget(host, lookupAll);
  if (closed_.load()) {
    std::lock_guard<std::mutex> lk(mutex_);
    sessions_.erase(sessionId);
    return;
  }
  if (!guard.ok) {
    sendError(sessionId, guard.reason);
    std::lock_guard<std::mutex> lk(mutex_);
    sessions_.erase(sessionId);
    return;
  }

  // 关键：连接使用「校验通过的 IP」，避免 DNS rebinding / TOCTOU
  std::string connectHost = guard.addresses.empty() ? host : guard.addresses[0];
  if (cfg_.connectOverride) connectHost = cfg_.connectOverride(connectHost, host);

  auto sock = TcpSocket::connectTo(connectHost, port, cfg_.connectTimeoutMs);
  if (!sock) {
    sendError(sessionId, "target socket error: connect failed");
    closeSession(session, "connect failed", false);
    return;
  }
  sock->setNoDelay(true);
  session->socket_ = sock;
  session->lastActiveMs_ = nowMs();

  {
    std::lock_guard<std::mutex> lk(mutex_);
    if (closed_.load() || !sessions_.count(sessionId)) {
      session->socket_.reset();
      return;
    }
  }

  sendJson("{\"type\":\"connected\",\"sessionId\":" + std::to_string(sessionId) + "}");

  // 目标 → WSS 读线程
  std::thread t([this, session] { targetReadLoop(session); });
  {
    std::lock_guard<std::mutex> lk(mutex_);
    workers_.push_back(std::move(t));
    if (workers_.size() > 64) reapWorkersLocked();
  }
}

void SessionManager::targetReadLoop(std::shared_ptr<Session> session) {
  Bytes buf(64 * 1024);
  while (!stopped_.load()) {
    if (!session->socket_) break;
    const ssize_t n = session->socket_->readSome(buf.data(), buf.size(), 500);
    if (n == 0) {
      closeSession(session, "target closed", true);
      return;
    }
    if (n < 0) {
      // 超时 / 错误：检查空闲
      const int64_t idleFor = nowMs() - session->lastActiveMs_;
      if (idleFor > cfg_.idleTimeoutMs) {
        closeSession(session, "target idle timeout", true);
        return;
      }
      continue;
    }
    session->lastActiveMs_ = nowMs();
    // 下行背压
    while (!stopped_.load() && ws_ && ws_->state() == WsState::Open) {
      // 简化实现：WebSocket 写为阻塞写，缓冲即发；背压通过小分片自然形成
      break;
    }
    Bytes frame = encodeDataFrame(session->id_, buf.data(), static_cast<size_t>(n));
    if (!ws_ || ws_->state() != WsState::Open) {
      closeSession(session, "wss closed", false);
      return;
    }
    if (!ws_->sendBinary(frame.data(), frame.size())) {
      closeSession(session, "wss send failed", false);
      return;
    }
  }
}

void SessionManager::handleData(const uint8_t* data, size_t len) {
  if (closed_.load()) return;
  const auto frame = decodeDataFrame(data, len);
  if (!frame) return;
  std::shared_ptr<Session> session;
  {
    std::lock_guard<std::mutex> lk(mutex_);
    const auto it = sessions_.find(frame->sessionId);
    if (it == sessions_.end()) return;
    session = it->second;
  }
  if (!session->socket_ || session->uplinkClosed_.load()) return;
  session->lastActiveMs_ = nowMs();
  if (!session->socket_->writeAll(frame->payload, frame->len)) {
    closeSession(session, "target write failed", true);
  }
}

void SessionManager::handleHalfClose(const JsonObject& msg) {
  if (closed_.load()) return;
  const auto itId = msg.find("sessionId");
  if (itId == msg.end() || !itId->second.isNumber) return;
  std::shared_ptr<Session> session;
  {
    std::lock_guard<std::mutex> lk(mutex_);
    const auto it = sessions_.find(static_cast<uint32_t>(itId->second.num));
    if (it == sessions_.end()) return;
    session = it->second;
  }
  session->uplinkClosed_.store(true);
  session->lastActiveMs_ = nowMs();
  if (session->socket_) session->socket_->shutdownWrite();
}

void SessionManager::handleClose(const JsonObject& msg) {
  const auto itId = msg.find("sessionId");
  if (itId == msg.end() || !itId->second.isNumber) return;
  std::shared_ptr<Session> session;
  {
    std::lock_guard<std::mutex> lk(mutex_);
    const auto it = sessions_.find(static_cast<uint32_t>(itId->second.num));
    if (it == sessions_.end()) return;
    session = it->second;
  }
  closeSession(session, "client closed", false);
}

void SessionManager::sweepIdle() {
  std::vector<std::shared_ptr<Session>> idle;
  const int64_t now = nowMs();
  {
    std::lock_guard<std::mutex> lk(mutex_);
    for (auto& kv : sessions_) {
      if (now - kv.second->lastActiveMs_ > cfg_.idleTimeoutMs) idle.push_back(kv.second);
    }
  }
  for (auto& s : idle) closeSession(s, "idle timeout", true);
}

void SessionManager::closeSession(std::shared_ptr<Session> session, const std::string& reason,
                                  bool notifyClient) {
  if (!session) return;
  bool removed = false;
  {
    std::lock_guard<std::mutex> lk(mutex_);
    const auto it = sessions_.find(session->id_);
    if (it != sessions_.end()) {
      sessions_.erase(it);
      removed = true;
    }
  }
  if (!removed && reason != "manager stopped") return;
  if (session->socket_) {
    session->socket_->close();
    session->socket_.reset();
  }
  if (notifyClient) {
    sendJson("{\"type\":\"close\",\"sessionId\":" + std::to_string(session->id_) +
             ",\"reason\":\"" + jsonEscape(reason) + "\"}");
  }
}

void SessionManager::reapWorkersLocked() {
  std::vector<std::thread> keep;
  keep.reserve(workers_.size());
  for (auto& t : workers_) {
    if (finishedWorkers_.count(t.get_id())) {
      if (t.joinable()) t.join();
    } else {
      keep.push_back(std::move(t));
    }
  }
  workers_ = std::move(keep);
}

void SessionManager::reapWorkers(bool) {}

void SessionManager::destroyAll(const std::string& reason) {
  closed_.store(true);
  std::vector<std::shared_ptr<Session>> all;
  {
    std::lock_guard<std::mutex> lk(mutex_);
    for (auto& kv : sessions_) all.push_back(kv.second);
    sessions_.clear();
  }
  for (auto& s : all) {
    if (s->socket_) {
      s->socket_->close();
      s->socket_.reset();
    }
    sendJson("{\"type\":\"close\",\"sessionId\":" + std::to_string(s->id_) +
             ",\"reason\":\"" + jsonEscape(reason) + "\"}");
  }
  // 读线程会因 socket 关闭而自然退出
  std::vector<std::thread> pending;
  {
    std::lock_guard<std::mutex> lk(mutex_);
    pending.swap(workers_);
  }
  for (auto& t : pending) {
    if (t.joinable() && t.get_id() != std::this_thread::get_id()) t.join();
  }
}

}  // namespace hwp
