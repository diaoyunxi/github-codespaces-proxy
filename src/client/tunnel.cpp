#include "tunnel.hpp"

#include <algorithm>
#include <condition_variable>
#include <cstring>

#include "../common/util.hpp"
#include "local_proxy.hpp"

namespace hwp {

bool parseWsUrl(const std::string& url, ParsedUrl& out) {
  std::string rest;
  if (url.rfind("wss://", 0) == 0) {
    out.tls = true;
    rest = url.substr(6);
  } else if (url.rfind("ws://", 0) == 0) {
    out.tls = false;
    rest = url.substr(5);
  } else {
    return false;
  }
  const auto slash = rest.find('/');
  std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
  out.path = slash == std::string::npos ? "/" : rest.substr(slash);
  if (out.path.empty()) out.path = "/";

  if (!authority.empty() && authority.front() == '[') {
    const auto end = authority.find(']');
    if (end == std::string::npos) return false;
    out.host = authority.substr(1, end - 1);
    const auto colon = authority.find(':', end);
    if (colon != std::string::npos)
      out.port = static_cast<uint16_t>(std::stoi(authority.substr(colon + 1)));
  } else {
    const auto colon = authority.rfind(':');
    if (colon != std::string::npos && authority.find(':') == colon) {
      out.host = authority.substr(0, colon);
      out.port = static_cast<uint16_t>(std::stoi(authority.substr(colon + 1)));
    } else {
      out.host = authority;
    }
  }
  if (out.host.empty()) return false;
  out.hostHeader = out.host + ":" + std::to_string(out.port);
  return true;
}

WssTunnel::WssTunnel(TunnelOptions opts) : opts_(std::move(opts)) {}

WssTunnel::~WssTunnel() { close(); }

void WssTunnel::connect() {
  if (stopped_.load()) return;
  if (loopThread_.joinable()) loopThread_.join();
  loopThread_ = std::thread([this] { runLoop(); });
}

void WssTunnel::close() {
  stopped_.store(true);
  {
    std::lock_guard<std::mutex> lk(wsMutex_);
    if (ws_) {
      ws_->close();
      ws_->terminate();
      ws_.reset();
    }
  }
  ready_.store(false);
  if (loopThread_.joinable()) loopThread_.join();
  std::lock_guard<std::mutex> lk(sessionsMutex_);
  for (auto& kv : sessions_) {
    if (kv.second->onClose) kv.second->onClose("tunnel shutdown");
    kv.second->state_ = TunnelSession::State::Closed;
  }
  sessions_.clear();
}

size_t WssTunnel::sessionCount() {
  std::lock_guard<std::mutex> lk(sessionsMutex_);
  return sessions_.size();
}

uint32_t WssTunnel::allocId() {
  std::lock_guard<std::mutex> lk(sessionsMutex_);
  for (int i = 0; i < opts_.maxSessions * 2; i++) {
    const uint32_t id = nextId_;
    nextId_ = (id >= 0xfffffffeu) ? 1 : id + 1;
    if (!sessions_.count(id)) return id;
  }
  return 0;
}

void WssTunnel::runLoop() {
  while (!stopped_.load()) {
    ParsedUrl url;
    if (!parseWsUrl(opts_.url, url)) {
      if (onError) onError("invalid server url: " + opts_.url);
      return;
    }
    std::shared_ptr<TcpSocket> sock = TcpSocket::connectTo(url.host, url.port, opts_.connectTimeoutMs);
    if (!sock) {
      onDisconnected("wss connect failed");
    } else {
      std::shared_ptr<TlsStream> tls;
      if (url.tls) {
        std::string err;
        tls = TlsStream::clientHandshake(sock, url.host, opts_.rejectUnauthorized, opts_.caFile, &err);
        if (!tls) {
          sock->close();
          onDisconnected("tls handshake failed: " + err);
        }
      }
      if (sock && (!url.tls || tls)) {
        auto ws = WebSocket::connectClient(sock, tls, url.hostHeader, url.path, "");
        if (!ws) {
          sock->close();
          onDisconnected("websocket handshake failed");
        } else {
          {
            std::lock_guard<std::mutex> lk(wsMutex_);
            ws_ = ws;
          }
          ready_.store(true);
          reconnectAttempts_ = 0;
          disconnected_.store(false);
          if (onReady) onReady();

          ws->onText([this](const std::string& text) {
            const auto msg = parseControlMessage(text);
            if (msg) handleControl(*msg);
          });
          ws->onBinary([this](const uint8_t* data, size_t len) {
            const auto frame = decodeDataFrame(data, len);
            if (!frame) return;
            std::shared_ptr<TunnelSession> session;
            {
              std::lock_guard<std::mutex> lk(sessionsMutex_);
              auto it = sessions_.find(frame->sessionId);
              if (it != sessions_.end()) session = it->second;
            }
            if (session && session->onData && !session->closed_.load()) {
              session->onData(frame->payload, frame->len);
            }
          });
          ws->onClose([this](const std::string& reason) { onDisconnected(reason); });
          ws->onError([this](const std::string& m) {
            if (onError) onError(m);
            onDisconnected(m);
          });

          // 心跳线程（独立线程，避免阻塞读循环）
          std::thread pingThread([this, ws] {
            int waited = 0;
            while (!stopped_.load() && ws->state() == WsState::Open) {
              std::this_thread::sleep_for(std::chrono::milliseconds(500));
              waited += 500;
              if (waited >= opts_.pingIntervalMs) {
                waited = 0;
                if (ws->state() == WsState::Open) ws->sendPing();
              }
            }
          });

          // 读循环：本线程阻塞在此，直到连接断开
          ws->runReadLoop();
          pingThread.join();
          {
            std::lock_guard<std::mutex> lk(wsMutex_);
            ws_.reset();
          }
          if (!stopped_.load()) onDisconnected("wss closed");
        }
      }
    }
    if (stopped_.load()) break;
    const int delay = std::min(opts_.reconnectDelayMs * (1 << std::min(reconnectAttempts_, 10)),
                               opts_.maxReconnectDelayMs);
    reconnectAttempts_++;
    for (int i = 0; i < delay && !stopped_.load(); i += 100)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  ready_.store(false);
}

void WssTunnel::onDisconnected(const std::string& reason) {
  if (disconnected_.exchange(true)) {
    // 幂等：一次断线只处理一遍（与 Node 版 _onDisconnected 一致）
    return;
  }
  ready_.store(false);
  std::vector<std::shared_ptr<TunnelSession>> all;
  {
    std::lock_guard<std::mutex> lk(sessionsMutex_);
    for (auto& kv : sessions_) all.push_back(kv.second);
    sessions_.clear();
  }
  for (auto& s : all) {
    if (s->onError) s->onError(reason);
    if (s->onClose) s->onClose(reason);
    s->state_ = TunnelSession::State::Closed;
    s->closed_.store(true);
  }
  if (onDown) onDown(reason);
}

void WssTunnel::handleControl(const JsonObject& msg) {
  const auto itId = msg.find("sessionId");
  if (itId == msg.end() || !itId->second.isNumber) return;
  const uint32_t id = static_cast<uint32_t>(itId->second.num);
  std::shared_ptr<TunnelSession> session;
  {
    std::lock_guard<std::mutex> lk(sessionsMutex_);
    auto it = sessions_.find(id);
    if (it != sessions_.end()) session = it->second;
  }
  if (!session) return;

  const std::string type = msg.find("type")->second.str;
  if (type == "connected") {
    if (session->state_ == TunnelSession::State::Connecting) {
      session->state_ = TunnelSession::State::Open;
      if (session->onOpen) session->onOpen();
    }
    return;
  }
  if (type == "close") {
    std::string reason = "server closed";
    if (auto it = msg.find("reason"); it != msg.end() && it->second.isString) reason = it->second.str;
    {
      std::lock_guard<std::mutex> lk(sessionsMutex_);
      sessions_.erase(id);
    }
    session->state_ = TunnelSession::State::Closed;
    session->closed_.store(true);
    if (session->onClose) session->onClose(reason);
    return;
  }
  if (type == "error") {
    std::string message = "server error";
    if (auto it = msg.find("message"); it != msg.end() && it->second.isString) message = it->second.str;
    {
      std::lock_guard<std::mutex> lk(sessionsMutex_);
      sessions_.erase(id);
    }
    session->state_ = TunnelSession::State::Closed;
    session->closed_.store(true);
    if (session->onError) session->onError(message);
    if (session->onClose) session->onClose("server error: " + message);
  }
}

std::shared_ptr<TunnelSession> WssTunnel::openSession(const std::string& host, uint16_t port) {
  if (!ready_.load()) return nullptr;
  {
    std::lock_guard<std::mutex> lk(sessionsMutex_);
    if (static_cast<int>(sessions_.size()) >= opts_.maxSessions) return nullptr;
  }
  const uint32_t id = allocId();
  if (id == 0) return nullptr;

  auto session = std::make_shared<TunnelSession>(id, host, port);
  {
    std::lock_guard<std::mutex> lk(sessionsMutex_);
    sessions_[id] = session;
  }

  std::shared_ptr<WebSocket> ws;
  {
    std::lock_guard<std::mutex> lk(wsMutex_);
    ws = ws_;
  }
  if (!ws || ws->state() != WsState::Open) {
    std::lock_guard<std::mutex> lk(sessionsMutex_);
    sessions_.erase(id);
    return nullptr;
  }
  const std::string msg = "{\"type\":\"connect\",\"sessionId\":" + std::to_string(id) +
                          ",\"host\":\"" + jsonEscape(host) + "\",\"port\":" +
                          std::to_string(port) + ",\"mode\":\"" + kModeTcpOverWss + "\"}";
  std::lock_guard<std::mutex> lk(sendMutex_);
  if (!ws->sendText(msg)) {
    std::lock_guard<std::mutex> lk2(sessionsMutex_);
    sessions_.erase(id);
    return nullptr;
  }
  return session;
}

bool WssTunnel::push(std::shared_ptr<TunnelSession> session, const uint8_t* data, size_t len) {
  if (!session || session->closed_.load() || session->uplinkClosed_.load()) return false;
  std::shared_ptr<WebSocket> ws;
  {
    std::lock_guard<std::mutex> lk(wsMutex_);
    ws = ws_;
  }
  if (!ws || ws->state() != WsState::Open) return false;
  const Bytes frame = encodeDataFrame(session->id(), data, len);
  std::lock_guard<std::mutex> lk(sendMutex_);
  if (!ws->sendBinary(frame.data(), frame.size())) {
    closeSession(session, "wss send failed", false);
    return false;
  }
  return true;
}

void WssTunnel::pushEnd(std::shared_ptr<TunnelSession> session) {
  if (!session || session->closed_.load()) return;
  if (session->uplinkClosed_.exchange(true)) return;
  std::shared_ptr<WebSocket> ws;
  {
    std::lock_guard<std::mutex> lk(wsMutex_);
    ws = ws_;
  }
  if (!ws || ws->state() != WsState::Open) return;
  std::lock_guard<std::mutex> lk(sendMutex_);
  ws->sendText("{\"type\":\"half-close\",\"sessionId\":" + std::to_string(session->id()) + "}");
}

void WssTunnel::closeSession(std::shared_ptr<TunnelSession> session, const std::string& reason,
                             bool notifyServer) {
  if (!session) return;
  if (session->closed_.exchange(true)) return;
  session->state_ = TunnelSession::State::Closed;
  {
    std::lock_guard<std::mutex> lk(sessionsMutex_);
    sessions_.erase(session->id());
  }
  if (notifyServer) {
    std::shared_ptr<WebSocket> ws;
    {
      std::lock_guard<std::mutex> lk(wsMutex_);
      ws = ws_;
    }
    if (ws && ws->state() == WsState::Open) {
      std::lock_guard<std::mutex> lk(sendMutex_);
      ws->sendText("{\"type\":\"close\",\"sessionId\":" + std::to_string(session->id()) + "}");
    }
  }
  if (session->onClose) session->onClose(reason);
}

}  // namespace hwp
