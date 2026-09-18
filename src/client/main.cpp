/**
 * 客户端入口 —— 与 Node 版 client/index.js 等价
 *
 * 启动流程：
 *   1. 加载配置（本地端口、远端 WSS 地址、证书校验开关等）
 *   2. 建立 WSS 长连接隧道（自动重连 + 心跳）
 *   3. 启动本地用户态 HTTP 代理，监听 127.0.0.1:8080
 *
 * 纯用户态运行：不创建虚拟网卡、不装驱动、不改动全局路由表。
 */
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

#include "../common/tcpsocket.hpp"
#include "../common/util.hpp"
#include "local_proxy.hpp"
#include "tunnel.hpp"

using namespace hwp;

namespace {

std::atomic<bool> g_stopping{false};

std::map<std::string, std::string> parseConfigFile(const std::string& path) {
  std::map<std::string, std::string> out;
  std::ifstream f(path);
  if (!f.good()) return out;
  std::stringstream ss;
  ss << f.rdbuf();
  const std::string text = ss.str();
  size_t i = 0;
  auto skipWs = [&] {
    while (i < text.size()) {
      if (std::isspace(static_cast<unsigned char>(text[i]))) i++;
      else if (text[i] == '/' && i + 1 < text.size() && text[i + 1] == '/') {
        while (i < text.size() && text[i] != '\n') i++;
      } else break;
    }
  };
  skipWs();
  if (i >= text.size() || text[i] != '{') return out;
  i++;
  while (i < text.size()) {
    skipWs();
    if (i < text.size() && text[i] == '}') break;
    if (i >= text.size()) break;
    std::string key;
    if (text[i] == '"') {
      i++;
      while (i < text.size() && text[i] != '"') key += text[i++];
      i++;
    } else {
      while (i < text.size() &&
             (std::isalnum(static_cast<unsigned char>(text[i])) || text[i] == '_'))
        key += text[i++];
    }
    skipWs();
    if (i < text.size() && text[i] == ':') i++;
    skipWs();
    std::string value;
    if (i < text.size() && text[i] == '"') {
      i++;
      while (i < text.size() && text[i] != '"') {
        if (text[i] == '\\' && i + 1 < text.size()) i++;
        value += text[i++];
      }
      i++;
    } else {
      while (i < text.size() && text[i] != ',' && text[i] != '}' && text[i] != '\n')
        value += text[i++];
    }
    if (!key.empty()) out[key] = trim(value);
    skipWs();
    if (i < text.size() && text[i] == ',') i++;
  }
  return out;
}

int toInt(const std::string& s, int def) {
  try {
    return std::stoi(s);
  } catch (...) {
    return def;
  }
}

struct ClientConfig {
  std::string listenHost = "127.0.0.1";
  uint16_t listenPort = 8080;
  std::string serverUrl = "wss://proxy.example.com/";
  bool rejectUnauthorized = true;
  int connectTimeoutMs = 10000;
  int handshakeTimeoutMs = 15000;
  int reconnectDelayMs = 500;
  int maxReconnectDelayMs = 15000;
  int pingIntervalMs = 25000;
  int maxSessions = 1024;
  std::string caFile;
  int halfCloseIdleMs = 3000;
};

ClientConfig loadConfig(const std::string& defaultPath) {
  ClientConfig cfg;
  const char* envFile = std::getenv("PROXY_CLIENT_CONFIG");
  const std::string file = envFile ? envFile : defaultPath;
  auto kv = parseConfigFile(file);
  if (kv.count("listenHost")) cfg.listenHost = kv["listenHost"];
  if (kv.count("listenPort")) cfg.listenPort = static_cast<uint16_t>(toInt(kv["listenPort"], cfg.listenPort));
  if (kv.count("serverUrl")) cfg.serverUrl = kv["serverUrl"];
  if (kv.count("rejectUnauthorized")) cfg.rejectUnauthorized = (kv["rejectUnauthorized"] != "false");
  if (kv.count("connectTimeoutMs")) cfg.connectTimeoutMs = toInt(kv["connectTimeoutMs"], cfg.connectTimeoutMs);
  if (kv.count("handshakeTimeoutMs")) cfg.handshakeTimeoutMs = toInt(kv["handshakeTimeoutMs"], cfg.handshakeTimeoutMs);
  if (kv.count("reconnectDelayMs")) cfg.reconnectDelayMs = toInt(kv["reconnectDelayMs"], cfg.reconnectDelayMs);
  if (kv.count("maxReconnectDelayMs")) cfg.maxReconnectDelayMs = toInt(kv["maxReconnectDelayMs"], cfg.maxReconnectDelayMs);
  if (kv.count("pingIntervalMs")) cfg.pingIntervalMs = toInt(kv["pingIntervalMs"], cfg.pingIntervalMs);
  if (kv.count("maxSessions")) cfg.maxSessions = toInt(kv["maxSessions"], cfg.maxSessions);
  if (kv.count("caFile")) cfg.caFile = kv["caFile"];
  if (kv.count("halfCloseIdleMs")) cfg.halfCloseIdleMs = toInt(kv["halfCloseIdleMs"], cfg.halfCloseIdleMs);

  if (const char* v = std::getenv("PROXY_SERVER_URL")) cfg.serverUrl = v;
  if (const char* v = std::getenv("PROXY_LISTEN_PORT")) cfg.listenPort = static_cast<uint16_t>(toInt(v, cfg.listenPort));
  if (const char* v = std::getenv("PROXY_LISTEN_HOST")) cfg.listenHost = v;
  return cfg;
}

void onSignal(int) { g_stopping.store(true); }

}  // namespace

int main(int argc, char** argv) {
  socketInitGlobal();
  std::string configPath = "config.json";
  ClientConfig cfg = loadConfig(configPath);
  for (int i = 1; i < argc; i++) {
    const std::string a = argv[i];
    if (a == "--server" && i + 1 < argc) cfg.serverUrl = argv[++i];
    else if (a == "--listen-port" && i + 1 < argc) cfg.listenPort = static_cast<uint16_t>(toInt(argv[++i], 8080));
    else if (a == "--listen-host" && i + 1 < argc) cfg.listenHost = argv[++i];
    else if (a == "--ca" && i + 1 < argc) cfg.caFile = argv[++i];
    else if (a == "--insecure") cfg.rejectUnauthorized = false;
    else if (a == "--config" && i + 1 < argc) cfg = loadConfig(argv[++i]);
    else if (a == "--help" || a == "-h") {
      std::fprintf(stdout,
                   "usage: http-over-wss-client [--server wss://host/] [--listen-host H] "
                   "[--listen-port P] [--ca FILE] [--insecure] [--config FILE]\n");
      return 0;
    }
  }

  TunnelOptions topts;
  topts.url = cfg.serverUrl;
  topts.connectTimeoutMs = cfg.connectTimeoutMs;
  topts.handshakeTimeoutMs = cfg.handshakeTimeoutMs;
  topts.reconnectDelayMs = cfg.reconnectDelayMs;
  topts.maxReconnectDelayMs = cfg.maxReconnectDelayMs;
  topts.pingIntervalMs = cfg.pingIntervalMs;
  topts.maxSessions = cfg.maxSessions;
  topts.rejectUnauthorized = cfg.rejectUnauthorized;
  topts.caFile = cfg.caFile;

  auto tunnel = std::make_shared<WssTunnel>(topts);
  tunnel->onReady = [&cfg] { logLine("tunnel", "connected -> " + cfg.serverUrl); };
  tunnel->onDown = [](const std::string& reason) {
    logLine("tunnel", "down: " + reason + " (auto reconnecting)");
  };
  tunnel->onError = [](const std::string& m) { logLine("tunnel", "error: " + m); };
  tunnel->connect();

  ProxyOptions popts;
  popts.tunnel = tunnel;
  popts.halfCloseIdleMs = cfg.halfCloseIdleMs;
  popts.log = [](const std::string& m) { logLine("proxy", m); };

  auto proxy = std::make_shared<LocalProxy>(popts);
  std::string err;
  if (!proxy->listen(cfg.listenHost, cfg.listenPort, &err)) {
    logLine("fatal", "客户端启动失败: listen failed: " + err);
    return 1;
  }
  logLine("proxy", "listening on http://" + cfg.listenHost + ":" + std::to_string(cfg.listenPort));
  logLine("hint", "在系统「设置 → 网络和 Internet → 代理」中开启手动代理并填入上述地址");

  std::signal(SIGINT, onSignal);
  std::signal(SIGTERM, onSignal);
  while (!g_stopping.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  logLine("exit", "shutting down ...");
  proxy->stop();
  tunnel->close();
  logLine("exit", "bye");
  return 0;
}
