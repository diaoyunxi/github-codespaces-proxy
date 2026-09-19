/**
 * 代理服务端 —— 唯一入口 `wss://<host>/`（与 Node 版 server/index.js 等价）
 *
 * 约束（方案固定不可修改项）：
 *   - 只有根路径一个入口，其余路由一律 400
 *   - 只接受 WebSocket Upgrade，普通 HTTP 请求返回 400
 *   - 不做 WSS 入口认证
 *   - 传输模式 tcp-over-wss：建立原始 TCP，不 TLS 握手、不解析、只透传
 */
#include <atomic>
#include <csignal>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "../common/base64.hpp"
#include "../common/protocol.hpp"
#include "../common/ssrf.hpp"
#include "../common/stream.hpp"
#include "../common/tcpsocket.hpp"
#include "../common/util.hpp"
#include "../common/websocket.hpp"
#include "session_manager.hpp"

namespace hwp {
namespace {

std::atomic<bool> g_stopping{false};
std::shared_ptr<TcpSocket> g_listener;

/** 读取 PEM 文件内容（仅用于存在性校验） */
bool fileExists(const std::string& p) {
  std::ifstream f(p);
  return f.good();
}

/** 极简配置解析：只解析本协议用到的字符串 / 数字字段，支持 `//` 注释 */
std::map<std::string, std::string> parseConfig(const std::string& path) {
  std::map<std::string, std::string> out;
  std::ifstream f(path);
  if (!f.good()) return out;
  std::stringstream ss;
  ss << f.rdbuf();
  const std::string text = ss.str();

  size_t i = 0;
  auto skipWs = [&] {
    while (i < text.size()) {
      if (std::isspace(static_cast<unsigned char>(text[i]))) {
        i++;
      } else if (text[i] == '/' && i + 1 < text.size() && text[i + 1] == '/') {
        while (i < text.size() && text[i] != '\n') i++;
      } else {
        break;
      }
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
      while (i < text.size() && (std::isalnum(static_cast<unsigned char>(text[i])) || text[i] == '_'))
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
      while (i < text.size() && text[i] != ',' && text[i] != '}' && text[i] != '\n') value += text[i++];
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

/**
 * 读取配置：显式传入配置文件路径（为空时回落到环境变量 PROXY_CONFIG / 默认 config.json）。
 * 不使用 setenv，避免 Windows(MSVC) 无 setenv 导致编译失败。
 */
ServerConfig loadConfig(const std::string& file) {
  ServerConfig cfg;
  auto kv = parseConfig(file);
  if (kv.count("port")) cfg.port = static_cast<uint16_t>(toInt(kv["port"], cfg.port));
  if (kv.count("host")) cfg.host = kv["host"];
  if (kv.count("tlsCert")) cfg.tlsCert = kv["tlsCert"];
  if (kv.count("tlsKey")) cfg.tlsKey = kv["tlsKey"];
  if (kv.count("connectTimeoutMs")) cfg.connectTimeoutMs = toInt(kv["connectTimeoutMs"], cfg.connectTimeoutMs);
  if (kv.count("idleTimeoutMs")) cfg.idleTimeoutMs = toInt(kv["idleTimeoutMs"], cfg.idleTimeoutMs);
  if (kv.count("maxSessionsPerConnection"))
    cfg.maxSessionsPerConnection = toInt(kv["maxSessionsPerConnection"], cfg.maxSessionsPerConnection);
  if (kv.count("maxSessionsPerIp")) cfg.maxSessionsPerIp = toInt(kv["maxSessionsPerIp"], cfg.maxSessionsPerIp);
  if (kv.count("wsBufferedHighWaterMark"))
    cfg.wsBufferedHighWaterMark = static_cast<size_t>(toInt(kv["wsBufferedHighWaterMark"], 4194304));
  if (kv.count("wsBufferedLowWaterMark"))
    cfg.wsBufferedLowWaterMark = static_cast<size_t>(toInt(kv["wsBufferedLowWaterMark"], 1048576));

  /**
   * 测试专用连接改写钩子（等价 Node 版 config.connectOverride）：
   * 环境变量 HWP_TEST_CONNECT_MAP="公网IP=127.0.0.1" 时，把「已通过 SSRF 校验的公网 IP」
   * 替换为实际可达的地址，仅在本地自测使用，生产禁止设置。
   */
  if (const char* map = std::getenv("HWP_TEST_CONNECT_MAP")) {
    const std::string spec = map;
    const auto eq = spec.find('=');
    if (eq != std::string::npos) {
      const std::string from = spec.substr(0, eq);
      const std::string to = spec.substr(eq + 1);
      cfg.connectOverride = [from, to](const std::string& guarded, const std::string&) {
        return guarded == from ? to : guarded;
      };
      logLine("warn", "test connect override active: " + from + " -> " + to);
    }
  }

  if (const char* v = std::getenv("PROXY_PORT")) cfg.port = static_cast<uint16_t>(toInt(v, cfg.port));
  if (const char* v = std::getenv("PROXY_HOST")) cfg.host = v;
  if (const char* v = std::getenv("PROXY_TLS_CERT")) cfg.tlsCert = v;
  if (const char* v = std::getenv("PROXY_TLS_KEY")) cfg.tlsKey = v;
  return cfg;
}

/** 读取并解析 HTTP 请求头（含可能多读的 body 前缀） */
struct HttpHead {
  std::string method;
  std::string target;
  std::string version;
  std::map<std::string, std::string> headers;  // 键为小写
  std::string raw;
  Bytes bodyPrefix;
};

bool readHttpHead(std::shared_ptr<TcpSocket>& sock, HttpHead& out) {
  std::string buf;
  if (!sock->readUntil("\r\n\r\n", buf, 64 * 1024, 20000)) return false;
  const size_t headEnd = buf.find("\r\n\r\n");
  std::string head = buf.substr(0, headEnd);
  const std::string rest = buf.substr(headEnd + 4);
  out.raw = head;
  out.bodyPrefix.assign(rest.begin(), rest.end());

  std::istringstream ss(head);
  std::string line;
  if (!std::getline(ss, line)) return false;
  if (!line.empty() && line.back() == '\r') line.pop_back();
  std::istringstream ls(line);
  ls >> out.method >> out.target >> out.version;
  if (out.method.empty() || out.target.empty()) return false;
  while (std::getline(ss, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    const auto c = line.find(':');
    if (c == std::string::npos) continue;
    out.headers[toLower(trim(line.substr(0, c)))] = trim(line.substr(c + 1));
  }
  return true;
}

/** 从 sockaddr 字符串取对端 IP（去掉 IPv6 zone / 映射前缀） */
std::string peerIpOf(std::shared_ptr<TcpSocket>& sock) {
  std::string peer = sock->peerAddress();
  if (peer.empty()) return "unknown";
  return peer;
}

/** 单 IP 并发连接计数 */
std::mutex g_ipMutex;
std::map<std::string, int> g_perIpCount;

int incIp(const std::string& ip) {
  std::lock_guard<std::mutex> lk(g_ipMutex);
  return ++g_perIpCount[ip];
}
int decIp(const std::string& ip) {
  std::lock_guard<std::mutex> lk(g_ipMutex);
  auto it = g_perIpCount.find(ip);
  if (it == g_perIpCount.end()) return 0;
  if (--it->second <= 0) {
    g_perIpCount.erase(it);
    return 0;
  }
  return it->second;
}
int ipCount(const std::string& ip) {
  std::lock_guard<std::mutex> lk(g_ipMutex);
  auto it = g_perIpCount.find(ip);
  return it == g_perIpCount.end() ? 0 : it->second;
}

void respond400(std::shared_ptr<TcpSocket>& sock, const std::string& body) {
  const std::string resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\n"
                           "Content-Length: " + std::to_string(body.size()) +
                           "\r\nConnection: close\r\n\r\n" + body;
  sock->writeAll(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
}

/** 处理一条已接受的连接 */
void handleConnection(std::shared_ptr<TcpSocket> rawSock, const ServerConfig& cfg) {
  HttpHead req;
  if (!readHttpHead(rawSock, req)) {
    rawSock->close();
    return;
  }

  const std::string path = req.target.substr(0, req.target.find('?'));
  const bool isUpgrade = req.headers.count("upgrade") &&
                         iequals(req.headers.at("upgrade"), "websocket");
  if (!isUpgrade || path != "/") {
    respond400(rawSock, "400 Bad Request: this endpoint only accepts WebSocket upgrade on \"/\"\n");
    rawSock->shutdownWrite();
    rawSock->close();
    return;
  }

  // TLS（用 peek 到的一个字节无法回推，这里通过配置决定整条连接是否 TLS）
  std::shared_ptr<Stream> stream;
  std::shared_ptr<TlsStream> tls;
  if (!cfg.tlsCert.empty() && !cfg.tlsKey.empty()) {
    // TLS 连接已在 accept 后直接握手（见下方 listenLoop）
  }
  stream = makePlainStream(rawSock);

  const std::string clientIp = peerIpOf(rawSock);
  const int current = ipCount(clientIp);
  if (current >= cfg.maxSessionsPerIp) {
    respond400(rawSock, "503 per-ip session limit reached\n");
    rawSock->close();
    return;
  }
  incIp(clientIp);

  const std::string key = req.headers.count("sec-websocket-key") ? req.headers.at("sec-websocket-key") : "";
  const std::string accept = WebSocket::acceptKey(key);
  const std::string resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                           "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n";
  if (!stream->writeAll(reinterpret_cast<const uint8_t*>(resp.data()), resp.size())) {
    decIp(clientIp);
    rawSock->close();
    return;
  }

  auto ws = WebSocket::fromServerStream(rawSock, nullptr, accept);
  ws->setServerSide(true);
  ws->setStateOpen();

  auto manager = std::make_shared<SessionManager>(ws, clientIp, cfg);
  manager->start();
  logLine("conn", "+ " + clientIp + " (ip sessions=" + std::to_string(current + 1) + ")");

  ws->onText([manager, ws](const std::string& text) {
    const auto msg = parseControlMessage(text);
    if (!msg) return;
    const auto typeIt = msg->find("type");
    const std::string type = typeIt->second.str;
    if (type == "connect") {
      const auto itId = msg->find("sessionId");
      const auto itHost = msg->find("host");
      const auto itPort = msg->find("port");
      if (itId == msg->end() || !itId->second.isNumber || itHost == msg->end() ||
          !itHost->second.isString || itPort == msg->end() || !itPort->second.isNumber ||
          itHost->second.str.empty() || !isValidPort(static_cast<int>(itPort->second.num)) ||
          !isValidSessionId(static_cast<uint32_t>(itId->second.num))) {
        manager->handleConnect(*msg);  // 内部会回 invalid connect message
      } else {
        manager->handleConnect(*msg);
      }
      return;
    }
    if (type == "half-close") {
      manager->handleHalfClose(*msg);
      return;
    }
    if (type == "close") {
      manager->handleClose(*msg);
      return;
    }
    const auto itId = msg->find("sessionId");
    const uint32_t sid = (itId != msg->end() && itId->second.isNumber)
                             ? static_cast<uint32_t>(itId->second.num)
                             : 0;
    ws->sendText("{\"type\":\"error\",\"sessionId\":" + std::to_string(sid) + ",\"message\":\"" +
                 jsonEscape("unknown type: " + type) + "\"}");
  });
  ws->onBinary([manager](const uint8_t* data, size_t len) { manager->handleData(data, len); });
  ws->onClose([manager, clientIp](const std::string&) {
    const size_t n = manager->sessionCount();
    manager->stop();
    decIp(clientIp);
    logLine("conn", "- " + clientIp + " (released " + std::to_string(n) + " sessions)");
  });
  ws->onError([clientIp](const std::string& m) {
    logLine("conn", "error " + clientIp + ": " + m);
  });

  ws->runReadLoop();
  manager->stop();
}
}  // namespace
}  // namespace hwp

using namespace hwp;

static void onSignal(int) { g_stopping.store(true); }

int main(int argc, char** argv) {
  socketInitGlobal();
  const char* envFile = std::getenv("PROXY_CONFIG");
  std::string configFile = envFile ? envFile : "config.json";
  ServerConfig cfg = loadConfig(configFile);
  for (int i = 1; i < argc; i++) {
    const std::string a = argv[i];
    if (a == "--port" && i + 1 < argc) cfg.port = static_cast<uint16_t>(std::stoi(argv[++i]));
    else if (a == "--host" && i + 1 < argc) cfg.host = argv[++i];
    else if (a == "--tls-cert" && i + 1 < argc) cfg.tlsCert = argv[++i];
    else if (a == "--tls-key" && i + 1 < argc) cfg.tlsKey = argv[++i];
    else if (a == "--config" && i + 1 < argc) {
      // 直接以命令行指定的文件重新加载（跨平台，无需 setenv）
      configFile = argv[i + 1];
      cfg = loadConfig(configFile);
      i++;
    } else if (a == "--help" || a == "-h") {
      std::fprintf(stdout,
                   "usage: http-over-wss-server [--host H] [--port P] [--tls-cert FILE] "
                   "[--tls-key FILE] [--config FILE]\n");
      return 0;
    }
  }

  const bool useTls = !cfg.tlsCert.empty() && !cfg.tlsKey.empty();
  if (useTls) {
    if (!fileExists(cfg.tlsCert) || !fileExists(cfg.tlsKey)) {
      logLine("fatal", "TLS cert/key not found: " + cfg.tlsCert + " / " + cfg.tlsKey);
      return 1;
    }
  } else {
    logLine("warn", "TLS 未配置，降级为明文 HTTP/WS（仅供内网调试，禁止公网使用）");
  }

  std::string err;
  auto listener = TcpSocket::listenOn(cfg.host, cfg.port, &err);
  if (!listener) {
    logLine("fatal", "listen failed on " + cfg.host + ":" + std::to_string(cfg.port) + ": " + err);
    return 1;
  }
  g_listener = listener;

  std::signal(SIGINT, onSignal);
  std::signal(SIGTERM, onSignal);

  logLine("listen", std::string(useTls ? "wss" : "ws") + "://" + cfg.host + ":" +
                        std::to_string(cfg.port) + "/");

  std::vector<std::shared_ptr<TcpSocket>> accepted;
  std::mutex accMutex;

  while (!g_stopping.load()) {
    auto conn = listener->acceptConn(500);
    if (!conn) continue;

    if (g_stopping.load()) {
      conn->close();
      break;
    }

    std::shared_ptr<TcpSocket> sock = conn;
    std::shared_ptr<TlsStream> tls;
    if (useTls) {
      std::string terr;
      tls = TlsStream::serverHandshake(sock, cfg.tlsCert, cfg.tlsKey, &terr);
      if (!tls) {
        logLine("warn", "TLS handshake failed: " + terr);
        sock->close();
        continue;
      }
    }

    std::thread([sock, tls, cfg] {
      if (tls) {
        // TLS 场景：走 WebSocket over TLS
        HttpHead req;
        std::string buf;
        // 通过 TLS 流读取 HTTP 头：直接用底层 socket 读会有缓冲问题，
        // 因此这里改用流接口逐字节读取。
        std::string acc;
        uint8_t c;
        bool ok = false;
        while (acc.size() < 64 * 1024) {
          const ssize_t n = tls->read(&c, 1, 20000);
          if (n <= 0) break;
          acc += static_cast<char>(c);
          if (acc.size() >= 4 && acc.compare(acc.size() - 4, 4, "\r\n\r\n") == 0) {
            ok = true;
            break;
          }
        }
        if (!ok) {
          tls->close();
          return;
        }
        req.raw = acc.substr(0, acc.size() - 4);
        std::istringstream ss(req.raw);
        std::string line;
        std::getline(ss, line);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::istringstream ls(line);
        ls >> req.method >> req.target >> req.version;
        while (std::getline(ss, line)) {
          if (!line.empty() && line.back() == '\r') line.pop_back();
          const auto cc = line.find(':');
          if (cc == std::string::npos) continue;
          req.headers[toLower(trim(line.substr(0, cc)))] = trim(line.substr(cc + 1));
        }

        const std::string path = req.target.substr(0, req.target.find('?'));
        const bool isUpgrade =
            req.headers.count("upgrade") && iequals(req.headers.at("upgrade"), "websocket");
        if (!isUpgrade || path != "/") {
          const std::string body = "400 Bad Request\n";
          const std::string resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: " +
                                   std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
          tls->writeAll(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
          tls->close();
          return;
        }
        const std::string clientIp = tls->peerAddress();
        const int current = ipCount(clientIp);
        if (current >= cfg.maxSessionsPerIp) {
          tls->close();
          return;
        }
        incIp(clientIp);
        const std::string key =
            req.headers.count("sec-websocket-key") ? req.headers.at("sec-websocket-key") : "";
        const std::string accept = WebSocket::acceptKey(key);
        const std::string resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                                 "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n";
        if (!tls->writeAll(reinterpret_cast<const uint8_t*>(resp.data()), resp.size())) {
          decIp(clientIp);
          tls->close();
          return;
        }
        auto ws = WebSocket::fromServerStream(sock, tls, accept);
        ws->setServerSide(true);
        ws->setStateOpen();
        auto manager = std::make_shared<SessionManager>(ws, clientIp, cfg);
        manager->start();
        logLine("conn", "+ " + clientIp + " (ip sessions=" + std::to_string(current + 1) + ")");
        ws->onText([manager](const std::string& text) {
          const auto msg = parseControlMessage(text);
          if (!msg) return;
          const std::string type = msg->find("type")->second.str;
          if (type == "connect") manager->handleConnect(*msg);
          else if (type == "half-close") manager->handleHalfClose(*msg);
          else if (type == "close") manager->handleClose(*msg);
        });
        ws->onBinary([manager](const uint8_t* d, size_t l) { manager->handleData(d, l); });
        ws->onClose([manager, clientIp](const std::string&) {
          const size_t n = manager->sessionCount();
          manager->stop();
          decIp(clientIp);
          logLine("conn", "- " + clientIp + " (released " + std::to_string(n) + " sessions)");
        });
        ws->onError([clientIp](const std::string& m) { logLine("conn", "error " + clientIp + ": " + m); });
        ws->runReadLoop();
        manager->stop();
        return;
      }
      handleConnection(sock, cfg);
    }).detach();
  }

  if (g_listener) g_listener->close();
  logLine("exit", "bye");
  return 0;
}
