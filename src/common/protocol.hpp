#pragma once
/**
 * WSS 隧道帧协议 —— 与 Node 版 server/protocol.js 完全等价。
 *
 * 控制消息：WebSocket 文本帧 + JSON
 *   { "type": "connect",    "sessionId": 1, "host": "example.com", "port": 443, "mode": "tcp-over-wss" }
 *   { "type": "connected",  "sessionId": 1 }
 *   { "type": "half-close", "sessionId": 1 }
 *   { "type": "close",      "sessionId": 1 }
 *   { "type": "error",      "sessionId": 1, "message": "..." }
 *
 * 数据消息：WebSocket 二进制帧
 *   [0..3] 4 字节大端 uint32 sessionId
 *   [4..]  原始 TCP 字节，零 Base64 开销
 */
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

#include "util.hpp"

namespace hwp {

inline constexpr const char* kModeTcpOverWss = "tcp-over-wss";
inline constexpr size_t kDataHeaderLen = 4;
inline constexpr uint32_t kSessionIdMin = 1;
inline constexpr uint32_t kSessionIdMax = 0xffffffffu;

/** 编码数据帧（4 字节大端 sessionId + 载荷） */
Bytes encodeDataFrame(uint32_t sessionId, const uint8_t* payload, size_t len);
inline Bytes encodeDataFrame(uint32_t sessionId, const Bytes& payload) {
  return encodeDataFrame(sessionId, payload.data(), payload.size());
}

/** 解析数据帧。帧过短返回 nullopt */
struct DataFrame {
  uint32_t sessionId = 0;
  const uint8_t* payload = nullptr;
  size_t len = 0;
};
std::optional<DataFrame> decodeDataFrame(const uint8_t* buf, size_t len);

bool isValidSessionId(uint32_t v);
bool isValidPort(int v);

/** 极简 JSON 对象解析（仅支持本协议用到的扁平结构：字符串 / 数字） */
struct JsonValue {
  bool isString = false;
  bool isNumber = false;
  std::string str;
  double num = 0;
};
using JsonObject = std::unordered_map<std::string, JsonValue>;

/** 解析控制消息文本帧；非对象 / 缺 type 返回 nullopt */
std::optional<JsonObject> parseControlMessage(const std::string& text);

/** 构造控制消息 */
std::string controlMessage(const std::string& type,
                           const std::unordered_map<std::string, std::string>& fields = {});

/** JSON 字符串转义 */
std::string jsonEscape(const std::string& s);

}  // namespace hwp
