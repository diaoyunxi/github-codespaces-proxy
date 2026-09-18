#include "protocol.hpp"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace hwp {

Bytes encodeDataFrame(uint32_t sessionId, const uint8_t* payload, size_t len) {
  Bytes out(kDataHeaderLen + len);
  putU32BE(out.data(), sessionId);
  if (len && payload) std::memcpy(out.data() + kDataHeaderLen, payload, len);
  return out;
}

std::optional<DataFrame> decodeDataFrame(const uint8_t* buf, size_t len) {
  if (!buf || len < kDataHeaderLen) return std::nullopt;
  DataFrame f;
  f.sessionId = getU32BE(buf);
  f.payload = buf + kDataHeaderLen;
  f.len = len - kDataHeaderLen;
  return f;
}

bool isValidSessionId(uint32_t v) { return v >= kSessionIdMin && v <= kSessionIdMax; }
bool isValidPort(int v) { return v >= 1 && v <= 65535; }

std::string jsonEscape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      default:
        if (c < 0x20) {
          char b[8];
          std::snprintf(b, sizeof(b), "\\u%04x", c);
          out += b;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out;
}

namespace {

// 简易 JSON 扫描器：解析顶层对象的键值（值为字符串或数字），
// 忽略未识别的键值形态（对象/数组/布尔/null 也安全跳过）。
class Scanner {
 public:
  explicit Scanner(const std::string& s) : s_(s) {}

  bool parseObject(JsonObject& out) {
    ws();
    if (!eat('{')) return false;
    ws();
    if (eat('}')) return true;
    while (true) {
      ws();
      std::string key;
      if (!string(&key)) return false;
      ws();
      if (!eat(':')) return false;
      ws();
      JsonValue v;
      if (peek() == '"') {
        v.isString = true;
        if (!string(&v.str)) return false;
      } else if (peek() == '-' || std::isdigit(static_cast<unsigned char>(peek()))) {
        v.isNumber = true;
        v.num = number();
      } else {
        if (!skipValue()) return false;
      }
      out[key] = v;
      ws();
      if (eat(',')) continue;
      if (eat('}')) return true;
      return false;
    }
  }

 private:
  const std::string& s_;
  size_t i_ = 0;

  char peek() const { return i_ < s_.size() ? s_[i_] : '\0'; }
  void ws() {
    while (i_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[i_]))) i_++;
  }
  bool eat(char c) {
    if (i_ < s_.size() && s_[i_] == c) {
      i_++;
      return true;
    }
    return false;
  }
  bool string(std::string* out) {
    if (!eat('"')) return false;
    std::string r;
    while (i_ < s_.size()) {
      char c = s_[i_++];
      if (c == '"') {
        *out = r;
        return true;
      }
      if (c == '\\' && i_ < s_.size()) {
        char e = s_[i_++];
        switch (e) {
          case 'n': r += '\n'; break;
          case 'r': r += '\r'; break;
          case 't': r += '\t'; break;
          case 'b': r += '\b'; break;
          case 'f': r += '\f'; break;
          case 'u': {
            if (i_ + 4 > s_.size()) return false;
            unsigned code = 0;
            for (int k = 0; k < 4; k++) {
              char h = s_[i_ + k];
              code <<= 4;
              if (h >= '0' && h <= '9') code |= static_cast<unsigned>(h - '0');
              else if (h >= 'a' && h <= 'f') code |= static_cast<unsigned>(h - 'a' + 10);
              else if (h >= 'A' && h <= 'F') code |= static_cast<unsigned>(h - 'A' + 10);
              else return false;
            }
            i_ += 4;
            // 仅处理 BMP 的 UTF-8 编码（够用；协议内主机名不会用到代理对）
            if (code < 0x80) {
              r += static_cast<char>(code);
            } else if (code < 0x800) {
              r += static_cast<char>(0xC0 | (code >> 6));
              r += static_cast<char>(0x80 | (code & 0x3F));
            } else if (code >= 0xD800 && code <= 0xDFFF) {
              // 代理对：跳过（罕见），输出替换字符
              r += '?';
            } else {
              r += static_cast<char>(0xE0 | (code >> 12));
              r += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
              r += static_cast<char>(0x80 | (code & 0x3F));
            }
            break;
          }
          default: r += e;
        }
        continue;
      }
      r += c;
    }
    return false;
  }
  double number() {
    size_t start = i_;
    if (peek() == '-') i_++;
    while (i_ < s_.size() && (std::isdigit(static_cast<unsigned char>(s_[i_])) || s_[i_] == '.' ||
                              s_[i_] == 'e' || s_[i_] == 'E' || s_[i_] == '+' || s_[i_] == '-'))
      i_++;
    return std::strtod(s_.substr(start, i_ - start).c_str(), nullptr);
  }
  /** 跳过对象 / 数组 / 字面量 */
  bool skipValue() {
    if (peek() == '"') {
      std::string dummy;
      return string(&dummy);
    }
    int depth = 0;
    while (i_ < s_.size()) {
      char c = s_[i_];
      if (c == '"') {
        std::string dummy;
        if (!string(&dummy)) return false;
        continue;
      }
      if (c == '{' || c == '[') depth++;
      if (c == '}' || c == ']') {
        depth--;
        i_++;
        if (depth <= 0) return true;
        continue;
      }
      if (depth == 0 && (c == ',' || c == '}')) return true;
      i_++;
    }
    return depth == 0;
  }
};

}  // namespace

std::optional<JsonObject> parseControlMessage(const std::string& text) {
  Scanner sc(text);
  JsonObject obj;
  if (!sc.parseObject(obj)) return std::nullopt;
  auto it = obj.find("type");
  if (it == obj.end() || !it->second.isString || it->second.str.empty()) return std::nullopt;
  return obj;
}

std::string controlMessage(const std::string& type,
                           const std::unordered_map<std::string, std::string>& fields) {
  std::string out = "{\"type\":\"" + jsonEscape(type) + "\"";
  for (const auto& kv : fields) {
    out += ",\"" + jsonEscape(kv.first) + "\":\"" + jsonEscape(kv.second) + "\"";
  }
  out += "}";
  return out;
}

}  // namespace hwp
