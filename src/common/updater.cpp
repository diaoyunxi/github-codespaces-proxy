#include "updater.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "tcpsocket.hpp"
#include "stream.hpp"
#include "util.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>
#include <process.h>
#else
#include <unistd.h>
#include <climits>
#include <cerrno>
#include <sys/stat.h>
#endif

namespace hwp {
namespace {

// ----------------------------------------------------------------------------
// 极简 JSON 解析（只覆盖 Release 接口用到的 object/array/string/number/bool/null）
// ----------------------------------------------------------------------------
struct JVal {
  enum T { NUL, STR, NUM, BOOL, ARR, OBJ } t = NUL;
  std::string s;
  double d = 0;
  bool b = false;
  std::vector<JVal> a;
  std::map<std::string, JVal> o;
  const JVal* find(const std::string& k) const {
    auto it = o.find(k);
    return it == o.end() ? nullptr : &it->second;
  }
};

struct JsonParser {
  const std::string& src;
  size_t i = 0;
  explicit JsonParser(const std::string& s) : src(s) {}
  void ws() {
    while (i < src.size() && std::isspace(static_cast<unsigned char>(src[i]))) i++;
  }
  bool parse(JVal& v) {
    ws();
    if (i >= src.size()) return false;
    char c = src[i];
    if (c == '{') return parseObj(v);
    if (c == '[') return parseArr(v);
    if (c == '"') return parseStr(v);
    if (c == 't' || c == 'f') return parseBool(v);
    if (c == 'n') { i += 4; v.t = JVal::NUL; return true; }
    if (c == '-' || (c >= '0' && c <= '9')) return parseNum(v);
    return false;
  }
  bool parseObj(JVal& v) {
    v.t = JVal::OBJ;
    i++;  // {
    ws();
    if (i < src.size() && src[i] == '}') { i++; return true; }
    for (;;) {
      ws();
      if (i >= src.size() || src[i] != '"') return false;
      JVal key;
      if (!parseStr(key)) return false;
      ws();
      if (i >= src.size() || src[i] != ':') return false;
      i++;
      JVal val;
      if (!parse(val)) return false;
      v.o[key.s] = std::move(val);
      ws();
      if (i >= src.size()) return false;
      if (src[i] == ',') { i++; continue; }
      if (src[i] == '}') { i++; return true; }
      return false;
    }
  }
  bool parseArr(JVal& v) {
    v.t = JVal::ARR;
    i++;
    ws();
    if (i < src.size() && src[i] == ']') { i++; return true; }
    for (;;) {
      JVal val;
      if (!parse(val)) return false;
      v.a.push_back(std::move(val));
      ws();
      if (i >= src.size()) return false;
      if (src[i] == ',') { i++; continue; }
      if (src[i] == ']') { i++; return true; }
      return false;
    }
  }
  bool parseStr(JVal& v) {
    v.t = JVal::STR;
    i++;  // "
    std::string out;
    while (i < src.size()) {
      char c = src[i++];
      if (c == '"') { v.s = out; return true; }
      if (c == '\\') {
        if (i >= src.size()) return false;
        char e = src[i++];
        switch (e) {
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          case 'n': out += '\n'; break;
          case 't': out += '\t'; break;
          case 'r': out += '\r'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'u': {
            if (i + 4 > src.size()) return false;
            int cp = 0;
            for (int k = 0; k < 4; k++) {
              char h = src[i++];
              cp <<= 4;
              if (h >= '0' && h <= '9') cp |= h - '0';
              else if (h >= 'a' && h <= 'f') cp |= h - 'a' + 10;
              else if (h >= 'A' && h <= 'F') cp |= h - 'A' + 10;
              else return false;
            }
            if (cp < 0x80) out += static_cast<char>(cp);
            else if (cp < 0x800) {
              out += static_cast<char>(0xC0 | (cp >> 6));
              out += static_cast<char>(0x80 | (cp & 0x3F));
            } else {
              out += static_cast<char>(0xE0 | (cp >> 12));
              out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
              out += static_cast<char>(0x80 | (cp & 0x3F));
            }
            break;
          }
          default: out += e; break;
        }
      } else {
        out += c;
      }
    }
    return false;
  }
  bool parseNum(JVal& v) {
    v.t = JVal::NUM;
    size_t start = i;
    if (i < src.size() && src[i] == '-') i++;
    while (i < src.size() &&
           ((src[i] >= '0' && src[i] <= '9') || src[i] == '.' || src[i] == 'e' ||
            src[i] == 'E' || src[i] == '+' || src[i] == '-'))
      i++;
    if (i == start) return false;
    v.s = src.substr(start, i - start);
    v.d = std::strtod(v.s.c_str(), nullptr);
    return true;
  }
  bool parseBool(JVal& v) {
    if (src.compare(i, 4, "true") == 0) { i += 4; v.t = JVal::BOOL; v.b = true; return true; }
    if (src.compare(i, 5, "false") == 0) { i += 5; v.t = JVal::BOOL; v.b = false; return true; }
    return false;
  }
};

bool jsonParse(const std::string& s, JVal& out, std::string* err) {
  JsonParser p(s);
  if (!p.parse(out)) {
    if (err) *err = "invalid json";
    return false;
  }
  return true;
}

// ----------------------------------------------------------------------------
// 版本比较：去掉前导 v，按 . 分段逐段比较；返回 -1/0/1
// ----------------------------------------------------------------------------
int compareVersion(const std::string& a, const std::string& b) {
  auto norm = [](const std::string& s) -> std::string {
    if (!s.empty() && (s[0] == 'v' || s[0] == 'V')) return s.substr(1);
    return s;
  };
  auto split = [](const std::string& s) -> std::vector<int> {
    std::vector<int> v;
    std::stringstream ss(s);
    std::string tok;
    while (std::getline(ss, tok, '.')) {
      std::string num;
      for (char c : tok)
        if (std::isdigit(static_cast<unsigned char>(c))) num += c;
      v.push_back(num.empty() ? 0 : std::stoi(num));
    }
    while (v.size() < 3) v.push_back(0);
    return v;
  };
  std::vector<int> va = split(norm(a)), vb = split(norm(b));
  for (size_t k = 0; k < 3; k++) {
    if (va[k] != vb[k]) return va[k] < vb[k] ? -1 : 1;
  }
  return 0;
}

// 按当前平台挑选资产下载地址
std::string selectAsset(const JVal& release, std::string* err) {
#ifdef _WIN32
  const std::string want = "win-amd64";
  const std::string ext = ".zip";
#else
  const std::string want = "amd64";
  const std::string ext = ".deb";
#endif
  const JVal* assets = release.find("assets");
  if (!assets || assets->t != JVal::ARR) {
    if (err) *err = "release has no assets";
    return "";
  }
  for (const JVal& a : assets->a) {
    const JVal* name = a.find("name");
    const JVal* url = a.find("browser_download_url");
    if (!name || !url) continue;
    const std::string n = name->s, u = url->s;
    if (n.find(want) != std::string::npos && n.size() >= ext.size() &&
        n.compare(n.size() - ext.size(), ext.size(), ext) == 0) {
      return u;
    }
  }
  if (err) *err = "no matching asset for this platform";
  return "";
}

// ----------------------------------------------------------------------------
// HTTPS GET（带重定向跟随），返回响应体（二进制安全）
// ----------------------------------------------------------------------------
#ifdef _WIN32
std::wstring toWide(const std::string& s) {
  int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
  std::wstring w(n, 0);
  if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
  return w;
}
std::string toUtf8(const std::wstring& w) {
  int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
  std::string s(n, 0);
  if (n > 0)
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
  return s;
}

struct WinUrl {
  std::wstring host;
  int port = 443;
  std::wstring path;
};

WinUrl splitUrl(const std::string& url) {
  WinUrl u;
  size_t p = url.find("://");
  std::string rest = (p == std::string::npos) ? url : url.substr(p + 3);
  size_t slash = rest.find('/');
  std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
  u.path = (slash == std::string::npos) ? L"/" : toWide(rest.substr(slash));
  size_t colon = hostport.rfind(':');
  if (colon != std::string::npos && colon > 0) {
    u.host = toWide(hostport.substr(0, colon));
    try { u.port = std::stoi(hostport.substr(colon + 1)); } catch (...) {}
  } else {
    u.host = toWide(hostport);
  }
  return u;
}

std::string winHttpsGet(const std::string& url, std::string* err) {
  HINTERNET hSession = WinHttpOpen(L"hwp-updater/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSession) {
    if (err) *err = "WinHttpOpen failed";
    return "";
  }
  // 限制超时，避免离线时长时间阻塞
  WinHttpSetTimeouts(hSession, 8000, 8000, 10000, 15000);

  std::string body;
  std::string curUrl = url;
  int attempt = 0;
  while (attempt++ < 6) {
    WinUrl u = splitUrl(curUrl);
    HINTERNET hConnect = WinHttpConnect(hSession, u.host.c_str(), (INTERNET_PORT)u.port, 0);
    if (!hConnect) {
      if (err) *err = "WinHttpConnect failed";
      WinHttpCloseHandle(hSession);
      return "";
    }
    HINTERNET hReq = WinHttpOpenRequest(hConnect, L"GET", u.path.c_str(), NULL,
                                        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        WINHTTP_FLAG_SECURE);
    if (!hReq) {
      WinHttpCloseHandle(hConnect);
      if (err) *err = "WinHttpOpenRequest failed";
      WinHttpCloseHandle(hSession);
      return "";
    }
    std::wstring headers = L"User-Agent: hwp-updater/1.0\r\nAccept: */*\r\n";
    if (!WinHttpSendRequest(hReq, headers.c_str(), (DWORD)headers.size(), NULL, 0, 0, 0)) {
      WinHttpCloseHandle(hReq);
      WinHttpCloseHandle(hConnect);
      if (err) *err = "WinHttpSendRequest failed";
      WinHttpCloseHandle(hSession);
      return "";
    }
    if (!WinHttpReceiveResponse(hReq, NULL)) {
      WinHttpCloseHandle(hReq);
      WinHttpCloseHandle(hConnect);
      if (err) *err = "WinHttpReceiveResponse failed";
      WinHttpCloseHandle(hSession);
      return "";
    }
    DWORD status = 0, sz = sizeof(status);
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL,
                        &status, &sz, NULL);
    if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
      DWORD len = 0;
      WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION, NULL, NULL, &len, NULL);
      if (len) {
        std::wstring loc(len / sizeof(wchar_t), 0);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION, NULL, (LPVOID)loc.data(), &len, NULL);
        if (!loc.empty() && loc.back() == 0) loc.pop_back();  // 去掉末尾 NUL
        std::string locUtf8 = toUtf8(loc);
        if (locUtf8.find("://") == std::string::npos) {
          WinUrl base = splitUrl(curUrl);
          std::string nb = "https://" + toUtf8(base.host);
          if (base.port != 443) nb += ":" + std::to_string(base.port);
          if (!locUtf8.empty() && locUtf8[0] == '/') nb += locUtf8;
          else nb += "/" + locUtf8;
          curUrl = nb;
        } else {
          curUrl = locUtf8;
        }
        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConnect);
        continue;
      }
      WinHttpCloseHandle(hReq);
      WinHttpCloseHandle(hConnect);
      if (err) *err = "redirect without location";
      WinHttpCloseHandle(hSession);
      return "";
    }
    DWORD available = 0, read = 0;
    for (;;) {
      if (!WinHttpQueryDataAvailable(hReq, &available)) break;
      if (available == 0) break;
      std::vector<char> buf(available);
      if (!WinHttpReadData(hReq, buf.data(), available, &read)) break;
      if (read == 0) break;
      body.append(buf.data(), read);
    }
    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConnect);
    break;
  }
  WinHttpCloseHandle(hSession);
  return body;
}

#else  // !_WIN32 —— Linux / macOS：基于已封装的 TcpSocket + TlsStream

struct HttpResp {
  int status = 0;
  std::string location;
  std::string body;
};

HttpResp posixHttpsRequest(const std::string& h, const std::string& pt, int prt,
                           const std::string& caFile, std::string* err) {
  HttpResp r;
  auto sock = TcpSocket::connectTo(h, static_cast<uint16_t>(prt), 8000);
  if (!sock || !sock->valid()) {
    if (err) *err = "connect failed: " + h;
    return r;
  }
  std::string lerr;
  auto tls = TlsStream::clientHandshake(sock, h, true, caFile, &lerr);
  if (!tls) {
    if (err) *err = "tls failed: " + lerr;
    return r;
  }
  std::string req = "GET " + pt + " HTTP/1.1\r\nHost: " + h +
                    "\r\nUser-Agent: hwp-updater/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
  if (!tls->writeAll(reinterpret_cast<const uint8_t*>(req.data()), req.size())) {
    if (err) *err = "write failed";
    return r;
  }
  std::string header;
  if (!tls->readUntil("\r\n\r\n", header, 64 * 1024, 15000)) {
    if (err) *err = "read header failed";
    return r;
  }
  size_t sp = header.find(' ');
  if (sp != std::string::npos) {
    try { r.status = std::stoi(header.substr(sp + 1)); } catch (...) {}
  }
  std::stringstream hs(header);
  std::string line;
  bool first = true;
  while (std::getline(hs, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (first) { first = false; continue; }
    size_t c = line.find(':');
    if (c != std::string::npos) {
      std::string k = toLower(trim(line.substr(0, c)));
      std::string v = trim(line.substr(c + 1));
      if (k == "location") r.location = v;
    }
  }
  uint8_t buf[8192];
  for (;;) {
    ssize_t n = tls->read(buf, sizeof(buf), 15000);
    if (n <= 0) break;
    r.body.append(reinterpret_cast<char*>(buf), static_cast<size_t>(n));
  }
  return r;
}

std::string posixHttpsGet(const std::string& url, const std::string& caFile, std::string* err) {
  std::string curUrl = url;
  int redirects = 0;
  for (;;) {
    size_t cp = curUrl.find("://");
    if (cp == std::string::npos) { if (err) *err = "bad url"; return ""; }
    std::string crest = curUrl.substr(cp + 3);
    size_t cslash = crest.find('/');
    std::string chostport = cslash == std::string::npos ? crest : crest.substr(0, cslash);
    std::string cpath = cslash == std::string::npos ? "/" : crest.substr(cslash);
    int cport = 443;
    size_t ccolon = chostport.rfind(':');
    std::string chost;
    if (ccolon != std::string::npos && ccolon > 0) {
      chost = chostport.substr(0, ccolon);
      try { cport = std::stoi(chostport.substr(ccolon + 1)); } catch (...) {}
    } else {
      chost = chostport;
    }

    HttpResp r = posixHttpsRequest(chost, cpath, cport, caFile, err);
    if (r.status == 0) return "";  // 错误已设置
    if (r.status == 301 || r.status == 302 || r.status == 303 || r.status == 307 ||
        r.status == 308) {
      if (redirects++ >= 5) { if (err) *err = "too many redirects"; return ""; }
      if (r.location.empty()) { if (err) *err = "redirect without location"; return ""; }
      if (r.location.find("://") == std::string::npos) {
        curUrl = "https://" + chost;
        if (cport != 443) curUrl += ":" + std::to_string(cport);
        if (!r.location.empty() && r.location[0] == '/') curUrl += r.location;
        else curUrl += "/" + r.location;
      } else {
        curUrl = r.location;
      }
      continue;
    }
    return r.body;
  }
}

#endif

std::string httpsGet(const std::string& url, const std::string& caFile, std::string* err) {
#ifdef _WIN32
  (void)caFile;
  return winHttpsGet(url, err);
#else
  return posixHttpsGet(url, caFile, err);
#endif
}

// ----------------------------------------------------------------------------
// 应用更新：下载资产 -> 解包 -> 替换 -> 重启
// ----------------------------------------------------------------------------
#ifdef _WIN32
std::string escapeSingle(const std::string& s) {
  std::string out = "'";
  for (char c : s) {
    if (c == '\'') out += "''";
    else out += c;
  }
  out += "'";
  return out;
}

// 返回 self 完整路径
std::string getSelfPath() {
  std::wstring buf(4096, 0);
  DWORD n = GetModuleFileNameW(NULL, &buf[0], (DWORD)buf.size());
  if (n == 0) return "";
  buf.resize(n);
  return toUtf8(buf);
}

bool applyUpdateWin(const std::string& assetUrl, const std::string& caFile, int argc,
                    char** argv, std::string* err) {
  std::string self = getSelfPath();
  if (self.empty()) { if (err) *err = "cannot get self path"; return false; }
  size_t sep = self.find_last_of("\\/");
  std::string dir = self.substr(0, sep);
  std::string baseName = self.substr(sep + 1);

  wchar_t tmp[MAX_PATH];
  if (!GetTempPathW(MAX_PATH, tmp)) { if (err) *err = "GetTempPath failed"; return false; }
  std::string tmpRoot = toUtf8(std::wstring(tmp));
  if (!tmpRoot.empty() && tmpRoot.back() != '\\') tmpRoot += '\\';
  std::string tmpDir = tmpRoot + "hwp_update_" + std::to_string(GetCurrentProcessId());
  CreateDirectoryA(tmpDir.c_str(), NULL);

  std::string zipPath = tmpDir + "\\asset.zip";
  std::string body = httpsGet(assetUrl, caFile, err);
  if (body.empty()) return false;
  {
    std::ofstream f(zipPath, std::ios::binary);
    if (!f.good()) { if (err) *err = "cannot write asset"; return false; }
    f.write(body.data(), (std::streamsize)body.size());
  }

  std::string extracted = tmpDir + "\\extracted";
  // 重新拼出启动参数（去掉 argv[0]，交给 Start-Process 的 -FilePath）
  std::string argsJoined;
  for (int i = 1; i < argc; i++) {
    if (i > 1) argsJoined += ", ";
    argsJoined += escapeSingle(argv[i]);
  }

  std::string ps;
  ps += "$ErrorActionPreference='SilentlyContinue'\n";
  ps += "$pidToWait=" + std::to_string(GetCurrentProcessId()) + "\n";
  ps += "$zip=" + escapeSingle(zipPath) + "\n";
  ps += "$extracted=" + escapeSingle(extracted) + "\n";
  ps += "$exeDir=" + escapeSingle(dir) + "\n";
  ps += "$exeName=" + escapeSingle(baseName) + "\n";
  ps += "$args=@(" + argsJoined + ")\n";
  ps += "while(Get-Process -Id $pidToWait -ErrorAction SilentlyContinue){Start-Sleep -Milliseconds 300}\n";
  ps += "Expand-Archive -Path $zip -DestinationPath $extracted -Force\n";
  ps += "Copy-Item -Path \"$extracted\\*\" -Destination $exeDir -Recurse -Force\n";
  ps += "Start-Process -FilePath \"$exeDir\\$exeName\" -ArgumentList $args\n";
  ps += "Remove-Item " + escapeSingle(tmpDir) + " -Recurse -Force\n";

  std::string psPath = tmpDir + "\\updater.ps1";
  {
    std::ofstream f(psPath);
    f << ps;
  }

  std::wstring cmd = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"" +
                     toWide(psPath) + L"\"";
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  std::memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  if (!CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE,
                      CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
    if (err) *err = "failed to launch updater script";
    return false;
  }
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  logLine("update", "下载到新版本，正在重启以应用更新 ...");
  // 退出当前进程，让更新脚本等待本进程结束后替换并重启
  std::exit(0);
  return true;  // 不会到达
}

#else
bool applyUpdateLinux(const std::string& assetUrl, const std::string& caFile, int argc,
                      char** argv, std::string* err) {
  std::string self = argv[0];
  char buf[PATH_MAX];
  ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n > 0) {
    buf[n] = 0;
    self = buf;
  }
  size_t sep = self.find_last_of('/');
  std::string dir = self.substr(0, sep);
  std::string baseName = self.substr(sep + 1);

  std::string tmpDir = "/tmp/hwp_update_" + std::to_string(getpid());
  if (mkdir(tmpDir.c_str(), 0700) != 0 && errno != EEXIST) {
    if (err) *err = "cannot create temp dir";
    return false;
  }
  std::string assetPath = tmpDir + "/asset.deb";
  std::string body = httpsGet(assetUrl, caFile, err);
  if (body.empty()) return false;
  {
    std::ofstream f(assetPath, std::ios::binary);
    if (!f.good()) { if (err) *err = "cannot write asset"; return false; }
    f.write(body.data(), (std::streamsize)body.size());
  }

  std::string cmd = "cd '" + tmpDir + "' && ar x '" + assetPath + "' 2>/dev/null; ";
  cmd += "for f in data.tar.*; do tar -xf \"$f\" 2>/dev/null; done; ";
  cmd += "find '" + tmpDir + "' -type f \\( -name '" + baseName +
         "' -o -name 'http-over-wss-server' -o -name 'hwp_core.so*' \\) -exec cp -f {} '" + dir +
         "/' \\; ";
  // SECURITY WARNING: system() with concatenated strings is vulnerable to command injection (CWE-78)
  // TODO: Replace with fork()+execvp() for production use
  if (system(cmd.c_str()) != 0) {
    if (err) *err = "extraction/install failed (需要 ar/tar)";
    return false;
  }

  logLine("update", "已安装新版本，正在重启以应用更新 ...");
  std::vector<char*> newArgv;
  for (int i = 0; i < argc; i++) newArgv.push_back(argv[i]);
  newArgv.push_back(nullptr);
  execv(self.c_str(), newArgv.data());
  if (err) *err = "execv failed";
  return false;
}
#endif

}  // namespace

void maybeSelfUpdate(const std::string& currentVersion, const std::string& repo,
                     const std::string& caFile, int argc, char** argv) {
  std::string apiUrl = "https://api.github.com/repos/" + repo + "/releases/latest";
  std::string err;
  std::string json = httpsGet(apiUrl, caFile, &err);
  if (json.empty()) {
    logLine("update", "跳过检查: " + err);
    return;
  }
  JVal root;
  if (!jsonParse(json, root, &err)) {
    logLine("update", "解析失败: " + err);
    return;
  }
  const JVal* tag = root.find("tag_name");
  if (!tag || tag->t != JVal::STR) {
    logLine("update", "响应中缺少 tag_name（可能触发限流或仓库无 Release）");
    return;
  }
  std::string latest = tag->s;
  if (compareVersion(currentVersion, latest) >= 0) {
    logLine("update", "已是最新版本 (" + currentVersion + ")");
    return;
  }
  logLine("update", "发现新版本 " + latest + "（当前 " + currentVersion + "），准备更新");
  std::string assetUrl = selectAsset(root, &err);
  if (assetUrl.empty()) {
    logLine("update", "无可用资产: " + err);
    return;
  }

#ifdef _WIN32
  applyUpdateWin(assetUrl, caFile, argc, argv, &err);
#else
  applyUpdateLinux(assetUrl, caFile, argc, argv, &err);
#endif
  // 只有更新失败时才会走到这里
  logLine("update", "更新失败: " + err + "（继续使用当前版本）");
}

}  // namespace hwp
