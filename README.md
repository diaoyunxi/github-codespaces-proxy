# http-over-wss-proxy（C++ 重构版）

把 HTTP 代理请求通过 **WSS 长连接隧道**（`tcp-over-wss`）送到远端服务端，
由服务端建立原始 TCP 连接访问外网目标。

**全程用户态、无 TUN、无驱动、不接管全局路由**，可与 Windows 上已有闭源 VPN 共存。

> 本仓库是 [gitee.com/diaoyunxi/proxy](https://gitee.com/diaoyunxi/proxy)（Node.js 实现）的
> **C++ 重构版**：协议、行为、配置项、脚本全部对齐，改为单一可执行文件分发，
> 并通过 GitHub Actions 产出 Windows amd64 的 `exe + dll` 与 Linux amd64 的 `.deb`。

## 与原版的关系

| 维度 | Node 版 | 本 C++ 版 |
| --- | --- | --- |
| 运行依赖 | Node.js ≥ 18 + `ws` | 无（Windows 静态链接，Linux 仅依赖 libssl/libc） |
| 分发形态 | 源码 / npm | Windows `exe + hwp_core.dll`、Linux `.deb` |
| 帧协议 | 文本帧 JSON + 二进制帧 | **逐字节对齐**，可与 Node 版互操作 |
| SSRF 规则 | `server/ssrf.js` | **逐条对齐**（含 IPv4-mapped IPv6 语义） |
| 配置项 | `config.json` / 环境变量 | **同名同名同义** |
| WebSocket | `ws` 库 | 自研极简 RFC6455 实现（含分片、掩码、ping/pong） |
| TLS | Node `tls` | OpenSSL |
| 半关语义 | `end` 只传播上行 FIN | 一致（含空闲兜底超时） |

## 为什么这么设计

Windows 上已有闭源 VPN 占用系统 TUN 网卡，无法再创建虚拟网卡。本方案：

1. 只在 `127.0.0.1` 起一个**用户态** HTTP 代理，走系统内置环回路由，不碰 VPN 的 TUN。
2. 用一条 WSS 长连接多路复用所有会话，避免每连接重复 TLS 握手。
3. 用**一条静态路由**把「本机 → 代理服务器」的 WSS 流量钉在物理网卡上，绕过 VPN；其余流量照旧走 VPN。
4. 服务端只做 TCP 字节双向透传，不 TLS 握手、不解析、不解密，HTTPS 端到端由客户端与目标自行完成。

## 网络拓扑

```text
Windows 系统所有走系统代理的应用
→ 本地用户态 HTTP 代理（127.0.0.1:8080）
→ WSS 长连接隧道（wss://你的代理服务器/）
→ 远端代理服务端
→ 服务端自建原始 TCP 连接（tcp-over-wss）
→ 外网目标服务器
```

## 目录结构

```text
.
├── src/
│   ├── common/             共用底座
│   │   ├── protocol.hpp/cpp   帧协议（编码/解码、控制消息 JSON）
│   │   ├── ssrf.hpp/cpp       SSRF 拦截（IPv4/IPv6 网段表）
│   │   ├── websocket.hpp/cpp  极简 RFC6455（握手/收发/分片/ping）
│   │   ├── stream.hpp/cpp     流抽象 + OpenSSL TLS 流
│   │   ├── tcpsocket.hpp/cpp  跨平台 socket（WinSock / BSD，带超时）
│   │   ├── sha1 / base64      WebSocket 握手所需
│   │   └── util               字符串 / 时间 / 字节序 / 日志
│   ├── server/
│   │   ├── main.cpp           入口：唯一 WSS 路由 `/`，其余 400
│   │   └── session_manager.*  会话管理：建连、透传、超时、断线全量释放
│   └── client/
│       ├── main.cpp           入口：建隧道 + 起本地代理
│       ├── tunnel.*           WSS 隧道：多路复用、自动重连、心跳
│       └── local_proxy.*      本地用户态 HTTP 代理（CONNECT + 普通 HTTP）
├── tests/selftest.cpp       单元自测（协议 / SSRF / SHA1 / WebSocket 握手）
├── scripts/                 Windows PowerShell 脚本（路由豁免、系统代理）
├── server/config.example.json
├── client/config.example.json
├── docs/protocol.md         帧协议规范
└── .github/workflows/build.yml
```

## 构建

### Linux（产出 .deb）

```bash
sudo apt-get install -y build-essential cmake libssl-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure   # 单元自测
cd build && cpack -G DEB                     # 生成 .deb
sudo dpkg -i http-over-wss-proxy_1.0.0_amd64.deb
```

### Windows（产出 exe + dll）

需要 Visual Studio 2022（或 Build Tools）+ CMake + vcpkg：

```powershell
vcpkg install openssl:x64-windows-static
cmake -S . -B build -G "Ninja" `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build --parallel
# 产物：build\http-over-wss-server.exe / http-over-wss-client.exe / hwp_core.dll
```

## 快速开始

### 1. 启动服务端（Linux）

```bash
sudo cp server/config.example.json server/config.json
# 编辑 tlsCert / tlsKey 指向你的证书（Let's Encrypt 或自签）
http-over-wss-server --config server/config.json
# 或命令行覆盖： http-over-wss-server --host 0.0.0.0 --port 8443 \
#                  --tls-cert /path/fullchain.pem --tls-key /path/privkey.pem
```

日志出现 `[listen] wss://0.0.0.0:8443/` 即成功。

### 2. 启动 Windows 客户端

```powershell
copy client\config.example.json client\config.json
# 编辑 serverUrl 为 wss://你的代理服务器/
http-over-wss-client.exe --config client\config.json
# 或： http-over-wss-client.exe --server wss://proxy.example.com/ --listen-port 8080
```

日志出现 `[proxy] listening on http://127.0.0.1:8080` 即成功。

### 3. Windows 侧三件套配置

以**管理员身份**打开 PowerShell：

```powershell
# 3.1 把「本机 → 代理服务器」钉到物理网卡，绕过 VPN
.\scripts\windows-add-route.ps1 -ServerIp 203.0.113.10     # 换成你的代理服务器公网 IP

# 3.2 开启系统手动代理
.\scripts\windows-set-system-proxy.ps1                     # 默认 127.0.0.1:8080
```

不用时反向操作：

```powershell
.\scripts\windows-set-system-proxy.ps1 -Clear
.\scripts\windows-remove-route.ps1 -ServerIp 203.0.113.10
```

## 命令行参数

### 服务端 `http-over-wss-server`

| 参数 | 说明 |
| --- | --- |
| `--host H` | 监听地址，默认 `0.0.0.0` |
| `--port P` | 监听端口，默认 `8443` |
| `--tls-cert FILE` / `--tls-key FILE` | 同时给出才启用 TLS，否则降级明文 WS（仅内网调试） |
| `--config FILE` | 配置文件路径，默认 `config.json` |

环境变量：`PROXY_HOST` / `PROXY_PORT` / `PROXY_TLS_CERT` / `PROXY_TLS_KEY` / `PROXY_CONFIG`。

### 客户端 `http-over-wss-client`

| 参数 | 说明 |
| --- | --- |
| `--server URL` | 远端 WSS 地址，如 `wss://proxy.example.com/` |
| `--listen-host H` / `--listen-port P` | 本地代理监听，默认 `127.0.0.1:8080` |
| `--ca FILE` | 自定义 CA（企业自签） |
| `--insecure` | 跳过服务端证书校验（仅调试） |
| `--config FILE` | 配置文件路径，默认 `config.json` |

环境变量：`PROXY_SERVER_URL` / `PROXY_LISTEN_HOST` / `PROXY_LISTEN_PORT` / `PROXY_CLIENT_CONFIG`。

## 端到端运行流程

1. Windows 设置系统代理：`127.0.0.1:8080`
2. Windows 添加代理服务器 IP 静态路由豁免
3. 客户端本地 HTTP 代理启动监听
4. 浏览器发起 HTTPS 访问，产生 `CONNECT` 请求
5. 本地代理经已复用的 WSS 长连接发送 `connect`（含 `sessionId`、`host`、`port`、`mode`）
6. 服务端解析目标、校验解析后 IP、建立原始 TCP 连接
7. 客户端与服务端经 WSS 双向透传全部原始 TLS 报文
8. 网页加载完成，客户端发 `close`，服务端销毁对应 TCP 会话

## 帧协议速览

- **控制消息**：WebSocket 文本帧 + JSON
  - `connect`：`sessionId`、`host`、`port`、`mode`
  - `connected` / `half-close` / `close` / `error`
- **数据消息**：WebSocket 二进制帧
  - `[4 字节大端 sessionId][原始 TCP 字节]`，**不做 Base64**

详见 [docs/protocol.md](docs/protocol.md)。

## 安全策略

- **SSRF 拦截**：服务端只允许访问公网地址
  - IPv4：`0.0.0.0/8`、`10.0.0.0/8`、`100.64.0.0/10`、`127.0.0.0/8`、
    `169.254.0.0/16`（含云元数据 `169.254.169.254`）、`172.16.0.0/12`、
    `192.168.0.0/16`、`224.0.0.0/4`、`240.0.0.0/4`
  - IPv6：`::/128`、`::1/128`、`64:ff9b::/96`（NAT64）、`2002::/16`（6to4）、
    `fc00::/7`、`fe80::/10`，以及 IPv4-mapped `::ffff:x.x.x.x` 按 IPv4 语义校验
- **只校验解析后的 IP**：域名先解析，所有解析结果全部通过才建连；字面 IP 直接校验。
- **校验地址即连接地址**：建连使用已校验的 IP，避免 DNS rebinding / TOCTOU。
- 连接超时、空闲超时限制；单 WSS 连接与单 IP 会话数上限。
- WSS 入口不做认证，靠「服务器只在需要时开机」降低暴露面；服务端必须配好 TLS。

## 测试

```bash
ctest --test-dir build --output-on-failure
# 或直接运行
./build/hwp_selftest
```

覆盖：帧协议编码/解码、控制消息解析（含未知字段）、SSRF 全部网段与 IPv4-mapped 语义、
`guardTarget` 各失败路径、SHA1（RFC 3174 向量）、Base64、WebSocket `Sec-WebSocket-Accept`（RFC 6455 示例）。

端到端联调（本地回环）已验证：

- `ws://` 链路：CONNECT 隧道、明文 HTTP 绝对 URL 透传
- `wss://` 链路（真实 TLS 证书）：CONNECT 隧道内再走 TLS（TLS-in-TLS）、明文 HTTP
- SSRF 拦截私有地址、`mode` 非 `tcp-over-wss` 返回 `error`、二进制帧双向透传

## 方案固定项（不建议改动）

1. 客户端 HTTP 代理：`127.0.0.1:8080`
2. 服务端唯一入口：WSS `/`
3. 传输模式：`tcp-over-wss` 为基础，可扩展
4. Windows：必须静态路由豁免代理服务器 IP
5. 全程用户态、无 TUN、无驱动、无全局路由接管
6. `data` 帧：`[4 字节大端 sessionId][原始字节]`，不做 Base64
7. 控制帧：文本 JSON；数据帧：WebSocket 二进制
8. WSS 入口不做认证
9. SSRF 拦截非公网地址（私有 / 回环 / 链路本地 / CGNAT / 组播 / 保留），只校验解析后 IP

## License

MIT
