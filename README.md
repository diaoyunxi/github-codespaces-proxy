# http-over-wss-proxy

把 HTTP 代理请求通过 **WSS 长连接隧道**（`tcp-over-wss`）送到远端服务端，
由服务端建立原始 TCP 连接访问外网目标。

**全程用户态、无 TUN、无驱动、不接管全局路由**，可与 Windows 上已有闭源 VPN 共存。

## 为什么这么设计

Windows 上已有闭源 VPN 占用系统 TUN 网卡，无法再创建虚拟网卡。本方案：

1. 只在 `127.0.0.1` 起一个**用户态** HTTP 代理，走系统内置环回路由，不碰 VPN 的 TUN。
2. 用一条（或少量）WSS 长连接多路复用所有会话，避免每连接重复 TLS 握手。
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
├── server/                 服务端
│   ├── index.js            入口：唯一 WSS 路由 `/`，其余请求 400
│   ├── session.js          会话管理：(WSS 连接, sessionId) ↔ 目标 TCP 套接字
│   ├── ssrf.js             SSRF 拦截：只校验解析后的 IP
│   ├── protocol.js         帧协议（服务端/客户端共用）
│   └── config.example.json 配置样例
├── client/                 Windows 客户端
│   ├── index.js            入口：建隧道 + 起本地代理
│   ├── http-proxy.js       本地用户态 HTTP 代理（CONNECT + 普通 HTTP）
│   ├── wss-tunnel.js       WSS 隧道：会话多路复用、自动重连、心跳
│   └── config.example.json 配置样例
├── scripts/                Windows PowerShell 操作脚本
│   ├── windows-add-route.ps1         加静态路由豁免代理服务器 IP
│   ├── windows-remove-route.ps1      删该路由
│   └── windows-set-system-proxy.ps1  一键设置/清除系统代理
├── test/                   自动化测试（55 个用例）
└── docs/
    ├── protocol.md         帧协议规范
    └── deployment.md       部署与运维
```

## 快速开始

### 1. 安装依赖

```bash
npm install            # 仅依赖 ws
```

### 2. 启动服务端

```bash
cp server/config.example.json server/config.json
# 编辑 tlsCert / tlsKey 指向你的证书（Let's Encrypt 或自签）
npm run server
```

日志出现 `[listen] wss://0.0.0.0:8443/` 即成功。

### 3. 启动 Windows 客户端

```bash
cp client/config.example.json client/config.json
# 编辑 serverUrl 为 wss://你的代理服务器/
npm run client
```

日志出现 `[proxy] listening on http://127.0.0.1:8080` 即成功。

### 4. Windows 侧三件套配置

以**管理员身份**打开 PowerShell：

```powershell
# 4.1 把「本机 → 代理服务器」钉到物理网卡，绕过 VPN
.\scripts\windows-add-route.ps1 -ServerIp 203.0.113.10     # 换成你的代理服务器公网 IP

# 4.2 开启系统手动代理
.\scripts\windows-set-system-proxy.ps1                     # 默认 127.0.0.1:8080
```

之后系统「设置 → 网络和 Internet → 代理」里会显示手动代理已开启。
所有遵循系统代理的应用（浏览器、大部分常规软件）自动走代理，无需逐个配置。

不用时反向操作：

```powershell
.\scripts\windows-set-system-proxy.ps1 -Clear
.\scripts\windows-remove-route.ps1 -ServerIp 203.0.113.10
```

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
  - `connected` / `close` / `error`
- **数据消息**：WebSocket 二进制帧
  - `[4 字节大端 sessionId][原始 TCP 字节]`，**不做 Base64**

`sessionId` 由客户端生成，4 字节大端 `uint32`，服务端只回显并据此绑定目标 TCP 套接字。
详见 [docs/protocol.md](docs/protocol.md)。

## 安全策略

- **SSRF 拦截**：只拦最核心的私有 / 回环地址
  - IPv4：`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`127.0.0.0/8`
  - IPv6：`::1/128`、`fc00::/7`、`fe80::/10`
- **只校验解析后的 IP**：域名先解析，所有解析结果全部通过才建连；字面 IP 直接校验。
- **校验地址即连接地址**：建连使用已校验的 IP，避免 DNS rebinding / TOCTOU。
- 连接超时、读写（空闲）超时限制；单 WSS 连接与单 IP 会话数上限。
- WSS 入口不做认证，靠「服务器只在需要时开机」降低暴露面；服务端必须配好 TLS。

## 测试

```bash
npm test           # 全部 55 个用例
npm run test:unit  # 帧协议 + SSRF 规则
npm run test:e2e   # 端到端链路 + 真实 TLS
```

## 方案固定项（不建议改动）

1. 客户端 HTTP 代理：`127.0.0.1:8080`
2. 服务端唯一入口：WSS `/`
3. 传输模式：`tcp-over-wss` 为基础，可扩展
4. Windows：必须静态路由豁免代理服务器 IP
5. 全程用户态、无 TUN、无驱动、无全局路由接管
6. `data` 帧：`[4 字节大端 sessionId][原始字节]`，不做 Base64
7. 控制帧：文本 JSON；数据帧：WebSocket 二进制
8. WSS 入口不做认证
9. SSRF 只拦核心私有 / 回环地址，只校验解析后 IP

## 待定项决策

方案第三节「普通明文 HTTP 请求处理」三个候选中，本实现选择 **候选 C**：

> 本地解析 HTTP，原样转发绝对 URL，按 `host:port` 动态新建 / 复用 session。

理由：不在本地改写请求行，避免破坏 `Origin`、签名、缓存键等语义；
绝对形式 request-target 是 HTTP 代理的 RFC 标准用法，上游服务器与中间设备都能正确处理。

同时本地做了最小必要的解析：只取目标 `host:port` 与报文边界，其余字节原样透传。

实现要点：

- 上行：重建请求行 + 头部时**剥离逐跳头**（`Proxy-Connection`、`Connection`、
  `Transfer-Encoding`、`Keep-Alive`、`Upgrade`、`TE`、`Trailer`、代理认证头），
  并追加 `Connection: close`——本实现按「一个请求一条隧道会话」处理，
  不做上游 keep-alive 复用，避免响应边界错乱。
- 下行：**不经过 `ServerResponse` 回写**。上游返回的是已分帧的原始 HTTP 响应，
  若交给 `ServerResponse` 会被二次分帧导致报文损坏。因此调用
  `res.detachSocket()` 摘除其控制权，把响应字节原样写入客户端 socket。
- 建连窗口：`connected` 到达前的请求体先缓存，就绪后按序补发，避免丢字节。

## License

MIT
