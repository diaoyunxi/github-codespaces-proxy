# 部署与运维

## 服务端

### 依赖

- Node.js ≥ 18（使用了 `node:` 前缀导入、`--test` 运行器、`fetch` 等现代特性）
- 一张有效 TLS 证书（Let's Encrypt 或商业证书；自签需在客户端配 `caFile`）

### 配置

复制 `server/config.example.json` 为 `server/config.json`：

```json
{
  "port": 8443,
  "host": "0.0.0.0",
  "tlsCert": "/etc/letsencrypt/live/proxy.example.com/fullchain.pem",
  "tlsKey": "/etc/letsencrypt/live/proxy.example.com/privkey.pem",
  "connectTimeoutMs": 10000,
  "idleTimeoutMs": 120000,
  "maxSessionsPerConnection": 256,
  "maxSessionsPerIp": 512
}
```

也可用环境变量覆盖：`PROXY_PORT`、`PROXY_HOST`、`PROXY_TLS_CERT`、`PROXY_TLS_KEY`、`PROXY_CONFIG`（配置文件路径）。

> **注意**：未配置证书时服务端会降级为明文 `http`/`ws`，仅用于内网调试。
> 公网部署必须配置 TLS——本方案的前提是「WSS 入口不加认证」，安全性依赖传输层加密与低暴露面。

### 证书获取（Let's Encrypt）

```bash
# 用 acme.sh 或 certbot，standalone 模式需要 80 端口空闲
certbot certonly --standalone -d proxy.example.com
```

证书续期后服务端需重启（或用 systemd 定时重启）。

### systemd 服务

```ini
# /etc/systemd/system/http-over-wss-proxy.service
[Unit]
Description=HTTP-over-WSS proxy server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/http-over-wss-proxy
ExecStart=/usr/bin/node server/index.js
Restart=always
RestartSec=3
User=proxy
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now http-over-wss-proxy
```

### 端口与反向代理

服务端可以直连公网端口（如上例 8443），也可以放在 Nginx / Caddy 后面。
放在反向代理后面时，**必须**透传 Upgrade 头：

```nginx
location / {
    proxy_pass http://127.0.0.1:8443;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    proxy_buffering off;          # 隧道流量不要缓冲
}
```

> 由于服务端唯一入口是 `/`，Nginx 的 `location /` 正好对应，无需额外路由。

## 客户端（Windows）

### 依赖

- Node.js ≥ 18

### 配置

复制 `client/config.example.json` 为 `client/config.json`：

```json
{
  "listenHost": "127.0.0.1",
  "listenPort": 8080,
  "serverUrl": "wss://proxy.example.com/",
  "rejectUnauthorized": true,
  "caFile": "",
  "pingIntervalMs": 25000,
  "maxSessions": 1024
}
```

| 字段 | 说明 |
| --- | --- |
| `listenHost` / `listenPort` | 本地代理监听地址，默认 `127.0.0.1:8080`（方案固定项） |
| `serverUrl` | 远端 WSS 地址，**必须**是根路径 `/` |
| `rejectUnauthorized` | 是否校验服务端证书。生产环境保持 `true` |
| `caFile` | 自签 / 企业 CA 证书路径，配合 `rejectUnauthorized: true` 使用 |
| `reconnectDelayMs` / `maxReconnectDelayMs` | 重连退避区间（指数增长，上限封顶） |
| `pingIntervalMs` | WebSocket 心跳间隔，用于穿过 NAT / 负载均衡的空闲超时 |

### 开机自启（任务计划程序）

```powershell
# 以管理员身份运行
$action  = New-ScheduledTaskAction -Execute 'node.exe' `
           -Argument 'client/index.js' -WorkingDirectory 'C:\proxy\client'
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
Register-ScheduledTask -TaskName 'http-over-wss-proxy-client' `
  -Action $action -Trigger $trigger -Principal $principal
```

> `-RunLevel Highest` 是为了让子进程有权限执行 `windows-add-route.ps1` 的收尾清理；
> 日常运行时本地代理本身**不需要**管理员权限。

## Windows 侧操作速查

### 加 / 删静态路由（绕过 VPN）

```powershell
# 自动识别物理网卡
.\scripts\windows-add-route.ps1 -ServerIp 203.0.113.10

# 手动指定物理网卡接口索引（Get-NetAdapter 可查看）
.\scripts\windows-add-route.ps1 -ServerIp 203.0.113.10 -PhysicalInterfaceIndex 12

# 删除
.\scripts\windows-remove-route.ps1 -ServerIp 203.0.113.10
```

脚本会跳过名称 / 描述匹配 `TAP|TUN|VPN|WireGuard|OpenVPN|Tailscale|ZeroTier|Wintun|Clash|Mihomo|虚拟|隧道` 的网卡。

### 验证路由生效

```powershell
Find-NetRoute -RemoteIPAddress 203.0.113.10 | Select-Object -First 1 IPAddress, InterfaceAlias
```

输出的 `InterfaceAlias` 应该是**物理网卡**，而不是 VPN 的虚拟网卡。

### 设置 / 清除系统代理

```powershell
.\scripts\windows-set-system-proxy.ps1              # 开启 127.0.0.1:8080
.\scripts\windows-set-system-proxy.ps1 -Clear       # 关闭
```

脚本会调用 `InternetSetOption` 通知系统刷新，避免部分应用沿用旧设置。

## 排障

### 应用不走代理

- 确认「设置 → 网络和 Internet → 代理」中手动代理已开启且为 `127.0.0.1:8080`
- 部分应用（如 UWP、命令行工具）不读系统代理，需要单独配置环境变量
  `HTTP_PROXY` / `HTTPS_PROXY`，或使用支持 WinINET 的启动方式

### 隧道连不上

1. `npm run client` 日志里若出现 `[tunnel] down: ... (auto reconnecting)`，检查：
   - `serverUrl` 是否是 `wss://` 且路径为 `/`
   - 静态路由是否生效（见上方验证命令）
   - 服务端是否在运行、防火墙 / 安全组是否放行端口
2. 自签证书场景：把证书路径填入 `caFile`，保持 `rejectUnauthorized: true`，
   不要图省事设成 `false`

### 目标被 SSRF 拦截

日志 / 客户端返回 `502 Bad Gateway: ... blocked range ...`。
这是预期行为：服务端只允许访问公网地址（私有、回环、链路本地含云元数据、
CGNAT、组播、保留网段一律拦截）。
确需访问内网时，应改 `server/ssrf.js` 的网段表，而不是全局关闭校验。

### 会话数打满

调大 `maxSessionsPerConnection` / `maxSessionsPerIp`（服务端）
与 `maxSessions`（客户端）。默认值对常规浏览足够；
批量爬取类场景需要显著调大，同时注意文件描述符上限（`ulimit -n`）。

### 连接延迟高

- 确认多路复用生效：一条 WSS 连接应承载全部会话，而不是每连接一条（看日志 `[conn] +` 出现次数）
- 适当调大 `idleTimeoutMs`，避免高频建连的目标反复重连

## 监控建议

服务端日志关键行：

| 日志 | 含义 |
| --- | --- |
| `[listen] wss://...` | 启动成功 |
| `[conn] + <ip> (ip sessions=N)` | 新 WSS 连接接入 |
| `[conn] - <ip> (released N sessions)` | 连接断开，释放了 N 个会话 |

重点关注 `[conn] +` 的频率：异常升高通常意味着客户端在反复重连（网络不稳或服务端不稳）。
