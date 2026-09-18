# Windows 操作脚本

三个 PowerShell 脚本，与 Node 版行为一致，可直接配套本 C++ 客户端使用。

| 脚本 | 作用 |
| --- | --- |
| `windows-add-route.ps1` | 为代理服务器公网 IP 添加 `/32` 永久静态路由，走物理网卡，绕过 VPN 的 TUN |
| `windows-remove-route.ps1`   | 删除上述路由 |
| `windows-set-system-proxy.ps1` | 一键开启/清除 Windows 系统手动代理（`127.0.0.1:8080`） |

均需**管理员身份**运行。详细用法见各脚本头部注释。
