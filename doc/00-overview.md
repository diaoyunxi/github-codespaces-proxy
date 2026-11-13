# 概览

**项目**：http-over-wss-proxy（C++ 重构版）

把 HTTP 代理请求通过 WSS 长连接隧道（tcp-over-wss）送到远端服务端，

## 原文前言

# http-over-wss-proxy（C++ 重构版）

把 HTTP 代理请求通过 **WSS 长连接隧道**（`tcp-over-wss`）送到远端服务端，
由服务端建立原始 TCP 连接访问外网目标。

**全程用户态、无 TUN、无驱动、不接管全局路由**，可与 Windows 上已有闭源 VPN 共存。

> 本仓库是 [gitee.com/diaoyunxi/proxy](https://gitee.com/diaoyunxi/proxy)（Node.js 实现）的
> **C++ 重构版**：协议、行为、配置项、脚本全部对齐，改为单一可执行文件分发，
> 并通过 GitHub Actions 产出 Windows amd64 的 `exe + dll` 与 Linux amd64 的 `.deb`。
