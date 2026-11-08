# http-over-wss-proxy（C++ 重构版）

把 HTTP 代理请求通过 WSS 长连接隧道（tcp-over-wss）送到远端服务端，

> 本文件为文档目录；全部说明文档统一存放于 `doc/`。

## 文档目录

- [00 · 概览](doc/00-overview.md)　`本文档总述`
- [01 · 与原版的关系](doc/01-与原版的关系.md)
- [02 · 为什么这么设计](doc/02-为什么这么设计.md)
- [03 · 网络拓扑](doc/03-网络拓扑.md)
- [04 · 目录结构](doc/04-目录结构.md)
- [05 · 构建](doc/05-构建.md)
- [06 · 快速开始](doc/06-快速开始.md)
- [07 · 在 GitHub Codespaces 上部署（零证书）](doc/07-在-GitHub-Codespaces-上部署-零证书.md)
- [08 · 命令行参数](doc/08-命令行参数.md)
- [09 · 端到端运行流程](doc/09-端到端运行流程.md)
- [10 · 帧协议速览](doc/10-帧协议速览.md)
- [11 · 安全策略](doc/11-安全策略.md)
- [12 · 测试](doc/12-测试.md)
- [13 · 方案固定项（不建议改动）](doc/13-方案固定项-不建议改动.md)
- [14 · License](doc/14-License.md)
- [变更日志](doc/changelog.md)
- [贡献指南](doc/contributing.md)
- [安全策略](doc/security.md)
- [部署指南](doc/deployment.md)
- [帧协议规范](doc/protocol.md)
- [脚本说明](doc/scripts.md)
- [cli](doc/cli.md)　`新增·代码可感知点`

---

> 文档与代码一致性按 `doc/` 各分册核对；实现以仓库源码为准。
