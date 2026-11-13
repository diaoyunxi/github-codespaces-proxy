> [← 返回文档目录](../README.md) ｜ 本分册由 `README.md` 的「在 GitHub Codespaces 上部署（零证书）」章节拆分而来。

## 在 GitHub Codespaces 上部署（零证书）

GitHub Codespaces 的端口转发**由 GitHub 边缘完成 TLS 终止**：你在容器里看到的是明文 HTTP/WS，
证书完全不用本程序管。因此服务端跑明文 `ws://`、客户端用 `wss://` 连 Codespaces 转发地址即可。

1. 在 codespace 里构建并启动服务端（**不配证书**，绑定 `0.0.0.0` 才能被转发命中）：

   ```bash
   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
   cmake --build build --parallel
   ./build/http-over-wss-server --host 0.0.0.0 --port 8443
   # 日志： [listen] ws://0.0.0.0:8443/
   ```

2. 在 Codespaces 面板把 **8443 端口设为 Public 或 Private** 并复制转发地址，
   形如 `https://<随机串>-8443.app.github.dev/`（这就是客户端要连的地址）。

3. Windows 客户端连接（注意用 `wss://` 或 `https://` 前缀，**不要**用 `http://`）：

   ```powershell
   .\http-over-wss-client.exe --server https://<随机串>-8443.app.github.dev/ --no-update
   # 日志： [proxy] listening on http://127.0.0.1:8080
   ```

4. 系统代理填 `127.0.0.1:8080`，并（如有需要）把「本机 → Codespaces 转发地址的 IP」加静态路由豁免。

> 说明：客户端给的是 `wss://`（或 `https://`，程序会自动转成 `wss://`），TLS 在 GitHub 边缘完成；
> 服务端在容器内只跑明文 `ws://`，所以**两端都不需要任何证书文件**。
