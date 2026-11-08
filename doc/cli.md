> [← 返回文档目录](../README.md)

# 客户端命令行参数补充（`src/client/main.cpp`）

README 参数表之外的客户端参数（由 `main.cpp` 的 `argv` 解析分支处理）：

| 参数 | 说明 |
|---|---|
| `--no-update` | 关闭启动时的自动更新检查 |
| `--update-repo <repo>` | 覆盖自动更新检查所用的 GitHub 仓库 |
| `--help` / `-h` | 打印 usage 并退出 |

服务端参数：`--host`、`--port`、`--tls-cert`、`--tls-key`、`--no-tls`、`--config`、`--help`。

> 以上分支均在 `src/client/main.cpp` / `src/server/main.cpp` 中出现。
