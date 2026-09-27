# 贡献指南

感谢你对 github-codespaces-proxy 项目的关注！

## 开发环境

- **编译器：** GCC 11+ 或 Clang 14+（C++17）
- **构建系统：** CMake 3.16+
- **平台：** Linux（主要）、Windows（可选）

## 构建步骤

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

## 代码规范

- C++17 标准
- 使用 `.editorconfig` 中定义的缩进和格式
- 所有公共 API 需添加 Doxygen 风格注释
- 错误处理使用返回值或 `std::optional`，避免异常
- 网络相关代码需考虑 SSRF 防护（参考 `ssrf.cpp`）

## 安全注意事项

本项目处理网络代理流量，修改时请特别注意：

- SSRF 防护规则（`src/common/ssrf.cpp`）的完整性
- WebSocket 协议解析的边界检查
- TCP 连接的生命周期管理
- 缓冲区操作（`memcpy`/`read`）的长度校验

## 提交 Pull Request

1. Fork 本仓库并创建功能分支
2. 确保编译通过且无警告
3. 如涉及安全相关修改，请在 PR 描述中说明威胁模型
4. 遵循 Conventional Commits 规范提交
