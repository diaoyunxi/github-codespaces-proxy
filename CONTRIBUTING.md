# 构建与开发速查

```bash
# Linux
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DHWP_BUILD_E2E=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure     # 单元 + 端到端
cd build && cpack -G DEB                        # 打包 .deb
```

Windows（MSVC + vcpkg）：

```powershell
vcpkg install openssl:x64-windows-static
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build --parallel
```

## 代码结构约定

- `src/common/` 不依赖 `src/server` 与 `src/client`，可单独复用。
- `WebSocket` 只依赖 `Stream` 抽象，因此 `ws://` 与 `wss://` 共用同一套帧编解码。
- 帧协议 / SSRF 规则的任何改动都应同步更新 `tests/selftest.cpp`。
- 与原 Node 版的行为差异视为 **Bug**（除分发形态外），协议必须保持逐字节兼容。

## 测试要求

- 新增 SSRF 网段：在 `src/common/ssrf.cpp` 的表里加，并在 `tests/selftest.cpp` 补正反用例。
- 涉及链路行为的改动：跑 `-DHWP_BUILD_E2E=ON` 的 `ctest`。

## 已知取舍

- 未实现 `permessage-deflate` 压缩扩展（本协议无需压缩，数据帧本就零额外开销）。
- WebSocket 发送为阻塞写，未做异步发送队列；下行背压通过客户端读循环的自然节流实现。
