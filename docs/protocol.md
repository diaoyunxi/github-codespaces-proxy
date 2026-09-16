# WSS 隧道帧协议

## 传输层

服务端唯一入口是 **HTTPS 根路径 `/`**，仅接受 WebSocket Upgrade。
普通 HTTP 请求、非 `/` 路径的 Upgrade 一律返回 `400 Bad Request`。

升级成功后，同一条 WebSocket 连接上承载控制消息与数据消息，二者靠**帧类型**区分：

- WebSocket **文本帧** → 控制消息（JSON）
- WebSocket **二进制帧** → 数据消息（原始 TCP 字节）

## 控制消息（文本帧 + JSON）

所有控制消息都是 JSON 对象，必含 `type` 字段。

### `connect`（客户端 → 服务端）

请求建立一条到 `host:port` 的隧道会话。

```json
{
  "type": "connect",
  "sessionId": 305419896,
  "host": "example.com",
  "port": 443,
  "mode": "tcp-over-wss"
}
```

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `sessionId` | uint32 | **必填**，非 0，客户端生成，由客户端保证在**该连接内**唯一 |
| `host` | string | **必填**，域名或 IP 字面量 |
| `port` | uint16 | **必填**，1–65535 |
| `mode` | string | 可选，默认 `tcp-over-wss`；其他值返回 `error` |

### `connected`（服务端 → 客户端）

目标 TCP 连接**已建立**，可以开始发送数据帧。

```json
{ "type": "connected", "sessionId": 305419896 }
```

> 客户端在收到 `connected` 之前不应发送该会话的数据帧。
> 服务端在目标 TCP 连接建立完成前会**静默丢弃**该会话的数据帧
> —— `handleData` 虽能查到会话（`handleConnect` 在 `await guardTarget(...)` 之前
> 就已 `sessions.set(sessionId, session)`），但此时 `state` 仍为 `connecting`，
> `Session.write` 仅在 `state === open` 时写入，返回 `false` 的字节被丢弃。
> 因此客户端实现**必须**把「建连前的首段字节」（如 TLS ClientHello、请求头）
> 缓存到 `connected` 之后再补发，否则会丢字节。

### `half-close`（客户端 → 服务端）

客户端上行方向 EOF：客户端不再发送该会话的数据，但**仍会接收下行数据**。

```json
{ "type": "half-close", "sessionId": 305419896 }
```

语义等价于向目标 TCP 发送 FIN（`socket.end()`），而不是关闭整个会话。
服务端收到后：

- 将 `Session.uplinkClosed` 置为 `true`，此后到达的该会话数据帧一律丢弃
- 调用 `session.socket.end()` 向目标发送 FIN
- **保留**下行：目标后续返回的数据仍会封帧发回客户端
- 当目标 socket 关闭时，会话才真正回收（回 `close`）

典型场景：HTTP/1.0 客户端、部分语言 SDK、隧道内半关闭
—— 「请求发完 → shutdown 写端 → 等响应」。
客户端的本地 socket 收到 FIN（`'end'`）时即发送本消息。

### `close`（双向）

任一端主动关闭某个会话。

```json
{ "type": "close", "sessionId": 305419896 }
{ "type": "close", "sessionId": 305419896, "reason": "target closed" }
```

服务端 → 客户端的 `close` 会带 `reason` 便于诊断。
客户端收到后应销毁对应会话；服务端收到后销毁目标 TCP 套接字。

### `error`（服务端 → 客户端）

会话级别的错误。收到即意味着该 `sessionId` 已失败，会话已销毁。

```json
{ "type": "error", "sessionId": 305419896, "message": "target IP 10.0.0.5 is in blocked range 10.0.0.0/8" }
```

常见 `message`：

| message 模式 | 含义 |
| --- | --- |
| `target IP ... is in blocked range ...` | 字面 IP 命中 SSRF 拦截网段 |
| `target ... resolves to blocked range ...` | 域名解析结果命中 SSRF 拦截网段 |
| `DNS resolve failed for ...` | 域名解析失败 |
| `unsupported mode: ...` | `mode` 不是 `tcp-over-wss` |
| `duplicate sessionId` | 同一连接内 `sessionId` 重复 |
| `per-connection session limit reached` | 超出单连接会话上限 |
| `target socket error: ...` | 目标建连 / 读写失败 |
| `target idle timeout` | 目标空闲超时 |
| `invalid connect message` | `connect` 字段缺失或类型非法 |

## 数据消息（二进制帧）

```
 0        1        2        3        4                          N
+--------+--------+--------+--------+--------------------------+
|            sessionId (uint32 BE)   |      原始 TCP 字节 ...     |
+--------+--------+--------+--------+--------------------------+
```

- 前 4 字节：**大端** `uint32` 的 `sessionId`，与服务端 `connect` 中的一致。
- 第 4 字节起：**原始 TCP 载荷**，逐字节透传，**不做 Base64、不做压缩、不加密**。
- 长度小于 4 字节的二进制帧视为非法，服务端直接忽略。

### 为什么用大端

网络字节序（big-endian）是网络协议惯例，`Buffer.readUInt32BE` / `writeUInt32BE` 直接对应，
跨语言实现时无需额外字节序协商。

### 数据方向

数据帧是**双向**的，同一格式：

- 客户端 → 服务端：`sessionId` 对应的目标套接字写入这些字节
- 服务端 → 客户端：来自目标套接字的字节

服务端不区分「上行 / 下行」帧，也不需要额外的方向标记。

## 会话生命周期

```
      客户端                                        服务端
         |                                             |
         |-- connect(sessionId, host, port, mode) ---->|
         |                                             |-- DNS 解析
         |                                             |-- SSRF 校验（全部解析结果）
         |                                             |-- TCP connect
         |<-------------- connected(sessionId) --------|
         |                                             |
         |<======== 二进制数据帧（双向透传）===========>|
         |                                             |
         |-- close(sessionId) ------------------------>|-- 销毁目标套接字
         |<-------------------- close(sessionId) -------|
```

失败路径：

```
         |-- connect(...) ---------------------------->|
         |<------------------- error(sessionId, msg) ---|  （会话未建立，直接回收）
```

## 超时与回收

| 时机 | 行为 |
| --- | --- |
| 目标 TCP 建连超时 | 服务端回 `error`，销毁会话 |
| 会话空闲超过 `idleTimeoutMs` | 服务端回 `close`，销毁目标套接字（每 5s 巡检一次） |
| 客户端发 `close` | 服务端立即销毁目标套接字 |
| 目标套接字关闭 | 服务端回 `close` |
| WSS 连接断开 | 服务端销毁该连接上**全部**会话；客户端清空本地会话并自动重连 |
| 单连接会话数超 `maxSessionsPerConnection` | 对新的 `connect` 回 `error` |
| 单 IP 会话数超 `maxSessionsPerIp` | 关闭整条 WSS 连接（`1013`） |

## 多路复用

一条 WSS 连接可承载任意多个会话（受 `maxSessionsPerConnection` 限制）。
`sessionId` 只需在**单条 WSS 连接内**唯一，不同连接之间互不影响。

## 扩展性

`mode` 字段用于未来扩展传输模式，当前只实现 `tcp-over-wss`。
后续可增加 `udp-over-wss` 等，控制消息格式不变，`connect` 时指定新的 `mode` 即可。
服务端收到不支持的 `mode` 会回 `error`，不会静默降级。
