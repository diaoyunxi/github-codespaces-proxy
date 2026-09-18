#pragma once
/**
 * 极简 WebSocket（RFC 6455）实现，够本协议用：
 *   - 握手（客户端 / 服务端）
 *   - 文本帧 / 二进制帧收发
 *   - ping / pong / close
 *   - 发送与接收均支持分片（发送分片阈值可配）
 *
 * 不实现压缩扩展（permessage-deflate）、不实现子协议协商。
 * 与 Node `ws` 互操作：文本帧 JSON 控制消息、二进制帧数据消息。
 */
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "util.hpp"

namespace hwp {

class TcpSocket;  // 前向声明（见 tcpsocket.hpp）
class TlsStream;

/** 发送分片大小：超过该长度的数据帧拆成多个 WebSocket 帧，避免单帧过大 */
inline constexpr size_t kWsSendChunk = 256 * 1024;

enum class WsState { Connecting, Open, Closing, Closed };

class WebSocket {
 public:
  using TextHandler = std::function<void(const std::string& text)>;
  using BinaryHandler = std::function<void(const uint8_t* data, size_t len)>;
  using CloseHandler = std::function<void(const std::string& reason)>;
  using ErrorHandler = std::function<void(const std::string& message)>;

  /** 客户端模式下发起握手；握手完成后触发 onOpen */
  static std::shared_ptr<WebSocket> connectClient(std::shared_ptr<TcpSocket> sock,
                                                  std::shared_ptr<TlsStream> tls,
                                                  const std::string& host, const std::string& path,
                                                  const std::string& extraHeaders);

  /** 服务端模式：在已升级的流上创建 */
  static std::shared_ptr<WebSocket> fromServerStream(std::shared_ptr<TcpSocket> sock,
                                                      std::shared_ptr<TlsStream> tls,
                                                      const std::string& acceptKey);

  virtual ~WebSocket() = default;

  void onText(TextHandler h) { textHandler_ = std::move(h); }
  void onBinary(BinaryHandler h) { binaryHandler_ = std::move(h); }
  void onClose(CloseHandler h) { closeHandler_ = std::move(h); }
  void onError(ErrorHandler h) { errorHandler_ = std::move(h); }
  void onOpen(std::function<void()> h) { openHandler_ = std::move(h); }

  /** 启动读循环（阻塞，需在独立线程调用） */
  virtual void runReadLoop() = 0;

  /** 发送文本帧 */
  virtual bool sendText(const std::string& text) = 0;
  /** 发送二进制帧（自动按键值分片） */
  virtual bool sendBinary(const uint8_t* data, size_t len) = 0;
  /** 发送 ping */
  virtual bool sendPing() = 0;
  /** 主动关闭 */
  virtual void close(uint16_t code = 1000, const std::string& reason = "") = 0;
  /** 立即断开（不发 close 帧） */
  virtual void terminate() = 0;

  WsState state() const { return state_.load(); }
  /** 发送缓冲待发字节数（用于下行背压） */
  size_t bufferedBytes() const;

  /** 计算 Sec-WebSocket-Accept */
  static std::string acceptKey(const std::string& clientKey);

  /** 标记本端是否为服务端（决定是否给发出的帧加掩码） */
  void setServerSide(bool v) { serverSideFlag_ = v; }
  void setStateOpen() { state_.store(WsState::Open); }

 protected:
  WebSocket() = default;

  /** 发送原始报文（由子类实现真实写操作，串行化） */
  virtual bool writeRaw(const uint8_t* data, size_t len) = 0;
  virtual void shutdownStream() = 0;

  bool sendFrame(uint8_t opcode, const uint8_t* payload, size_t len, bool fin);
  /** 收到一个完整帧后的分派 */
  void dispatchFrame(uint8_t opcode, const Bytes& payload, bool fin);
  void failConnection(const std::string& reason, bool notifyError);
  void emitClose(const std::string& reason);

  std::atomic<WsState> state_{WsState::Connecting};
  std::mutex writeMutex_;
  size_t buffered_ = 0;
  bool serverSideFlag_ = false;

  TextHandler textHandler_;
  BinaryHandler binaryHandler_;
  CloseHandler closeHandler_;
  ErrorHandler errorHandler_;
  std::function<void()> openHandler_;

 private:
  Bytes fragBuf_;
  uint8_t fragOpcode_ = 0;
  bool closeEmitted_ = false;
};

}  // namespace hwp
