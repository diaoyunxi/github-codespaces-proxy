/**
 * WSS 隧道帧协议 —— 客户端与服务端共用实现的规范说明与工具函数。
 *
 * 控制消息：WebSocket 文本帧 + JSON
 *   { "type": "connect",     "sessionId": 1, "host": "example.com", "port": 443, "mode": "tcp-over-wss" }
 *   { "type": "connected",   "sessionId": 1 }
 *   { "type": "half-close",  "sessionId": 1 }   // 客户端上行 EOF：不再发送数据，但仍接收下行
 *   { "type": "close",       "sessionId": 1 }
 *   { "type": "error",       "sessionId": 1, "message": "..." }
 *
 * 数据消息：WebSocket 二进制帧
 *   [0..3]  4 字节大端 uint32 sessionId
 *   [4..]   原始 TCP 字节，零 Base64 开销
 */

export const MODE_TCP_OVER_WSS = 'tcp-over-wss';

/** 数据帧头部长度：4 字节大端 sessionId */
export const DATA_HEADER_LEN = 4;

/** sessionId 取值范围 */
export const SESSION_ID_MIN = 1;
export const SESSION_ID_MAX = 0xffffffff;

/**
 * 编码数据帧。
 * @param {number} sessionId
 * @param {Buffer} payload 原始字节
 * @returns {Buffer}
 */
export function encodeDataFrame(sessionId, payload) {
  const head = Buffer.allocUnsafe(DATA_HEADER_LEN);
  head.writeUInt32BE(sessionId >>> 0, 0);
  if (!payload || payload.length === 0) return head;
  return Buffer.concat([head, payload]);
}

/**
 * 解码数据帧。返回 { sessionId, payload }，或 null（帧过短）。
 * @param {Buffer} buf
 */
export function decodeDataFrame(buf) {
  if (!buf || buf.length < DATA_HEADER_LEN) return null;
  return {
    sessionId: buf.readUInt32BE(0),
    payload: buf.subarray(DATA_HEADER_LEN),
  };
}

/**
 * 判断 sessionId 是否为合法的 uint32（非 0）。
 * @param {unknown} v
 */
export function isValidSessionId(v) {
  return (
    typeof v === 'number' &&
    Number.isInteger(v) &&
    v >= SESSION_ID_MIN &&
    v <= SESSION_ID_MAX
  );
}

/**
 * 判断端口是否合法。
 * @param {unknown} v
 */
export function isValidPort(v) {
  return typeof v === 'number' && Number.isInteger(v) && v >= 1 && v <= 65535;
}

/**
 * 解析控制消息文本帧。
 * @param {string} text
 * @returns {{type: string, [k: string]: unknown} | null}
 */
export function parseControlMessage(text) {
  let obj;
  try {
    obj = JSON.parse(text);
  } catch {
    return null;
  }
  if (!obj || typeof obj !== 'object' || typeof obj.type !== 'string') return null;
  return obj;
}

/** 构造控制消息文本帧内容 */
export function controlMessage(type, fields = {}) {
  return JSON.stringify({ type, ...fields });
}
