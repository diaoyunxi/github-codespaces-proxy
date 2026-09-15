import test from 'node:test';
import assert from 'node:assert/strict';
import {
  encodeDataFrame,
  decodeDataFrame,
  isValidSessionId,
  isValidPort,
  parseControlMessage,
  controlMessage,
} from '../server/protocol.js';

test('data 帧：[4 字节大端 sessionId][原始字节]', () => {
  const frame = encodeDataFrame(0x01020304, Buffer.from('hello'));
  assert.equal(frame.subarray(0, 4).toString('hex'), '01020304');
  assert.equal(frame.subarray(4).toString(), 'hello');
});

test('data 帧：roundtrip 保持字节完全一致（不做 Base64）', () => {
  const payload = Buffer.from([0x00, 0xff, 0x10, 0x80, 0x7f, 0x00]);
  const decoded = decodeDataFrame(encodeDataFrame(42, payload));
  assert.equal(decoded.sessionId, 42);
  assert.deepEqual(decoded.payload, payload);
});

test('data 帧：空 payload 也合法', () => {
  const decoded = decodeDataFrame(encodeDataFrame(7));
  assert.equal(decoded.sessionId, 7);
  assert.equal(decoded.payload.length, 0);
});

test('data 帧：长度不足 4 字节返回 null', () => {
  assert.equal(decodeDataFrame(Buffer.from([1, 2, 3])), null);
  assert.equal(decodeDataFrame(Buffer.alloc(0)), null);
});

test('data 帧：sessionId 支持 uint32 全范围', () => {
  const decoded = decodeDataFrame(encodeDataFrame(0xffffffff, Buffer.from('x')));
  assert.equal(decoded.sessionId, 0xffffffff);
});

test('sessionId 校验：0 与越界非法', () => {
  assert.equal(isValidSessionId(1), true);
  assert.equal(isValidSessionId(0xffffffff), true);
  assert.equal(isValidSessionId(0), false);
  assert.equal(isValidSessionId(0x100000000), false);
  assert.equal(isValidSessionId(-1), false);
  assert.equal(isValidSessionId(1.5), false);
  assert.equal(isValidSessionId('1'), false);
});

test('port 校验', () => {
  assert.equal(isValidPort(1), true);
  assert.equal(isValidPort(443), true);
  assert.equal(isValidPort(65535), true);
  assert.equal(isValidPort(0), false);
  assert.equal(isValidPort(65536), false);
  assert.equal(isValidPort('443'), false);
});

test('控制消息：文本帧 JSON，含 type 字段', () => {
  const msg = JSON.parse(controlMessage('connect', { sessionId: 1, host: 'a.com', port: 443, mode: 'tcp-over-wss' }));
  assert.equal(msg.type, 'connect');
  assert.equal(msg.host, 'a.com');
  assert.equal(msg.port, 443);
});

test('控制消息解析：非法 JSON / 缺 type 返回 null', () => {
  assert.equal(parseControlMessage('not json'), null);
  assert.equal(parseControlMessage('{}'), null);
  assert.equal(parseControlMessage('[]'), null);
  const ok = parseControlMessage(controlMessage('close', { sessionId: 3 }));
  assert.equal(ok.type, 'close');
  assert.equal(ok.sessionId, 3);
});
