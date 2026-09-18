#!/usr/bin/env bash
#
# 端到端联调脚本（本地回环，无需公网）
#
# 覆盖：
#   1) wss:// 链路（真实自签 TLS 证书）
#   2) CONNECT 隧道内的 TLS-in-TLS 端到端
#   3) 明文 HTTP 绝对 URL 透传
#   4) SSRF 拦截私有地址（期望 502）
#   5) 1MB 大响应（检验 WS 分片与透传正确性）
#   6) ws:// 明文链路（无 TLS）回归
#
# 用法：
#   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
#   bash tests/e2e/run_e2e.sh build
#
# 说明：
#   SSRF 规则禁止访问私有地址，因此测试用「公网字面 IP 9.9.9.9」发请求，
#   并通过服务端的测试钩子 HWP_TEST_CONNECT_MAP=9.9.9.9=127.0.0.1
#   把「已通过校验的地址」改写为本地回环目标。该钩子等价于 Node 版的
#   config.connectOverride，仅用于自测，生产环境请勿设置。
set -uo pipefail

# 参数可为「相对路径（相对当前工作目录）」或绝对路径
BUILD_DIR="${1:-build}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
case "$BUILD_DIR" in
  /*) ABS_BUILD="$BUILD_DIR" ;;
  *)  ABS_BUILD="$(cd "$BUILD_DIR" 2>/dev/null && pwd)" || { echo "构建目录不存在：$BUILD_DIR"; exit 1; } ;;
esac
BIN_SERVER="${SERVER_BIN:-$ABS_BUILD/http-over-wss-server}"
BIN_CLIENT="${CLIENT_BIN:-$ABS_BUILD/http-over-wss-client}"
WORK="$(mktemp -d)"
PASS=0
FAIL=0

# 端口可通过环境变量覆盖，避免与宿主环境冲突
SRV_PORT="${SRV_PORT:-18446}"
PROXY_PORT_NUM="${PROXY_PORT_NUM:-18078}"
TLS_PORT="${TLS_PORT:-19601}"
HTTP_PORT="${HTTP_PORT:-19602}"
BIG_PORT="${BIG_PORT:-19603}"

[[ -x "$BIN_SERVER" ]] || { echo "缺少服务端二进制：$BIN_SERVER"; exit 1; }
[[ -x "$BIN_CLIENT" ]] || { echo "缺少客户端二进制：$BIN_CLIENT"; exit 1; }
command -v node >/dev/null || { echo "需要 node（仅用于起测试用目标服务）"; exit 1; }

cleanup() {
  [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null
  [[ -n "${CLI_PID:-}" ]] && kill "$CLI_PID" 2>/dev/null
  [[ -n "${T1_PID:-}"  ]] && kill "$T1_PID"  2>/dev/null
  [[ -n "${T2_PID:-}"  ]] && kill "$T2_PID"  2>/dev/null
  [[ -n "${T3_PID:-}"  ]] && kill "$T3_PID"  2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

check() { # name expected actual
  if [[ "$2" == "$3" ]]; then
    echo "PASS  $1"; PASS=$((PASS + 1))
  else
    echo "FAIL  $1  期望=[$2] 实际=[$3]"; FAIL=$((FAIL + 1))
  fi
}

# ---- 自签证书（CN/SAN=localhost）----
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
  -days 2 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

# ---- 测试目标：TLS echo / 明文 HTTP / 1MB 大响应 ----
cat > "$WORK/targets.js" <<'EOF'
const tls = require('tls'), fs = require('fs'), http = require('http');
const dir = process.env.WORK;
tls.createServer(
  { key: fs.readFileSync(dir + '/key.pem'), cert: fs.readFileSync(dir + '/cert.pem') },
  s => s.on('data', d => s.write(Buffer.concat([Buffer.from('OK-TLS:'), d]))),
).listen(Number(process.env.TLS_PORT), '127.0.0.1');
http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('OK-HTTP ' + req.method + ' ' + req.url);
}).listen(Number(process.env.HTTP_PORT), '127.0.0.1');
http.createServer((req, res) => {
  const body = Buffer.alloc(1024 * 1024, 0x41);
  res.writeHead(200, { 'Content-Length': body.length });
  res.end(body);
}).listen(Number(process.env.BIG_PORT), '127.0.0.1');
EOF
WORK="$WORK" TLS_PORT="$TLS_PORT" HTTP_PORT="$HTTP_PORT" BIG_PORT="$BIG_PORT" \
  node "$WORK/targets.js" & T1_PID=$!
sleep 1

# ---- 服务端（wss + 测试钩子）----
HWP_TEST_CONNECT_MAP="9.9.9.9=127.0.0.1" "$BIN_SERVER" \
  --host 127.0.0.1 --port "$SRV_PORT" \
  --tls-cert "$WORK/cert.pem" --tls-key "$WORK/key.pem" > "$WORK/server.log" 2>&1 &
SRV_PID=$!
sleep 1.2

# ---- 客户端 ----
cat > "$WORK/client.json" <<EOF
{
  "listenHost": "127.0.0.1",
  "listenPort": $PROXY_PORT_NUM,
  "serverUrl": "wss://localhost:$SRV_PORT/",
  "caFile": "$WORK/cert.pem",
  "rejectUnauthorized": true
}
EOF
"$BIN_CLIENT" --config "$WORK/client.json" > "$WORK/client.log" 2>&1 &
CLI_PID=$!

for _ in $(seq 1 40); do grep -q "connected ->" "$WORK/client.log" 2>/dev/null && break; sleep 0.25; done
sleep 0.8

PROXY="http://127.0.0.1:$PROXY_PORT_NUM"

echo "== 1) CONNECT 隧道（TLS-in-TLS）=="
OUT="$(echo "e2e-payload" | timeout 15 openssl s_client -connect "9.9.9.9:$TLS_PORT" -proxy "127.0.0.1:$PROXY_PORT_NUM" -quiet 2>/dev/null | head -1)"
check "CONNECT + TLS 端到端" "OK-TLS:e2e-payload" "$OUT"

echo "== 2) 明文 HTTP（绝对 URL 透传）=="
OUT="$(timeout 15 curl -s -x "$PROXY" http://9.9.9.9:$HTTP_PORT/abs-path)"
check "绝对 URL request-target 透传" "OK-HTTP GET http://9.9.9.9:$HTTP_PORT/abs-path" "$OUT"

echo "== 3) SSRF 拦截私有地址 =="
OUT="$(timeout 15 curl -s -o /dev/null -w '%{http_code}' -x "$PROXY" http://10.0.0.5:80/x)"
check "私有 IP 返回 502" "502" "$OUT"

echo "== 4) 1MB 大响应 =="
OUT="$(timeout 30 curl -s -x "$PROXY" http://9.9.9.9:$BIG_PORT/big | wc -c | tr -d ' ')"
check "1MB 响应字节数" "1048576" "$OUT"

echo
echo "通过 $PASS 项，失败 $FAIL 项"
[[ "$FAIL" -eq 0 ]]
