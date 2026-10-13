#!/usr/bin/env bash
# 讯飞插件协议层测试一键脚本
#
# 覆盖：
#   1) 协议层单元自测（签名链 / MD5 / HMAC-SHA1 / SHA1 / Base64 / WebSocket 帧 / RTASR 解析）
#   2) 明文 WebSocket 端到端（起本地回显服务端）
#   3) 大帧分片 与 TCP 超时 两项回归
#
# 用法:  bash tests/run-protocol-tests.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SRC="$REPO_ROOT/src"
OUT="${OUT_DIR:-/tmp/xf-test-build}"
mkdir -p "$OUT"

# macOS：MacOSX27.0.sdk 的 tbd 声明了当前 ld 不认的架构，必须换 26.5
SDK="/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk"
[ -d "$SDK" ] || SDK="$(xcrun --show-sdk-path)"

# OpenSSL 前缀（macOS 没有系统 OpenSSL 头）
SSL_PREFIX="${SSL_PREFIX:-/opt/homebrew/opt/openssl@3}"
[ -f "$SSL_PREFIX/include/openssl/ssl.h" ] || SSL_PREFIX="$(pkg-config --variable=prefix openssl 2>/dev/null || echo /usr)"

CXX="${CXX:-clang++}"
COMMON_FLAGS=(-std=c++17 -O1 -Wall -Wextra -Wno-unused-parameter)
INCS=(-I"$SRC" -I"$SRC/xunfei" -I"$SSL_PREFIX/include" -isysroot "$SDK")
LIBS=(-L"$SSL_PREFIX/lib" -lssl -lcrypto)

fail=0
step() { printf '\n\033[1m=== %s\033[0m\n' "$1"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "缺少依赖: $1"; exit 2; }; }

need "$CXX"
need python3

step "1/3 编译并运行协议层单元自测"
"$CXX" "${COMMON_FLAGS[@]}" -o "$OUT/xf_selftest" \
  "$REPO_ROOT/src/xunfei/tests/xunfei-selftest.cpp" \
  "$SRC/xunfei/xunfei-utils.cpp" \
  "$SRC/xunfei/xunfei-json.cpp" \
  "$SRC/xunfei/xunfei-websocket.cpp" \
  "$SRC/xunfei/xunfei-rtasr.cpp" \
  "$SRC/model-utils/sha256.cpp" \
  "${INCS[@]}" "${LIBS[@]}" || fail=1
if [ "$fail" -eq 0 ]; then
  "$OUT/xf_selftest" || fail=1
fi

step "2/3 编译 WebSocket 端到端探针"
"$CXX" "${COMMON_FLAGS[@]}" -o "$OUT/ws_probe" \
  "$REPO_ROOT/src/xunfei/tests/ws_client_probe.cpp" \
  "$SRC/xunfei/xunfei-websocket.cpp" \
  "$SRC/xunfei/xunfei-utils.cpp" \
  "$SRC/model-utils/sha256.cpp" \
  "${INCS[@]}" "${LIBS[@]}" || fail=1

step "3/3 启动本地回显服务端并跑端到端（含分片/超时回归）"
PORT="${WS_PORT:-9911}"
if [ "$fail" -eq 0 ]; then
  python3 "$REPO_ROOT/src/xunfei/tests/ws_echo_server.py" "$PORT" &
  SRV_PID=$!
  trap 'kill "$SRV_PID" 2>/dev/null || true' EXIT
  # 等服务端就绪
  for _ in $(seq 1 30); do
    if python3 -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',$PORT))==0 else 1)" 2>/dev/null; then
      break
    fi
    sleep 0.2
  done
  "$OUT/ws_probe" "ws://127.0.0.1:$PORT/" || fail=1
fi

printf '\n'
if [ "$fail" -eq 0 ]; then
  printf '\033[32m全部测试通过\033[0m\n'
else
  printf '\033[31m存在失败项，见上方输出\033[0m\n'
fi
exit "$fail"
