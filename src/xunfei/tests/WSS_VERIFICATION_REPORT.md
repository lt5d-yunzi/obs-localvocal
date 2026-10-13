# wss://(TLS) 路径验证报告

- 验证对象：`vendor/localvocal-src/src/xunfei/xunfei-websocket.cpp`（RFC6455 + OpenSSL TLS 客户端）
- 验证时间：2026-10-13
- 验证者：子代理（C++ 网络协议验证）
- 重要声明：**本次没有改动 `vendor/localvocal-src/src/xunfei/` 下任何产品代码**
  （`xunfei-websocket.cpp` mtime 仍为 20:33、`xunfei-utils.cpp` 20:35、`sha256.cpp` Sep 9）。
  只新增/修改了 `tests/` 下的测试资产。

## 0. 环境

| 项 | 值 |
|---|---|
| 编译器 | Apple clang++ (`clang++`, `-std=c++17 -O1 -Wall`)，零告警 |
| SDK | `/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk`（按要求避开损坏的 27.0） |
| OpenSSL（客户端链接） | `/opt/homebrew/opt/openssl@3` = OpenSSL 3.6.4 |
| 系统 `openssl` CLI | `/usr/bin/openssl` = LibreSSL 3.3.6（支持 `req -addext`，自签证书生成正常） |
| 系统 python3 | 3.9.6，ssl = LibreSSL 2.8.3 → **服务端最高 TLS1.2** |
| 补充 TLS1.3 服务端 | `/opt/homebrew/bin/python3.14`，ssl = OpenSSL 4.0.3（用于覆盖 TLS1.3） |
| 外网 | 直连可用，**不需要代理**（`http://127.0.0.1:7897` 上无监听进程）；客户端不支持代理，也未用到 |

编译（探针，照用任务给定配方）：

```bash
cd /Users/yunzi/Desktop/Deepseek_Harness/obs-xunfei-translator
SSL_PREFIX=/opt/homebrew/opt/openssl@3
SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
clang++ -std=c++17 -O1 -Wall -o build/wss_probe tests/wss_client_probe.cpp \
  vendor/localvocal-src/src/xunfei/xunfei-websocket.cpp \
  vendor/localvocal-src/src/xunfei/xunfei-utils.cpp \
  vendor/localvocal-src/src/model-utils/sha256.cpp \
  -I vendor/localvocal-src/src -I vendor/localvocal-src/src/xunfei -I "$SSL_PREFIX/include" \
  -isysroot "$SDK" -L "$SSL_PREFIX/lib" -lssl -lcrypto
```

## 1. 结论表

| # | 验证项 | 结果 | 关键证据 |
|---|---|---|---|
| a | `wss://127.0.0.1:9912/` + `set_verify_peer(false)`：握手 + text 回显 + 1280B 二进制回显 + 70000B 大帧 + close | **通过** | 探针 9 项全 PASS，`ok=true` 耗时 24ms；服务端日志 `TLS=TLSv1.2 cipher=ECDHE-RSA-CHACHA20-POLY1305`、`收到二进制音频共 1280 字节` |
| b | `wss://127.0.0.1:9912/` + 开启证书校验（自签）→ 预期失败 | **通过（反向验证成立）** | `error="TLS handshake failed: error:0A000086:SSL routines::certificate verify failed"`；服务端同步记录 `TLSV1_ALERT_UNKNOWN_CA`，证明客户端真的发起了校验而不是静默跳过 |
| c | `wss://localhost:9912/` + 开启校验 + `SSL_CERT_FILE` 注入自签信任 | **通过（可做到，任务里的悲观假设不成立）** | `SSL_CERT_FILE=tests/tls/cert.pem` → `ok=true`，9 项全 PASS；换成无关 CA 立刻失败（见 c-neg） |
| c-neg1 | 证书只含 `DNS:localhost` 却用 IP 连接 + 注入该证书 | **通过（主机名校验确实生效）** | 连接失败；`s_client` 给出 `verify error:num=62:hostname mismatch` |
| c-neg2 | 注入无关 CA（`scratch/other-ca.pem`） | **通过（链校验确实生效）** | 连接失败；`s_client` 给出 `verify error:num=18:self-signed certificate` |
| d | 独立工具佐证本地服务端 TLS 正常 | **通过** | `s_client`：`Verification: OK` / `Verified peername: localhost` |
| d′ | TLS1.3 覆盖（本地 9914，python3.14/OpenSSL 4.0.3） | **通过** | 服务端日志 `TLS=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384`；noverify 与 verify+SSL_CERT_FILE 各 9 项全 PASS |
| e | 真实讯飞端点 `wss://rtasr.xfyun.cn/v1/ws?...`（FAKE 凭证，**开启校验，直连**） | **通过** | TLS 握手 276~616ms 成功（说明真实 CA 校验链路 OK），服务端返回 101 后下发 `{"action":"error","code":"10105","desc":"illegal access|ts expired",...}` 并 close；`s_client` 显示证书链 `GlobalSign Root CA - R3 → GlobalSign RSA OV SSL CA 2018 → CN=*.xfyun.cn`，`Verification: OK` |
| f | 未验证：带真实 appid/secret 的 RTASR 会话（音频上传、识别结果） | **未验证** | 无有效凭证 |
| g | 未验证：与讯飞之间的 TLS1.3（`s_client` 与讯飞协商到的是 TLSv1.2） | **未验证** | 未知 Tengine 是否支持 1.3；客户端侧 TLS1.3 已用本地 9914 覆盖 |
| h | 未验证：代理出口（`xunfei-websocket.cpp` 不支持代理） | **未验证（且直连本来也不需要）** | 7897 端口无监听；直连成功 |

## 2. 真实命令与真实输出（节选，全部为实跑）

### a) 关闭校验，全流程

```bash
./build/wss_probe "wss://127.0.0.1:9912/" noverify
```
```
== connect 结果: ok=true error="" (耗时 24ms)
[PASS] TLS + WebSocket 握手成功
[PASS] 发送文本帧 hello-xunfei
== 文本回显: "echo:hello-xunfei"
[PASS] 收到文本回显且内容与 ws:// 路径一致
[PASS] 发送 1280 字节二进制帧
== 二进制回显: 5 字节, 格式='B' + uint32BE, 长度字段=1280
[PASS] 二进制回显长度字段正确（1280 字节完整往返）
[PASS] 回显格式与 ws_echo_server.py 一致（b'B' + uint32BE）
== 大帧回显: 70005 字节（期望 70005）
[PASS] 70000 字节文本帧往返（127 长度编码 + 分片读取）
[PASS] 发送 close 帧
[PASS] close 后连接状态为断开
结果: 全部通过（0 项失败）
```
服务端（9912）日志：
```
[wss] TLS + WS 握手完成 (TLS=TLSv1.2 cipher=ECDHE-RSA-CHACHA20-POLY1305)
[wss] 会话结束，收到二进制音频共 1280 字节
```

### b) 开启校验 → 真实失败

```bash
./build/wss_probe "wss://127.0.0.1:9912/" verify --expect-fail
```
```
== connect 结果: ok=false error="TLS handshake failed: error:0A000086:SSL routines::certificate verify failed" (耗时 26ms)
[PASS] 连接按预期失败（校验生效），真实错误已在上方输出
```
服务端 9912 同时打印（说明是客户端主动 abort，而非服务端拒绝）：
```
[wss] TLS 握手失败: [SSL: TLSV1_ALERT_UNKNOWN_CA] tlsv1 alert unknown ca
```

### c) 用 SSL_CERT_FILE 注入自签信任（能成功）

```bash
SSL_CERT_FILE="$PWD/tests/tls/cert.pem" ./build/wss_probe "wss://localhost:9912/" verify
```
```
== 环境: SSL_CERT_FILE=/Users/.../tests/tls/cert.pem SSL_CERT_DIR=(unset)
== connect 结果: ok=true error="" (耗时 42ms)
... 9 项全 PASS ...
```

补充反证（确保“信任注入”不是“跳过校验”）：

```bash
# 9931 号服务端用的是只含 DNS:localhost 的证书，这里用 IP 访问
SSL_CERT_FILE="$PWD/tests/tls/scratch/dnsonly-cert.pem" ./build/wss_probe "wss://127.0.0.1:9913/" verify --expect-fail
# -> ok=false  TLS handshake failed: error:0A000086:SSL routines::certificate verify failed
#    同一张证书用 localhost 访问则 ok=true

SSL_CERT_FILE="$PWD/tests/tls/scratch/other-ca.pem" ./build/wss_probe "wss://localhost:9912/" verify --expect-fail
# -> ok=false  TLS handshake failed: error:0A000086:SSL routines::certificate verify failed
```

s_client 交叉确认失败原因：
```
verify error:num=62:hostname mismatch        # dnsonly 证书 + IP 访问
verify error:num=18:self-signed certificate  # 无关 CA
```

**机制说明**：`SSL_CTX_set_default_verify_paths()` 内部走 `X509_STORE_set_default_paths()`，
而 OpenSSL 的 “default” 文件/目录本身就是由 `SSL_CERT_FILE` / `SSL_CERT_DIR` 环境变量指定的，
所以自签证书可以通过环境变量注入信任 —— 任务里“可能无法注入”的担心不成立（已实测）。
生产环境连讯飞是正规 CA（GlobalSign），走系统默认信任库，不需要任何环境变量，已直连实测通过。

### d) 独立工具佐证 + e) 真实端点

```bash
echo | /opt/homebrew/opt/openssl@3/bin/openssl s_client -connect 127.0.0.1:9912 \
  -servername localhost -CAfile tests/tls/cert.pem -verify_hostname localhost -brief
#  -> CONNECTION ESTABLISHED / Protocol version: TLSv1.2 / Verification: OK / Verified peername: localhost

./build/wss_probe "wss://rtasr.xfyun.cn/v1/ws?appid=FAKE&ts=1&signa=FAKE" verify --listen-only=8000 --timeout=8000
```
```
== connect 结果: ok=true error="" (耗时 616ms)
[PASS] TLS + WebSocket 握手成功
== 收到帧 opcode=0x1 fin=1 len=119 payload="{"action":"error","code":"10105","data":"","desc":"illegal access|ts expired","sid":"rta029844ed@dxa7351e297351000100"}"
== 连接结束: server sent close frame
结果: 连接与监听完成（0 项失败）
```

不带本客户端、纯 openssl 的原始 HTTP 取证：
```bash
cat /tmp/ws_req.txt | /opt/homebrew/opt/openssl@3/bin/openssl s_client \
  -connect rtasr.xfyun.cn:443 -servername rtasr.xfyun.cn -quiet -ign_eof
```
```
depth=2 OU=GlobalSign Root CA - R3, O=GlobalSign, CN=GlobalSign
verify return:1
depth=1 C=BE, O=GlobalSign nv-sa, CN=GlobalSign RSA OV SSL CA 2018
verify return:1
depth=0 C=CN, ST=Anhui, L=Hefei, O=科大讯飞股份有限公司, CN=*.xfyun.cn
verify return:1
HTTP/1.1 101 Switching Protocols
Server: Tengine
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
...{"action":"error","code":"10105",...,"desc":"illegal access|ts expired"...}...
```
（`s3pPLMBiTxaQ9kYGzzhZRbK+xOo=` 正是 RFC6455 §1.3 给出的示例 key 对应的正确 Accept，
说明握手报文解析无误；两次会话的 `sid` 不同，确认是两次真实连接。）

## 3. 发现的问题

### F1（测试资产，已修）`tests/tls/wss_echo_server.py` 二进制回显格式与 `ws_echo_server.py` 不一致

- 现象：`ws_echo_server.py:120` 回 `b"B" + struct.pack(">I", len)`（5 字节），
  而 `wss_echo_server.py:105` 回 `struct.pack(">I", len)`（4 字节），无 `'B'` 前缀。
- 影响：任何复用 `ws_client_probe.cpp` 断言的服务端一致性检查在 wss 上必然 FAIL
  （探针首次运行即报 `[FAIL] 回显格式与 ws_echo_server.py 一致（b'B' + uint32BE）`，
  但长度字段 1280 正确，说明数据传输本身没问题，纯粹是服务端格式不统一）。
- 处置：已在 `tests/tls/wss_echo_server.py` 改成 `b"B" + struct.pack(">I", ...)`（只改测试服务端，未动产品代码）。
  修复后同一探针 9 项全 PASS。
- 顺带补齐：docstring 声称“行为与 ws_echo_server.py 一致”，但原实现缺少
  `payload == b'__ping__'` → 主动发 ping 的行为；已一并补齐，并在握手完成时打印
  `TLS=<版本> cipher=<套件>`（便于确认走的是 TLS 而不是明文）。

### F2（产品代码 bug，仅报告未修改）`xunfei-websocket.cpp` 大消息分片首帧 opcode 违反 RFC 6455

- 位置：`xunfei-websocket.cpp:444`
  ```cpp
  const uint8_t op = (take == len) ? opcode : 0x0; // 后续帧 opcode=continuation
  ```
  条件用错了：应该是“第一帧”（如 `p == 起始地址`），而不是 `take == len`。
  当 `len > 512KB` 时，第一帧 `take == kChunk != len`，于是首帧 opcode 被写成 `0x0`（continuation），
  而正确值应为 `0x2`(binary)/`0x1`(text)。RFC 6455 §5.4 要求分片消息首帧必须携带消息 opcode，
  严格服务端会以 1002 协议错误断开。
- 复现（帧级取证，`--send-only` + `tests/raw_ws_capture.py`）：
  ```bash
  cd tests && python3 -u raw_ws_capture.py 9915 &
  ./build/wss_probe "ws://127.0.0.1:9915/" noverify --send-only=600000
  ```
  抓包结果：
  ```
  [capture] 帧#1: fin=0 rsv=0 opcode=0x0 mask=1 len=524288 head_hex=00ff0000000000080000bb39a1ca
  [capture] 帧#2: fin=1 rsv=0 opcode=0x0 mask=1 len=75712  head_hex=80ff00000000000127c023814952
  ```
  帧#1 应为 `opcode=0x2`（`head_hex` 首字节应为 `02` 而不是 `00`）。
  对照组 —— 1000 字节（单帧路径）是正确的：
  ```
  [capture] 帧#1: fin=1 rsv=0 opcode=0x2 mask=1 len=1000 head_hex=82fe03e8d93e13a9
  ```
- 现实影响：**低**。讯飞 RTASR 音频帧是 1280 字节，走单帧路径不受影响；
  只有 >512KB 的单条 `send_text`/`send_binary` 才会触发。属于确实存在、但当前业务用不到的正确性缺陷。
- 未修改原因：非崩溃级缺陷，按任务要求只报告。

### F3（产品代码缺陷，仅报告未修改）`connect()` 的 `timeout_ms` 不约束 TCP 连接阶段

- 位置：`xunfei-websocket.cpp:192-233`。注释写“非阻塞 connect + poll 以实现超时”，
  但代码从未 `fcntl(O_NONBLOCK)`，也没有在 connect 外层 poll，只设了
  `SO_RCVTIMEO/SO_SNDTIMEO` —— 这两个选项对 `connect(2)` 无效（macOS 上尤其如此）。
- 复现：
  ```bash
  time ./build/wss_probe "wss://192.0.2.1:443/" verify --timeout=3000
  ```
  ```
  == connect 结果: ok=false error="TCP connect failed to 192.0.2.1:443" (耗时 75074ms)
  real 1m15.096s
  ```
  请求 3 秒超时，实际阻塞 75 秒（系统默认 TCP 连接超时）。
  对插件体验的影响：网络不可达时 UI 可能卡住 ~75s 而非 10s。

### F4（诊断能力，静态阅读发现，未做动态复现）

- `xunfei-websocket.cpp:230`：`"TCP connect failed to host:port"` 未带 `errno`，无法区分超时/拒绝/无路由。
- `xunfei-websocket.cpp:247`：`SSL_CTX_set_default_verify_paths(ctx)` 返回值未检查，
  信任库加载失败时会退化成“所有证书都校验失败”，且错误信息只有笼统的 `certificate verify failed`。
- `xunfei-websocket.cpp:314-320`：`raw_recv()` 返回 -2（`SSL_ERROR_WANT_READ`，通常由
  `SO_RCVTIMEO` 触发）时会走到 `n <= 0` 分支，拼出的错误是 `"recv handshake response failed: "`（冒号后为空），
  对排查不友好。
  以上三条均为代码阅读所得，未构造动态用例，标注为静态发现。

## 4. 新增/修改的测试资产

| 路径 | 说明 |
|---|---|
| `tests/wss_client_probe.cpp` | 新增：wss 探针。支持 `verify\|noverify`、`--expect-fail`（反向验证）、`--listen-only[=ms]`（真实端点取证）、`--send-only=N`（帧级取证） |
| `tests/raw_ws_capture.py` | 新增：帧级取证服务端，打印每帧 fin/opcode/mask/len 与头部 hex |
| `tests/tls/wss_echo_server.py` | 修改（测试服务端，非产品代码）：修二进制回显格式、补 `__ping__`、打印协商 TLS 版本 |
| `tests/tls/cert.pem` / `key.pem` | 运行时自签证书产物（CN=localhost，SAN=DNS:localhost,IP:127.0.0.1） |
| `tests/tls/scratch/` | 负向用例证书：`dnsonly-cert.pem`（仅 DNS，用于主机名不匹配）、`other-ca.pem`（无关 CA） |
| `build/wss_probe`、`build/ws_probe` | 编译产物（可删，用第 0 节命令重建） |

验证期间后台仍在运行：9912（TLS1.2 自签）、9913（仅 DNS 的证书）、9914（TLS1.3）、9911（既有明文服务端）。
