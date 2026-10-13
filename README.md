# 用讯飞接口的 OBS 实时字幕/翻译插件（基于 obs-localvocal 改造）

本目录是一次**从零到可构建源码**的改造：以 [obs-localvocal](https://github.com/royshil/obs-localvocal)（★1600+，活跃维护）为骨架，
把本地 whisper 语音识别替换为**讯飞实时语音转写（RTASR）**，并接入**讯飞机器翻译**，
从而实现「讯飞接口 + 开源 + 持续维护基座」的 OBS 实时双语字幕方案。

> 背景：另一个用讯飞接口的插件 [summershrimp/obs-auto-subtitle](https://github.com/summershrimp/obs-auto-subtitle) 虽然同时接了讯飞
> ASR + 讯飞翻译，但**代码自 2024-12 起停更**，35 个 fork 全部停在同期，构建基线还停在 OBS 30.0.2。
> 因此选择「改造活跃项目」这条路。

---

## 一、改了什么

### 1. 新增：`vendor/localvocal-src/src/xunfei/`（14 个文件，约 2400 行）

| 文件 | 职责 |
| :--- | :--- |
| `xunfei-utils.h/.cpp` | Base64 / SHA1 / **MD5** / HMAC-SHA1 / **HMAC-SHA256** / RFC1123 时间 / 语言代码映射。零外部依赖（SHA256 复用工程自带实现） |
| `xunfei-json.h/.cpp` | 极小 JSON 取值器（讯飞返回结构固定，避免为此引入 JSON 库） |
| `xunfei-websocket.h/.cpp` | **手写 WebSocket（RFC 6455）客户端 + OpenSSL TLS**，支持 ws/wss、掩码、分片、ping/pong、Accept 校验 |
| `xunfei-rtasr.h/.cpp` | 讯飞 RTASR 客户端：URL 鉴权、20 字节音频帧协议、结果解析（含「JSON 套 JSON」）、后台收发线程、3 秒音频队列上限 |
| `xunfei-translate.h/.cpp` | 讯飞机器翻译 `/v2/its` 客户端：`Digest` + `Authorization` 签名链、base64 文本、响应解析 |
| `xunfei-cloud.h/.cpp` | 把讯飞翻译接进 localvocal 的 `ITranslator` 体系（工厂桥接） |
| `xunfei-asr.h/.cpp` | 适配层：`OBS 音频 → 16kHz/mono → RTASR → 字幕`，复用既有 `set_text_callback` 输出链路 |

### 2. 修改：10 个既有文件（每处都有 `=== 讯飞` 注释标记）

| 文件 | 改动 |
| :--- | :--- |
| `CMakeLists.txt` | 新增 7 个源文件；新增 `find_package(OpenSSL)` 并链接 `OpenSSL::SSL/Crypto` |
| `src/transcription-filter-data.h` | 新增 `asr_engine` 枚举、讯飞凭证字段、`xunfei_ctx`、线程退出标志（用裸指针避免不完整类型） |
| `src/transcription-filter.cpp` | ① `filter_audio` 按引擎分流：讯飞模式直接把音频推给 RTASR，不加载本地模型；② 读取讯飞配置；③ 引擎切换时重启对应后端 |
| `src/transcription-filter-properties.cpp` | ① 新增「语音识别引擎」下拉框（本地模型 / 讯飞）；② 新增 AppId/ApiKey/标点/领域优化控件与可见性回调；③ 云翻译服务商列表新增「讯飞机器翻译」+ AppId 字段 |
| `src/whisper-utils/whisper-utils.cpp` | `start_whisper_thread_with_path` 支持讯飞分支（不建 VAD/模型，只起派发线程）；`shutdown_whisper_thread` 显式通知讯飞线程退出 |
| `src/whisper-utils/whisper-processing.cpp` | `whisper_loop` 新增讯飞分支：只做结果派发与字幕过期清理 |
| `src/translation/cloud-translation/translation-cloud.h/.cpp` | 配置结构新增 `app_id`；工厂新增 `xunfei` provider |
| `data/locale/en-US.ini`、`zh-CN.ini` | 新增 14+ 条中英文案（含讯飞机器翻译选项） |

### 3. 新增测试资产：`tests/`

- `run-protocol-tests.sh` —— 一键跑全部协议层测试
- `xunfei-selftest.cpp` —— 61 项单元自测
- `ws_client_probe.cpp` / `ws_echo_server.py` —— 明文 WebSocket 端到端（含分片、超时回归）
- `wss_client_probe.cpp` / `tls/wss_echo_server.py` —— TLS 端到端
- `raw_ws_capture.py` —— 帧级取证工具
- `tls/WSS_VERIFICATION_REPORT.md` —— TLS/wss 专项验证报告

---

## 二、验证到什么程度（全部为真实执行结果）

### ✅ 已完成

| 项目 | 结果 |
| :--- | :--- |
| 协议层单元自测 | **61/61 通过** |
| WebSocket 端到端（明文） | **14/14 通过**（含 600KB 分片回归、TCP 超时回归） |
| TLS/wss 端到端 | 通过：TLS1.2/TLS1.3、自签正/反向用例、主机名与链校验均生效 |
| **真实讯飞端点连通** | 通过：`wss://rtasr.xfyun.cn/v1/ws` 证书校验握手成功，服务端返回 `101` + `{"action":"error","code":"10105","desc":"illegal access\|ts expired"}`（假凭证，属预期） |
| 讯飞翻译签名链 | 对拍**外部独立实现**（Python + 独立 C 实现）的 canonical 向量，逐字节一致 |
| RTASR 鉴权链 | MD5/HMAC-SHA1 对拍 Python 独立计算 |
| 改动代码语法 | 用**真实 OBS 31.1.1 + Qt6 头文件**逐个文件检查，我的改动零错误 |
| 环境探测 | 发现并绕过本机 `MacOSX27.0.sdk` 的 `ld` 兼容问题 |

### ❌ 未完成（环境限制）

**插件二进制未在本机编译出来。** 原因：

- localvocal 的 macOS 构建链硬编码 Xcode 生成器（`cmake/macos/buildspec.cmake` 用 `-G Xcode`），
  而本机只装了 Command Line Tools，`cmake -G Xcode` 直接报 **`Xcode 1.5 not supported`**；
- 完整构建还需要先在线编译 obs-studio 31.1.1 本体（依赖 Xcode 或一个**复杂的 Makefiles 改造**），
  其后还要编译 whisper.cpp、CTranslate2、ONNX Runtime（小时级）。

这意味着：**协议层已充分验证，集成层的语法已用真实头文件验证，但「装进 OBS 点一下能用」这一步没有实机验证过。**

---

## 三、怎么用

### 安装（需要先得到插件二进制）

1. 用下面的构建方式之一产出 `.plugin`；
2. 放到 OBS 插件目录：
   - macOS：`/Library/Application Support/obs-studio/plugins/`
   - Windows：`C:\ProgramData\obs-studio\plugins\`
   - Linux：`~/.config/obs-studio/plugins/`

### 配置（OBS 里）

1. 给音频源添加「本地语音转录 / LocalVocal」滤镜；
2. 在 **转录** 组里把 **语音识别引擎** 选为「**讯飞实时语音转写（云端）**」；
3. 填 **讯飞 AppId** 与 **ApiKey**（需在 <https://console.xfyun.cn/services/rta> 开通**实时语音转写**服务）；
4. 新建一个「文本（GDI+/Freetype2）」源，在滤镜里把它设为**输出目的地**；
5. 需要翻译时，展开 **云翻译** 组：
   - 服务商选「**讯飞机器翻译**」
   - 填 AppId / APIKey / APISecret（<https://console.xfyun.cn/services/its>）
   - 选目标语言、把「译文输出目的地」指向另一个文本源 → 即得**双语字幕**。

> 讯飞 RTASR 当前只支持中文普通话，因此**源语言固定为中文**，翻译方向为「中 → 目标语言」。

### 构建

**方式 A（推荐，最省事）**：推到 GitHub 用项目自带的 CI（`.github/workflows/push.yaml`），
会自动产出 Windows / macOS / Linux 安装包——这条流程是原项目长期在跑的。

**方式 B（本机 macOS，需装完整 Xcode）**：

```bash
cd vendor/localvocal-src
export https_proxy=http://127.0.0.1:7897 http_proxy=http://127.0.0.1:7897   # 需要拉依赖时
cmake -S . -B build -G Xcode \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_OSX_SYSROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
  -DCODESIGN_IDENTITY="-"
cmake --build build --config RelWithDebInfo
```

**方式 C（Linux）**：`-G Ninja -DUSE_SYSTEM_CURL=true -DUSE_SYSTEM_ICU=true`，最接近 CI 环境。

### 跑测试

```bash
bash tests/run-protocol-tests.sh     # 61 项单元 + 14 项端到端
```

---

## 四、已知限制

1. **未实机验证**：插件未在本机产出二进制，`filter_audio → RTASR → 字幕` 这条完整链路尚未在真实 OBS 会话里跑过。
2. **仅中文**：讯飞 RTASR 只支持中文普通话；多语言识别需换讯飞「语音听写」或其它引擎。
3. **讯飞翻译语种有限**：机器翻译短码支持 `cn/en/ja/ko/fr/es/ru/ar/th/yue` 等，界面上的目标语言若超出会被拒绝并记录日志。
4. **音频帧节奏固定**：按 40ms（1280 字节）一帧推送，与讯飞建议一致；网络抖动时最多缓存 3 秒音频，超出丢最旧帧以保实时性。
5. **中途改凭证需重选引擎**：修改 AppId/ApiKey 后，切一次引擎或重开滤镜才会重连。

---

## 五、过程中修掉的真 bug（都有测试兜底）

| 来源 | 问题 | 修复 |
| :--- | :--- | :--- |
| 自测发现 | `rfc1123_utc_now()` 的 `snprintf` 参数错位（漏传星期），导致周五输出的日期串长度不对 → 讯飞签名会失败 | 修正参数顺序 |
| 自测发现 | `JP` 未映射到讯飞 `ja` | 补 `jp`/`kr` 别名 |
| 语法检查发现 | `resample_info.speakers` 是枚举 `speaker_layout`，我错当整数赋值；且 OBS 音频是 **planar** 格式 | 改用 `convert_speaker_layout()` + `AUDIO_FORMAT_FLOAT_PLANAR` |
| 语法检查发现 | `xf_push_audio` 参数类型与 `obs_audio_data.data`（`uint8_t*`）不符 | 统一为 `const uint8_t *const *` |
| 语法检查发现 | `unique_ptr<不完整类型>` 析构报错；ASR 回调用了 3 参数签名但需传 priv | 改裸指针 + 用 `obs_property_set_modified_callback2` |
| 子代理报告 | WebSocket 分片首帧 opcode 被误写成 continuation（>512KB 时违反 RFC 6455） | 用 `first` 标志判断，并加 600KB 回归用例 |
| 子代理报告 | TCP 连接超时不受 `timeout_ms` 约束（实测阻塞 75 秒） | 改非阻塞 connect + `poll` + `SO_ERROR`，回归实测 2.0 秒 |
| 子代理报告 | `SSL_CTX_set_default_verify_paths` 返回值未检查、错误串缺 errno | 逐项补齐 |

---

## 与上游的关系

本仓库是 [royshil/obs-localvocal](https://github.com/royshil/obs-localvocal) 的改造分支（fork），
上游原始 README 保留在 [`README-UPSTREAM.md`](./README-UPSTREAM.md)。

- 上游地址：https://github.com/royshil/obs-localvocal
- 本分支改动：见上文「一、改了什么」
- 同步上游更新：

```bash
git remote add upstream https://github.com/royshil/obs-localvocal.git
git fetch upstream
git merge upstream/master     # 冲突点多集中在 transcription-filter*.cpp 的引擎分流处
```

推送本分支到自己的 fork 即会触发上游自带的 CI（`.github/workflows/push.yaml`），
在 Actions 里产出 Windows / macOS / Linux 安装包。
