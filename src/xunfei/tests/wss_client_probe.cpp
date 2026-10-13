/**
 * wss_client_probe.cpp
 *
 * 专门验证 xunfei-websocket.cpp 的 **wss://(TLS) 路径**，与 ws_client_probe.cpp
 * 互补（后者覆盖 ws:// 明文路径）。不改动 vendor/ 下的产品代码。
 *
 * 用法:
 *   wss_client_probe <url> [选项]
 *
 * 选项:
 *   verify           开启证书校验（默认，等于产品默认行为）
 *   noverify         关闭证书校验 -> ws.set_verify_peer(false)
 *   --expect-fail    预期连接失败：连接失败即 PASS（用于反向验证校验生效）
 *   --listen-only[=ms]  连接成功后不发送业务数据，只监听并打印收到的帧（默认 5000ms）
 *   --send-only=N    连接成功后只发一条 N 字节二进制消息然后关闭（帧级取证用）
 *   --timeout=ms     连接超时，默认 10000
 *
 * 退出码: 0 = 全部 PASS，1 = 有 FAIL，2 = 参数错误
 *
 * 编译（照抄任务给定的配方）:
 *   SSL_PREFIX=/opt/homebrew/opt/openssl@3
 *   SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
 *   clang++ -std=c++17 -O1 -Wall -o /tmp/wss_probe tests/wss_client_probe.cpp \
 *     vendor/localvocal-src/src/xunfei/xunfei-websocket.cpp \
 *     vendor/localvocal-src/src/xunfei/xunfei-utils.cpp \
 *     vendor/localvocal-src/src/model-utils/sha256.cpp \
 *     -I vendor/localvocal-src/src -I vendor/localvocal-src/src/xunfei \
 *     -I "$SSL_PREFIX/include" -isysroot "$SDK" -L "$SSL_PREFIX/lib" -lssl -lcrypto
 */

#include "xunfei-websocket.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace xunfei;

static int g_failures = 0;

static void expect(bool cond, const std::string &name)
{
	printf("[%s] %s\n", cond ? "PASS" : "FAIL", name.c_str());
	if (!cond)
		++g_failures;
}

static uint32_t be32(const std::string &s, size_t off)
{
	return (static_cast<uint32_t>(static_cast<uint8_t>(s[off])) << 24) |
	       (static_cast<uint32_t>(static_cast<uint8_t>(s[off + 1])) << 16) |
	       (static_cast<uint32_t>(static_cast<uint8_t>(s[off + 2])) << 8) |
	       static_cast<uint32_t>(static_cast<uint8_t>(s[off + 3]));
}

/** 轮询等待一条指定 opcode 的帧；返回是否等到 */
static bool wait_frame(WebSocketClient &ws, WsFrame::Opcode want, std::string &payload,
		       int tries = 50, int per_ms = 200)
{
	for (int i = 0; i < tries; ++i) {
		std::string err;
		bool got = false;
		if (!ws.poll(per_ms, [&](const WsFrame &f) {
			    if (f.opcode == want && !got) {
				    payload = f.payload;
				    got = true;
			    }
		    }, &err)) {
			printf("      (poll 提前结束: %s)\n", err.empty() ? "(no error)" : err.c_str());
			return false;
		}
		if (got)
			return true;
	}
	return false;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <url> [verify|noverify] [--expect-fail] "
				"[--listen-only[=ms]] [--timeout=ms]\n", argv[0]);
		return 2;
	}

	const std::string url = argv[1];
	bool verify = true;
	bool expect_fail = false;
	bool listen_only = false;
	int listen_ms = 5000;
	int timeout_ms = 10000;
	int send_only = 0;

	for (int i = 2; i < argc; ++i) {
		const std::string a = argv[i];
		if (a == "verify")
			verify = true;
		else if (a == "noverify")
			verify = false;
		else if (a == "--expect-fail")
			expect_fail = true;
		else if (a == "--listen-only")
			listen_only = true;
		else if (a.rfind("--listen-only=", 0) == 0)
			listen_only = true, listen_ms = atoi(a.c_str() + 14);
		else if (a.rfind("--timeout=", 0) == 0)
			timeout_ms = atoi(a.c_str() + 10);
		else if (a.rfind("--send-only=", 0) == 0)
			send_only = atoi(a.c_str() + 12);
		else {
			fprintf(stderr, "unknown option: %s\n", a.c_str());
			return 2;
		}
	}

	printf("== URL: %s\n", url.c_str());
	printf("== verify_peer: %s | expect_fail: %s | listen_only: %s | timeout: %dms\n",
	       verify ? "true" : "false", expect_fail ? "true" : "false",
	       listen_only ? "true" : "false", timeout_ms);
	const char *cf = getenv("SSL_CERT_FILE");
	const char *cd = getenv("SSL_CERT_DIR");
	printf("== 环境: SSL_CERT_FILE=%s SSL_CERT_DIR=%s\n", cf ? cf : "(unset)",
	       cd ? cd : "(unset)");

	WebSocketClient ws;
	ws.set_verify_peer(verify);

	const auto t0 = std::chrono::steady_clock::now();
	const WsResult conn = ws.connect(url, {}, timeout_ms);
	const long ms = static_cast<long>(
		std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
			.count());

	printf("== connect 结果: ok=%s error=\"%s\" (耗时 %ldms)\n", conn.ok ? "true" : "false",
	       conn.error.c_str(), ms);

	if (!conn.ok) {
		if (expect_fail) {
			expect(true, "连接按预期失败（校验生效），真实错误已在上方输出");
			printf("\n结果: 全部通过（反向验证成功）\n");
			return g_failures == 0 ? 0 : 1;
		}
		expect(false, "连接失败: " + conn.error);
		printf("\n结果: 有失败（%d 项）\n", g_failures);
		return 1;
	}

	expect(conn.ok, "TLS + WebSocket 握手成功");
	if (expect_fail) {
		// 本来预期失败却成功了 -> 反向验证不成立
		expect(false, "预期连接失败，但实际连接成功（证书校验可能未生效！）");
		ws.close();
		printf("\n结果: 有失败（%d 项）\n", g_failures);
		return 1;
	}

	if (send_only > 0) {
		// 只发一条指定长度的二进制消息，用于帧级取证（配合 raw_ws_capture.py）
		std::vector<uint8_t> payload(static_cast<size_t>(send_only), 0x5A);
		const WsResult r = ws.send_binary(payload.data(), payload.size());
		printf("== send_binary(%d) 结果: ok=%s error=\"%s\"\n", send_only,
		       r.ok ? "true" : "false", r.error.c_str());
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
		ws.send_close();
		ws.close();
		printf("\n结果: send-only 完成（%d 项失败）\n", g_failures);
		return g_failures == 0 ? 0 : 1;
	}

	if (listen_only) {
		const auto deadline = std::chrono::steady_clock::now() +
				      std::chrono::milliseconds(listen_ms);
		int frames = 0;
		while (std::chrono::steady_clock::now() < deadline) {
			std::string err;
			const bool alive = ws.poll(500, [&](const WsFrame &f) {
				++frames;
				printf("== 收到帧 opcode=0x%X fin=%d len=%zu payload=\"%s\"\n",
				       static_cast<unsigned>(f.opcode), f.fin ? 1 : 0,
				       f.payload.size(),
				       f.payload.size() > 4000 ? "(过长，截断)" :
								 f.payload.c_str());
			}, &err);
			if (!alive) {
				printf("== 连接结束: %s\n", err.empty() ? "(peer closed)" : err.c_str());
				break;
			}
		}
		printf("== 监听结束，共收到 %d 帧\n", frames);
		ws.close();
		printf("\n结果: 连接与监听完成（%d 项失败）\n", g_failures);
		return g_failures == 0 ? 0 : 1;
	}

	/* ---- a) 文本回显 ---- */
	const WsResult sent = ws.send_text("hello-xunfei");
	expect(sent.ok, "发送文本帧 hello-xunfei");
	std::string text;
	const bool got_text = wait_frame(ws, WsFrame::TEXT, text);
	printf("== 文本回显: \"%s\"\n", got_text ? text.c_str() : "(无)");
	expect(got_text && text == "echo:hello-xunfei", "收到文本回显且内容与 ws:// 路径一致");

	/* ---- b) 1280 字节二进制回显 ---- */
	std::vector<uint8_t> audio(1280);
	for (size_t i = 0; i < audio.size(); ++i)
		audio[i] = static_cast<uint8_t>(i & 0xFF);
	const WsResult bsent = ws.send_binary(audio.data(), audio.size());
	expect(bsent.ok, "发送 1280 字节二进制帧");

	std::string bin;
	const bool got_bin = wait_frame(ws, WsFrame::BINARY, bin);
	if (got_bin) {
		std::string fmt = "未知";
		uint32_t lenfield = 0;
		if (bin.size() == 5 && bin[0] == 'B') {
			fmt = "'B' + uint32BE";
			lenfield = be32(bin, 1);
		} else if (bin.size() == 4) {
			fmt = "uint32BE（无 'B' 前缀）";
			lenfield = be32(bin, 0);
		}
		printf("== 二进制回显: %zu 字节, 格式=%s, 长度字段=%u\n", bin.size(), fmt.c_str(),
		       lenfield);
		expect(got_bin && lenfield == 1280,
		       "二进制回显长度字段正确（1280 字节完整往返）");
		// ws_echo_server.py 的约定是 b'B' + uint32；TLS 版服务端若不一致，这里会暴露
		expect(bin.size() == 5 && bin[0] == 'B',
		       "回显格式与 ws_echo_server.py 一致（b'B' + uint32BE）");
	} else {
		expect(false, "未收到二进制回显");
	}

	/* ---- c) 大帧（跨 64KB，验证 127 长度编码 + TLS 分片读取） ---- */
	std::string big(70000, 'Q');
	ws.send_text(big);
	std::string big_reply;
	const bool got_big = wait_frame(ws, WsFrame::TEXT, big_reply, 80, 200);
	printf("== 大帧回显: %zu 字节（期望 %zu）\n", big_reply.size(), big.size() + 5);
	expect(got_big && big_reply == "echo:" + big,
	       "70000 字节文本帧往返（127 长度编码 + 分片读取）");

	/* ---- d) close ---- */
	const WsResult cls = ws.send_close();
	expect(cls.ok, "发送 close 帧");
	ws.close();
	expect(!ws.is_connected(), "close 后连接状态为断开");

	printf("\n结果: %s（%d 项失败）\n", g_failures == 0 ? "全部通过" : "有失败", g_failures);
	return g_failures == 0 ? 0 : 1;
}
