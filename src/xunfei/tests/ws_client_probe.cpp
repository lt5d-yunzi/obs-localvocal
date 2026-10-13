/**
 * ws_client_probe.cpp
 *
 * 端到端验证 xunfei-websocket.cpp：
 * 连接本地回显服务端，走完整「握手 -> 文本发送 -> 回显接收 -> 二进制发送
 * -> ping/pong -> close」流程。
 *
 * 编译（不依赖 OBS）：
 *   clang++ -std=c++17 -O1 -o /tmp/ws_probe ws_client_probe.cpp \
 *     <src>/xunfei/xunfei-websocket.cpp <src>/xunfei/xunfei-utils.cpp \
 *     <src>/model-utils/sha256.cpp -I <src> -I <openssl>/include -lssl -lcrypto
 */

#include "xunfei-websocket.h"

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

using namespace xunfei;

int main(int argc, char **argv)
{
	const std::string url = argc > 1 ? argv[1] : "ws://127.0.0.1:9911/";
	int failures = 0;

	auto expect = [&](bool cond, const std::string &name) {
		printf("[%s] %s\n", cond ? "PASS" : "FAIL", name.c_str());
		if (!cond)
			++failures;
	};

	WebSocketClient ws;
	const WsResult conn = ws.connect(url);
	expect(conn.ok, "连接到 " + url + (conn.ok ? "" : " 失败: " + conn.error));
	if (!conn.ok)
		return 1;

	// 1) 文本回显
	std::vector<std::string> received;
	const WsResult sent = ws.send_text("hello-xunfei");
	expect(sent.ok, "发送文本帧");

	for (int i = 0; i < 40 && received.empty(); ++i) {
		std::string err;
		ws.poll(200, [&](const WsFrame &f) {
			if (f.opcode == WsFrame::TEXT)
				received.push_back(f.payload);
		}, &err);
	}
	expect(!received.empty() && received[0] == "echo:hello-xunfei",
	       "收到文本回显（内容一致）");

	// 2) 二进制回显（模拟音频帧，1280 字节）
	std::vector<uint8_t> audio(1280);
	for (size_t i = 0; i < audio.size(); ++i)
		audio[i] = static_cast<uint8_t>(i & 0xFF);
	const WsResult bsent = ws.send_binary(audio.data(), audio.size());
	expect(bsent.ok, "发送 1280 字节二进制帧");

	std::vector<std::string> bin_reply;
	for (int i = 0; i < 40 && bin_reply.empty(); ++i) {
		std::string err;
		ws.poll(200, [&](const WsFrame &f) {
			if (f.opcode == WsFrame::BINARY)
				bin_reply.push_back(f.payload);
		}, &err);
	}
	expect(!bin_reply.empty() && bin_reply[0].size() == 5 &&
		       static_cast<uint8_t>(bin_reply[0][0]) == 'B' && bin_reply[0][1] == 0x00 &&
		       bin_reply[0][2] == 0x00 && bin_reply[0][3] == 0x05 &&
		       static_cast<uint8_t>(bin_reply[0][4]) == 0x00,
	       "收到二进制回显且长度字段正确（1280 -> 0x00000500）");

	// 3) 大帧（跨 64KB，验证 127 长度编码路径）
	std::string big(70000, 'Q');
	ws.send_text(big);
	std::vector<std::string> big_reply;
	for (int i = 0; i < 60 && big_reply.empty(); ++i) {
		std::string err;
		ws.poll(200, [&](const WsFrame &f) {
			if (f.opcode == WsFrame::TEXT && f.payload.size() > 1000)
				big_reply.push_back(f.payload);
		}, &err);
	}
	expect(!big_reply.empty() && big_reply[0] == "echo:" + big,
	       "70000 字节文本帧往返（127 长度编码 + 分片读取）");

	// 4) ping/pong：服务端收到 __ping__ 会主动发 ping，客户端应自动回 pong
	ws.send_text("__ping__");
	std::this_thread::sleep_for(std::chrono::milliseconds(300));
	std::string keep_err;
	bool still_alive = ws.poll(0, [](const WsFrame &) {}, &keep_err);
	expect(still_alive && ws.is_connected(), "服务端 ping 后连接仍存活（自动回 pong）");

	// 5) 关闭
	const WsResult cls = ws.send_close();
	expect(cls.ok, "发送 close 帧");
	ws.close();
	expect(!ws.is_connected(), "close 后连接状态为断开");

	// 6) 回归：>512KB 触发内部分片，首帧 opcode 必须是原 opcode（不是 continuation 0x0）
	//    （历史 bug：首帧被写成 0x0，严格服务端会以 1002 断开）
	{
		WebSocketClient big;
		const WsResult c2 = big.connect(url);
		expect(c2.ok, "分片回归：重新连接");
		if (c2.ok) {
			const size_t big_size = 600 * 1024; // 600KB > 512KB 分片阈值
			std::vector<uint8_t> payload(big_size, 0x5A);
			const WsResult bs = big.send_binary(payload.data(), payload.size());
			expect(bs.ok, "分片回归：发送 600KB 二进制帧");

			bool got_echo = false;
			for (int i = 0; i < 80 && !got_echo; ++i) {
				std::string err;
				big.poll(200, [&](const WsFrame &f) {
					if (f.opcode == WsFrame::BINARY && f.payload.size() >= 5 &&
					    static_cast<uint8_t>(f.payload[0]) == 'B')
						got_echo = true;
				}, &err);
			}
			// 服务端按 RFC6455 组装分片后才会回显；能收到回显即说明分片序列合法
			expect(got_echo, "分片回归：服务端接受分片并回显（首帧 opcode 正确）");
			big.close();
		}
	}

	// 7) 回归：TCP 连接超时必须被 timeout_ms 约束
	//    此前只设了 SO_RCVTIMEO/SNDTIMEO（对 connect 无效），连黑洞地址会阻塞约 75 秒
	{
		WebSocketClient dead;
		const auto t0 = std::chrono::steady_clock::now();
		const WsResult dc = dead.connect("ws://192.0.2.1:443/", {}, 2000); // TEST-NET-1，保证不可达
		const auto elapsed_ms =
			std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - t0)
				.count();
		expect(!dc.ok, "超时回归：不可达地址连接失败");
		expect(elapsed_ms < 10000,
		       "超时回归：耗时 " + std::to_string(elapsed_ms) +
			       "ms < 10000ms（timeout_ms 生效）");
		dead.close();
	}

	printf("\n端到端结果: %s（失败 %d 项）\n", failures == 0 ? "全部通过" : "有失败", failures);
	return failures == 0 ? 0 : 1;
}
