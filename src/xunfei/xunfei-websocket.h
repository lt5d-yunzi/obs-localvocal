/**
 * xunfei-websocket.h
 *
 * 最小可用的 WebSocket（RFC 6455）客户端，支持 ws:// 与 wss://。
 *
 * 为什么手写而不复用工程里的 libcurl：
 *  - 链接的 libcurl 未必启用 WebSocket 支持（实测系统 curl 8.7.1 返回
 *    "Unsupported protocol"），依赖它会让插件在部分用户机器上直接不可用。
 *  - 讯飞 RTASR 只需要「连接 / 发文本 / 发二进制 / 收文本」这几件事，
 *    自己实现完全可控，且不挑构建环境。
 *
 * TLS 由 OpenSSL 提供（工程通过 BuildMyCurl.cmake 已经依赖 OpenSSL）。
 */

#ifndef XUNFEI_WEBSOCKET_H
#define XUNFEI_WEBSOCKET_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace xunfei {

struct WsFrame {
	enum Opcode { TEXT = 0x1, BINARY = 0x2, CLOSE = 0x8, PING = 0x9, PONG = 0xA } opcode = TEXT;
	bool fin = true;
	std::string payload;
};

struct WsResult {
	bool ok = false;
	std::string error;
};

class WebSocketClient {
public:
	/** 收到一条完整消息（已处理分片与 ping/pong）时回调 */
	using MessageCallback = std::function<void(const WsFrame &frame)>;
	/** 连接断开 / 出错时回调，参数为可读原因 */
	using CloseCallback = std::function<void(const std::string &reason)>;

	WebSocketClient();
	~WebSocketClient();

	WebSocketClient(const WebSocketClient &) = delete;
	WebSocketClient &operator=(const WebSocketClient &) = delete;

	/**
	 * 建立连接（含 TLS 握手与 WebSocket Upgrade）。
	 * @param url      形如 wss://rtasr.xfyun.cn/v1/ws?appid=..&ts=..&signa=..
	 * @param headers  额外请求头（如 Origin），可空
	 * @param timeout_ms 连接与 TLS 握手的超时时间
	 */
	WsResult connect(const std::string &url, const std::vector<std::string> &headers = {},
			 int timeout_ms = 10000);

	/** 发送一条文本消息（内部自动加掩码） */
	WsResult send_text(const std::string &text);
	/** 发送一条二进制消息（讯飞音频帧用这个） */
	WsResult send_binary(const void *data, size_t len);
	/** 发送 Close 帧 */
	WsResult send_close(uint16_t code = 1000, const std::string &reason = "");

	/**
	 * 阻塞读取并分派消息。收到一条完整应用层消息时调用 on_message。
	 * @return false 表示连接已结束或出错（原因写入 error_out）
	 */
	bool poll(int timeout_ms, MessageCallback on_message, std::string *error_out = nullptr);

	/** 关闭连接（幂等） */
	void close();

	bool is_connected() const { return connected_; }

	/** 是否校验服务端证书（默认开启；仅在调试时才应关闭） */
	void set_verify_peer(bool v) { verify_peer_ = v; }

	/** 最近一次错误描述 */
	const std::string &last_error() const { return last_error_; }

	/* ---- 以下为静态协议工具，供单元测试直接调用 ---- */

	/** 计算 Sec-WebSocket-Accept 的值 */
	static std::string compute_accept_key(const std::string &client_key);
	/** 编码一个客户端帧（含掩码），测试用 */
	static std::string encode_frame(uint8_t opcode, const std::string &payload, bool fin = true,
					uint32_t mask_seed = 0x12345678u);
	/** 解析缓冲区中的一帧；返回 true 表示解析出一帧，consumed 为消耗字节数 */
	static bool decode_frame(const std::string &buf, WsFrame &out, size_t &consumed,
				 std::string *error_out = nullptr);

private:
	WsResult send_binary_op(const void *data, size_t len, uint8_t opcode);
	bool read_available(int timeout_ms, std::string *error_out);
	bool tls_write_all(const void *data, size_t len, std::string *error_out);
	int raw_recv(void *buf, size_t len, std::string *error_out);

	void *tls_ = nullptr; // SSL*
	/**
	 * 套接字句柄：POSIX 是 int，Windows 是 SOCKET（无符号句柄）。
	 * 这里用 intptr_t 存，避免在头文件里引入平台头文件；
	 * -1 在两种平台都表示「无效」。
	 */
	intptr_t fd_ = -1;
	bool connected_ = false;
	bool verify_peer_ = true;
	std::string recv_buf_;
	std::string last_error_;
};

} // namespace xunfei

#endif // XUNFEI_WEBSOCKET_H
