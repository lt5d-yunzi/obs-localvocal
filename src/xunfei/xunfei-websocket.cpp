#include "xunfei-websocket.h"
#include "xunfei-utils.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

/*
 * 跨平台 socket 头。
 * Windows（Winsock）与 POSIX 的头文件、错误码、close/poll 名称都不同，
 * 下面用一层薄薄的适配把这些差异收敛掉，业务代码只写一套。
 */
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace xunfei {

/* ==================== 跨平台 socket 适配层 ==================== */

#ifdef _WIN32
using xf_socket_t = SOCKET;
using xf_socklen_t = int;
static const xf_socket_t XF_INVALID_SOCKET = INVALID_SOCKET;
/** Windows 错误码取 WSAGetLastError()，语义与 errno 接近 */
static int xf_socket_errno()
{
	return WSAGetLastError();
}
static int xf_close_socket(xf_socket_t s)
{
	return closesocket(s);
}
/** 把 Win32 socket 设为非阻塞 */
static bool xf_set_nonblocking(xf_socket_t s, bool nonblocking)
{
	u_long mode = nonblocking ? 1UL : 0UL;
	return ioctlsocket(s, FIONBIO, &mode) == 0;
}
/** 一次性初始化 Winsock（进程内只需一次） */
[[maybe_unused]] static void xf_socket_global_init()
{
	static bool initialized = false;
	if (!initialized) {
		WSADATA wsa;
		WSAStartup(MAKEWORD(2, 2), &wsa);
		initialized = true;
	}
}
static const char *xf_socket_strerror(int err)
{
	static thread_local char buf[128];
	buf[0] = 0;
	FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
		       static_cast<DWORD>(err), 0, buf, sizeof(buf), nullptr);
	if (buf[0] == 0)
		snprintf(buf, sizeof(buf), "socket error %d", err);
	return buf;
}
#else
using xf_socket_t = int;
using xf_socklen_t = socklen_t;
static const xf_socket_t XF_INVALID_SOCKET = -1;
static int xf_socket_errno()
{
	return errno;
}
static int xf_close_socket(xf_socket_t s)
{
	return ::close(s);
}
static bool xf_set_nonblocking(xf_socket_t s, bool nonblocking)
{
	const int flags = fcntl(s, F_GETFL, 0);
	if (flags < 0)
		return false;
	// 注意：恢复阻塞时必须显式清掉 O_NONBLOCK 位，不能直接把 flags 传回去
	const int target = nonblocking ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
	return fcntl(s, F_SETFL, target) == 0;
}
[[maybe_unused]] static void xf_socket_global_init() {}
static const char *xf_socket_strerror(int err)
{
	return strerror(err);
}
#endif

#ifdef _WIN32
using xf_pollfd_t = WSAPOLLFD;
static int xf_poll(xf_pollfd_t *fds, unsigned long nfds, int timeout_ms)
{
	return WSAPoll(fds, nfds, timeout_ms);
}
#else
using xf_pollfd_t = struct pollfd;
static int xf_poll(xf_pollfd_t *fds, unsigned long nfds, int timeout_ms)
{
	return ::poll(fds, static_cast<nfds_t>(nfds), timeout_ms);
}
#endif

/** Windows 与 POSIX 的超时参数类型不同，这里是唯一的差异点 */
static void xf_set_socket_timeout(xf_socket_t s, int which, int timeout_ms)
{
#ifdef _WIN32
	const DWORD ms = static_cast<DWORD>(timeout_ms);
	setsockopt(s, SOL_SOCKET, which, reinterpret_cast<const char *>(&ms), sizeof(ms));
#else
	struct timeval tv;
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;
	setsockopt(s, SOL_SOCKET, which, &tv, sizeof(tv));
#endif
}

/* ============================ 协议工具 ============================ */

std::string WebSocketClient::compute_accept_key(const std::string &client_key)
{
	// RFC 6455: base64(sha1(key + GUID))
	return sha1_base64(client_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
}

std::string WebSocketClient::encode_frame(uint8_t opcode, const std::string &payload, bool fin,
					  uint32_t mask_seed)
{
	std::string out;
	out.reserve(payload.size() + 14);

	out += static_cast<char>((fin ? 0x80 : 0x00) | (opcode & 0x0F));

	const size_t len = payload.size();
	if (len < 126) {
		out += static_cast<char>(0x80 | static_cast<uint8_t>(len)); // 客户端必须掩码
	} else if (len <= 0xFFFF) {
		out += static_cast<char>(0x80 | 126);
		out += static_cast<char>((len >> 8) & 0xFF);
		out += static_cast<char>(len & 0xFF);
	} else {
		out += static_cast<char>(0x80 | 127);
		for (int i = 7; i >= 0; --i)
			out += static_cast<char>((static_cast<uint64_t>(len) >> (i * 8)) & 0xFF);
	}

	// 掩码：用简单的确定性伪随机，测试可复现
	uint8_t mask[4];
	uint32_t s = mask_seed ? mask_seed : 1u;
	for (int i = 0; i < 4; ++i) {
		s = s * 1664525u + 1013904223u;
		mask[i] = static_cast<uint8_t>((s >> 16) & 0xFF);
	}
	for (int i = 0; i < 4; ++i)
		out += static_cast<char>(mask[i]);
	for (size_t i = 0; i < len; ++i)
		out += static_cast<char>(static_cast<uint8_t>(payload[i]) ^ mask[i % 4]);

	return out;
}

bool WebSocketClient::decode_frame(const std::string &buf, WsFrame &out, size_t &consumed,
				   std::string *error_out)
{
	consumed = 0;
	if (buf.size() < 2) {
		if (error_out)
			*error_out = "need more data (header)";
		return false;
	}

	const uint8_t b0 = static_cast<uint8_t>(buf[0]);
	const uint8_t b1 = static_cast<uint8_t>(buf[1]);
	const bool fin = (b0 & 0x80) != 0;
	const uint8_t opcode = b0 & 0x0F;
	const bool masked = (b1 & 0x80) != 0;
	uint64_t len = b1 & 0x7F;
	size_t pos = 2;

	if (len == 126) {
		if (buf.size() < pos + 2) {
			if (error_out)
				*error_out = "need more data (len16)";
			return false;
		}
		len = (static_cast<uint8_t>(buf[pos]) << 8) | static_cast<uint8_t>(buf[pos + 1]);
		pos += 2;
	} else if (len == 127) {
		if (buf.size() < pos + 8) {
			if (error_out)
				*error_out = "need more data (len64)";
			return false;
		}
		len = 0;
		for (int i = 0; i < 8; ++i)
			len = (len << 8) | static_cast<uint8_t>(buf[pos + i]);
		pos += 8;
	}

	uint8_t mask[4] = {0, 0, 0, 0};
	if (masked) {
		if (buf.size() < pos + 4) {
			if (error_out)
				*error_out = "need more data (mask)";
			return false;
		}
		for (int i = 0; i < 4; ++i)
			mask[i] = static_cast<uint8_t>(buf[pos + i]);
		pos += 4;
	}

	if (buf.size() < pos + len) {
		if (error_out)
			*error_out = "need more data (payload)";
		return false;
	}

	out.opcode = static_cast<WsFrame::Opcode>(opcode);
	out.fin = fin;
	out.payload.assign(buf, pos, static_cast<size_t>(len));
	if (masked) {
		for (size_t i = 0; i < out.payload.size(); ++i)
			out.payload[i] = static_cast<char>(static_cast<uint8_t>(out.payload[i]) ^
							   mask[i % 4]);
	}

	consumed = pos + static_cast<size_t>(len);
	return true;
}

/* ============================ 构造/析构 ============================ */

WebSocketClient::WebSocketClient()
{
	// OpenSSL 1.1+ 自动初始化；显式调用对 1.0.2 兼容也无害
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_library_init();
	SSL_load_error_strings();
#endif
}

WebSocketClient::~WebSocketClient()
{
	close();
}

/* ============================ 连接 ============================ */

WsResult WebSocketClient::connect(const std::string &url, const std::vector<std::string> &headers,
				  int timeout_ms)
{
	WsResult res;
	close();

#ifdef _WIN32
	xf_socket_global_init();
#endif

	// 1) 解析 URL
	if (!starts_with(url, "wss://") && !starts_with(url, "ws://")) {
		res.error = std::string("unsupported scheme (expect ws:// or wss://): ") + url;
		last_error_ = res.error;
		return res;
	}
	const bool use_tls = starts_with(url, "wss://");
	std::string rest = url.substr(use_tls ? 6 : 5);

	// 分离 path?query 与 host[:port]
	std::string hostport = rest;
	std::string path = "/";
	const size_t slash = rest.find('/');
	if (slash != std::string::npos) {
		hostport = rest.substr(0, slash);
		path = rest.substr(slash);
	}

	std::string host = hostport;
	int port = use_tls ? 443 : 80;
	const size_t colon = hostport.rfind(':');
	if (colon != std::string::npos) {
		host = hostport.substr(0, colon);
		port = atoi(hostport.substr(colon + 1).c_str());
		if (port <= 0 || port > 65535) {
			res.error = std::string("invalid port in url: ") + url;
			last_error_ = res.error;
			return res;
		}
	}

	// 2) TCP 连接（带超时）
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	struct addrinfo *addrs = nullptr;
	const std::string port_str = std::to_string(port);
	const int gai = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &addrs);
	if (gai != 0 || addrs == nullptr) {
		// 注意：gai_strerror 在 WinSock 下返回 WCHAR*（宽字符），不能直接转 std::string，
		// 这里只带错误码，保证跨平台一致且不依赖平台字符宽度。
		res.error = std::string("DNS resolve failed for ") + host +
			    " (getaddrinfo error " + std::to_string(gai) + ")";
		last_error_ = res.error;
		return res;
	}

	xf_socket_t fd = XF_INVALID_SOCKET;
	int last_errno = 0;
	for (struct addrinfo *ai = addrs; ai != nullptr; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd == XF_INVALID_SOCKET) {
			last_errno = xf_socket_errno();
			continue;
		}

		int one = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&one),
			   sizeof(one));

		/*
		 * 真正的「带超时的 connect」：
		 *   1) 设为非阻塞，connect 会立刻返回「进行中」；
		 *   2) 用 poll 等可写至多 timeout_ms；
		 *   3) 用 SO_ERROR 判断连接是否真的成功；
		 *   4) 改回阻塞，后续 TLS/读写沿用阻塞语义。
		 * （此前只设了 SO_RCVTIMEO/SNDTIMEO，那两个对 connect 无效，
		 *   连不可达地址时会阻塞到系统默认超时，实测可达 75 秒。）
		 */
		xf_set_nonblocking(fd, true);

		int rc = ::connect(fd, ai->ai_addr, static_cast<xf_socklen_t>(ai->ai_addrlen));
		const int connect_err = xf_socket_errno();
#ifdef _WIN32
		const bool in_progress = (rc != 0) && (connect_err == WSAEWOULDBLOCK ||
						       connect_err == WSAEINPROGRESS);
#else
		const bool in_progress = (rc != 0) && (connect_err == EINPROGRESS);
#endif
		if (in_progress) {
			xf_pollfd_t pfd;
			pfd.fd = static_cast<decltype(pfd.fd)>(fd);
			pfd.events = POLLOUT;
			pfd.revents = 0;
			const int pr = xf_poll(&pfd, 1, timeout_ms);
			if (pr == 0) {
#ifdef _WIN32
				last_errno = WSAETIMEDOUT;
#else
				last_errno = ETIMEDOUT;
#endif
				xf_close_socket(fd);
				fd = XF_INVALID_SOCKET;
				continue;
			}
			if (pr < 0) {
				last_errno = xf_socket_errno();
				xf_close_socket(fd);
				fd = XF_INVALID_SOCKET;
				continue;
			}
			int so_error = 0;
			xf_socklen_t so_len = sizeof(so_error);
			if (getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&so_error),
				       &so_len) != 0 ||
			    so_error != 0) {
				last_errno = so_error != 0 ? so_error : xf_socket_errno();
				xf_close_socket(fd);
				fd = XF_INVALID_SOCKET;
				continue;
			}
		} else if (rc != 0) {
			last_errno = connect_err;
			xf_close_socket(fd);
			fd = XF_INVALID_SOCKET;
			continue;
		}

		xf_set_nonblocking(fd, false); // 恢复阻塞
		xf_set_socket_timeout(fd, SO_RCVTIMEO, timeout_ms);
		xf_set_socket_timeout(fd, SO_SNDTIMEO, timeout_ms);
		break; // 连接成功
	}
	freeaddrinfo(addrs);

	if (fd == XF_INVALID_SOCKET) {
		res.error = std::string("TCP connect failed to ") + host + ":" + port_str + ": " +
			    (last_errno != 0 ? xf_socket_strerror(last_errno) : "unknown error");
		last_error_ = res.error;
		return res;
	}
	fd_ = static_cast<intptr_t>(fd);

	// 3) TLS 握手
	if (use_tls) {
		SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
		if (ctx == nullptr) {
			res.error = "SSL_CTX_new failed";
			last_error_ = res.error;
			close();
			return res;
		}
		if (verify_peer_) {
			SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
			// 加载系统默认信任库；失败要显式报错，否则会退化成「连不上但说不清原因」
			if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
				res.error = "无法加载系统 CA 信任库（SSL_CTX_set_default_verify_paths 失败）";
				last_error_ = res.error;
				SSL_CTX_free(ctx);
				close();
				return res;
			}
		} else {
			SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
		}

		SSL *ssl = SSL_new(ctx);
		if (ssl == nullptr) {
			SSL_CTX_free(ctx);
			res.error = "SSL_new failed";
			last_error_ = res.error;
			close();
			return res;
		}
		SSL_set_fd(ssl, static_cast<int>(fd_));
		SSL_set_tlsext_host_name(ssl, host.c_str()); // SNI
		if (verify_peer_)
			SSL_set1_host(ssl, host.c_str());

		if (SSL_connect(ssl) != 1) {
			const unsigned long e = ERR_get_error();
			char ebuf[256] = {0};
			ERR_error_string_n(e, ebuf, sizeof(ebuf));
			res.error = std::string("TLS handshake failed: ") + ebuf;
			last_error_ = res.error;
			SSL_free(ssl);
			SSL_CTX_free(ctx);
			close();
			return res;
		}
		tls_ = ssl;
		// SSL_CTX 由 SSL 对象持有引用计数（SSL_new 增加引用），这里可以释放
		SSL_CTX_free(ctx);
	}

	// 4) WebSocket Upgrade 握手
	const std::string key = websocket_key();
	std::string req;
	req += std::string("GET ") + path + " HTTP/1.1\r\n";
	req += std::string("Host: ") + hostport + "\r\n";
	req += "Upgrade: websocket\r\n";
	req += "Connection: Upgrade\r\n";
	req += std::string("Sec-WebSocket-Key: ") + key + "\r\n";
	req += "Sec-WebSocket-Version: 13\r\n";
	req += "User-Agent: obs-localvocal-xunfei/1.0\r\n";
	for (const auto &h : headers)
		req += h + "\r\n";
	req += "\r\n";

	std::string err;
	if (!tls_write_all(req.data(), req.size(), &err)) {
		res.error = std::string("send handshake failed: ") + err;
		last_error_ = res.error;
		close();
		return res;
	}

	// 读取响应头（直到 \r\n\r\n）
	std::string resp;
	const size_t max_header = 64 * 1024;
	while (resp.find("\r\n\r\n") == std::string::npos) {
		if (resp.size() > max_header) {
			res.error = "handshake response header too large";
			last_error_ = res.error;
			close();
			return res;
		}
		char tmp[2048];
		const int n = raw_recv(tmp, sizeof(tmp), &err);
		if (n <= 0) {
			res.error = std::string("recv handshake response failed: ") + err;
			last_error_ = res.error;
			close();
			return res;
		}
		resp.append(tmp, static_cast<size_t>(n));
	}

	const size_t header_end = resp.find("\r\n\r\n") + 4;
	const std::string header = resp.substr(0, header_end);
	const std::string leftover = resp.substr(header_end);
	recv_buf_ = leftover;

	// 状态行校验
	if (header.find(" 101 ") == std::string::npos &&
	    !starts_with(header, "HTTP/1.1 101")) {
		// 截取第一行作为错误信息
		std::string first = header.substr(0, header.find("\r\n"));
		res.error = std::string("server rejected websocket upgrade: ") + first;
		last_error_ = res.error;
		close();
		return res;
	}

	// Sec-WebSocket-Accept 校验（大小写不敏感地查头）
	const std::string expect = compute_accept_key(key);
	std::string lower = header;
	for (char &c : lower)
		c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
	const size_t ap = lower.find("sec-websocket-accept:");
	if (ap == std::string::npos || header.find(expect) == std::string::npos) {
		res.error = std::string("invalid Sec-WebSocket-Accept (expected ") + expect + ")";
		last_error_ = res.error;
		close();
		return res;
	}

	connected_ = true;
	res.ok = true;
	return res;
}

/* ============================ 收发 ============================ */

bool WebSocketClient::tls_write_all(const void *data, size_t len, std::string *error_out)
{
	const char *p = static_cast<const char *>(data);
	size_t sent = 0;
	while (sent < len) {
		int n;
		if (tls_ != nullptr) {
			n = SSL_write(static_cast<SSL *>(tls_), p + sent, static_cast<int>(len - sent));
			if (n <= 0) {
				const int e = SSL_get_error(static_cast<SSL *>(tls_), n);
				if (error_out)
					*error_out = std::string("SSL_write error ") + std::to_string(e);
				return false;
			}
		} else {
			n = static_cast<int>(::send(fd_, p + sent, static_cast<int>(len - sent), 0));
			if (n <= 0) {
				if (error_out)
					*error_out = std::string("send error: ") + xf_socket_strerror(xf_socket_errno());
				return false;
			}
		}
		sent += static_cast<size_t>(n);
	}
	return true;
}

int WebSocketClient::raw_recv(void *buf, size_t len, std::string *error_out)
{
	if (tls_ != nullptr) {
		const int n = SSL_read(static_cast<SSL *>(tls_), buf, static_cast<int>(len));
		if (n > 0)
			return n;
		const int e = SSL_get_error(static_cast<SSL *>(tls_), n);
		if (e == SSL_ERROR_ZERO_RETURN)
			return 0; // 正常关闭
		if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
			return -2; // 需要重试
		if (error_out)
			*error_out = std::string("SSL_read error ") + std::to_string(e);
		return -1;
	}

	#ifdef _WIN32
	const int n = ::recv(fd_, static_cast<char *>(buf), static_cast<int>(len), 0);
#else
	const ssize_t n = ::recv(fd_, buf, len, 0);
#endif
	if (n > 0)
		return static_cast<int>(n);
	if (n == 0)
		return 0;
	#ifdef _WIN32
	if (xf_socket_errno() == WSAEWOULDBLOCK)
		return -2;
#else
	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return -2;
#endif
	if (error_out)
		*error_out = std::string("recv error: ") + xf_socket_strerror(xf_socket_errno());
	return -1;
}

WsResult WebSocketClient::send_text(const std::string &text)
{
	return send_binary_op(text.data(), text.size(), WsFrame::TEXT);
}

WsResult WebSocketClient::send_binary(const void *data, size_t len)
{
	return send_binary_op(data, len, WsFrame::BINARY);
}

// 内部：统一发送路径（放在这里避免头文件暴露实现细节）
WsResult WebSocketClient::send_binary_op(const void *data, size_t len, uint8_t opcode)
{
	WsResult res;
	if (!connected_ || fd_ == -1) {
		res.error = "not connected";
		last_error_ = res.error;
		return res;
	}

	// 大消息分片（> 512KB），普通场景不会触发
	constexpr size_t kChunk = 512 * 1024;
	const char *p = static_cast<const char *>(data);
	size_t remaining = len;
	std::string err;

	// 只有「第一帧」使用调用方给的 opcode，后续帧必须是 continuation(0x0)。
	// （此前误用 take == len 判断，导致 len > kChunk 时首帧被写成 continuation）
	bool first = true;
	do {
		const size_t take = remaining > kChunk ? kChunk : remaining;
		const bool fin = (take == remaining);
		const uint8_t op = first ? opcode : 0x0;
		first = false;
		const std::string frame = encode_frame(op, std::string(p, take), fin,
						      static_cast<uint32_t>(reinterpret_cast<uintptr_t>(p)));
		if (!tls_write_all(frame.data(), frame.size(), &err)) {
			res.error = std::string("send frame failed: ") + err;
			last_error_ = res.error;
			return res;
		}
		p += take;
		remaining -= take;
	} while (remaining > 0);

	res.ok = true;
	return res;
}

WsResult WebSocketClient::send_close(uint16_t code, const std::string &reason)
{
	WsResult res;
	if (!connected_ || fd_ == -1) {
		res.ok = true; // 已经断了
		return res;
	}
	std::string payload;
	payload += static_cast<char>((code >> 8) & 0xFF);
	payload += static_cast<char>(code & 0xFF);
	payload += reason;
	const std::string frame = encode_frame(WsFrame::CLOSE, payload, true, 0xABCDEF01u);
	std::string err;
	if (!tls_write_all(frame.data(), frame.size(), &err)) {
		res.error = std::string("send close failed: ") + err;
		last_error_ = res.error;
		return res;
	}
	res.ok = true;
	return res;
}

bool WebSocketClient::read_available(int timeout_ms, std::string *error_out)
{
	if (fd_ == -1) {
		if (error_out)
			*error_out = "not connected";
		return false;
	}

	xf_pollfd_t pfd;
	pfd.fd = static_cast<decltype(pfd.fd)>(fd_);
	pfd.events = POLLIN;
	pfd.revents = 0;
	const int pr = xf_poll(&pfd, 1, timeout_ms);
	if (pr == 0)
		return true; // 超时，无数据，不算错误
	if (pr < 0) {
		if (error_out)
			*error_out = std::string("poll error: ") + xf_socket_strerror(xf_socket_errno());
		return false;
	}

	char tmp[8192];
	const int n = raw_recv(tmp, sizeof(tmp), error_out);
	if (n == -2)
		return true; // 需要重试
	if (n <= 0) {
		if (error_out && error_out->empty())
			*error_out = "connection closed by peer";
		return false;
	}
	recv_buf_.append(tmp, static_cast<size_t>(n));
	return true;
}

bool WebSocketClient::poll(int timeout_ms, MessageCallback on_message, std::string *error_out)
{
	if (!connected_) {
		if (error_out)
			*error_out = "not connected";
		return false;
	}

	int wait_ms = timeout_ms;
	for (;;) {
		// 先把缓冲区里已有的帧处理掉
		for (;;) {
			if (recv_buf_.empty())
				break;

			WsFrame frame;
			size_t consumed = 0;
			std::string err;
			if (!decode_frame(recv_buf_, frame, consumed, &err))
				break; // 数据不够

			recv_buf_.erase(0, consumed);

			switch (frame.opcode) {
			case WsFrame::PING:
				// 回 Pong
				{
					const std::string pong =
						encode_frame(WsFrame::PONG, frame.payload, true, 7u);
					std::string werr;
					tls_write_all(pong.data(), pong.size(), &werr);
				}
				continue;
			case WsFrame::PONG:
				continue;
			case WsFrame::CLOSE:
				connected_ = false;
				if (error_out)
					*error_out = "server sent close frame";
				return false;
			default:
				if (on_message)
					on_message(frame);
				continue;
			}
		}

		if (wait_ms <= 0) {
			if (error_out)
				error_out->clear();
			return true; // 缓冲区已处理完
		}

		if (!read_available(wait_ms, error_out))
			return false;
		wait_ms = 0; // 收到数据后只处理缓冲区，不继续等
	}
}

void WebSocketClient::close()
{
	connected_ = false;
	if (tls_ != nullptr) {
		SSL *ssl = static_cast<SSL *>(tls_);
		SSL_shutdown(ssl);
		SSL_free(ssl);
		tls_ = nullptr;
	}
	if (fd_ != -1) {
		xf_close_socket(static_cast<xf_socket_t>(fd_));
		fd_ = -1;
	}
	recv_buf_.clear();
}

} // namespace xunfei
