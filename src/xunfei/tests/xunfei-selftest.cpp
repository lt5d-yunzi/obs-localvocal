/**
 * xunfei-selftest.cpp
 *
 * 讯飞协议层自测：不依赖 OBS 运行时，可用系统 clang 直接编译运行。
 *
 *   clang++ -std=c++17 -O1 -o /tmp/xf_selftest \
 *       tests/xunfei-selftest.cpp \
 *       vendor/localvocal-src/src/xunfei/xunfei-*.cpp \
 *       vendor/localvocal-src/src/model-utils/sha256.cpp \
 *       -I vendor/localvocal-src/src -I vendor/localvocal-src/src/xunfei \
 *       -I <openssl include> -lssl -lcrypto
 *
 * 或直接运行 tests/run-protocol-tests.sh
 *
 * 覆盖：
 *   - Base64 / SHA1 已知向量（RFC 3174 / 6455）
 *   - HMAC-SHA256 与讯飞机器翻译签名链（对拍外部已验证的 canonical 值）
 *   - WebSocket 握手 Accept key（RFC 6455 官方示例）
 *   - WebSocket 帧编解码往返
 *   - 语言代码映射
 */

#include "xunfei-utils.h"
#include "xunfei-websocket.h"
#include "xunfei-json.h"
#include "xunfei-rtasr.h"

#include <cstdio>
#include <cstring>
#include <string>

using namespace xunfei;

static int g_pass = 0;
static int g_fail = 0;

static void check(bool cond, const std::string &name)
{
	if (cond) {
		++g_pass;
		printf("[PASS] %s\n", name.c_str());
	} else {
		++g_fail;
		printf("[FAIL] %s\n", name.c_str());
	}
}

static void check_eq(const std::string &got, const std::string &want, const std::string &name)
{
	if (got == want) {
		++g_pass;
		printf("[PASS] %s\n", name.c_str());
	} else {
		++g_fail;
		printf("[FAIL] %s\n      got : %s\n      want: %s\n", name.c_str(), got.c_str(),
		       want.c_str());
	}
}

/* ---------------- Base64 ---------------- */

static void test_base64()
{
	check_eq(base64_encode(std::string("")), "", "base64 空串");
	check_eq(base64_encode(std::string("f")), "Zg==", "base64 f");
	check_eq(base64_encode(std::string("fo")), "Zm8=", "base64 fo");
	check_eq(base64_encode(std::string("foo")), "Zm9v", "base64 foo");
	check_eq(base64_encode(std::string("foob")), "Zm9vYg==", "base64 foob");
	check_eq(base64_encode(std::string("fooba")), "Zm9vYmE=", "base64 fooba");
	check_eq(base64_encode(std::string("foobar")), "Zm9vYmFy", "base64 foobar");

	// 往返
	const std::string raw = "\x00\x01\x02\xfe\xff hello 中文";
	check_eq(base64_decode(base64_encode(raw)), raw, "base64 往返（含二进制与 UTF-8）");
	check(base64_decode("!!!!").empty(), "base64 非法字符返回空");
}

/* ---------------- SHA1 ---------------- */

static void test_sha1()
{
	// RFC 3174 / 常见向量
	check_eq(sha1_hex("abc"), "a9993e364706816aba3e25717850c26c9cd0d89d", "SHA1(abc)");
	check_eq(sha1_hex(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709", "SHA1(\"\")");
	check_eq(sha1_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
		 "84983e441c3bd26ebaae4aa1f95129e5e54670f1", "SHA1(56字节向量)");

	// RFC 6455 官方示例：key -> accept
	check_eq(WebSocketClient::compute_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
		 "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "WebSocket Accept key（RFC6455 示例）");
}

/* ---------------- SHA256 / HMAC / 签名链 ---------------- */

static const char *kCanonicalDate = "Wed, 20 Nov 2019 03:14:25 GMT";
static const char *kCanonicalBody =
	"{\"common\":{\"app_id\":\"5d000000\"},\"business\":{\"from\":\"cn\",\"to\":\"en\"},"
	"\"data\":{\"text\":\"5L2g5aW977yM5LiW55WM\"}}";
static const char *kCanonicalDigest = "SHA-256=BWACoL10puRFc7FeAolVSUUeiHnWfhxutK9MOWpFQZM=";
static const char *kCanonicalSecret = "FAKE_API_SECRET_0123456789abcdef";
static const char *kCanonicalSignature = "wV5o8q5dYTZPFe12MZvEekk0MNVyLQyKEvfgPc4WjVc=";

static void test_signature_chain()
{
	check_eq(sha256_digest_header(kCanonicalBody), kCanonicalDigest,
		 "SHA256 digest 头（对拍外部已验证值）");

	// 签名原文：四行、3 个 \n、末尾无换行
	const std::string origin = std::string("host: itrans.xfyun.cn\n") + "date: " +
				   kCanonicalDate + "\n" + "POST /v2/its HTTP/1.1\n" + "digest: " +
				   kCanonicalDigest;

	check_eq(hmac_sha256_base64(kCanonicalSecret, origin), kCanonicalSignature,
		 "HMAC-SHA256 签名（对拍外部已验证值）");

	// 末尾多一个换行必须得到不同签名（这是最容易踩的坑）
	const std::string origin_nl = origin + "\n";
	check(hmac_sha256_base64(kCanonicalSecret, origin_nl) != kCanonicalSignature,
	      "签名原文末尾加 \\n 会得到不同签名（绝不能加）");

	// HMAC-SHA256 RFC 4231 Test Case 2
	check_eq(hmac_sha256_base64("Jefe", "what do ya want for nothing?"),
		 "W9zBRr9gdU5qBCQmCJV1x1oAPwidJzmDnexYuWTsOEM=",
		 "HMAC-SHA256 RFC4231 case2（key=Jefe）");
}

/* ---------------- WebSocket 帧 ---------------- */

static void test_websocket_frames()
{
	// 短帧往返（客户端帧带掩码）
	for (const std::string &payload :
	     {std::string("hi"), std::string(125, 'x'), std::string(126, 'y'),
	      std::string(70000, 'z')}) {
		const std::string frame = WebSocketClient::encode_frame(0x1, payload, true);
		WsFrame out;
		size_t consumed = 0;
		std::string err;
		const bool ok = WebSocketClient::decode_frame(frame, out, consumed, &err);
		check(ok && out.payload == payload && consumed == frame.size(),
		      "WS 帧往返 payload=" + std::to_string(payload.size()) + " 字节");
	}

	// 已经验证过的掩码：手工构造一个已知帧
	// opcode=1, fin=1, len=5, mask 由 seed=1 决定 -> 只校验解析出的 payload 正确
	const std::string frame = WebSocketClient::encode_frame(0x2, "hello", true, 1u);
	WsFrame out;
	size_t consumed = 0;
	check(WebSocketClient::decode_frame(frame, out, consumed, nullptr) &&
		      out.payload == "hello" && out.opcode == WsFrame::BINARY,
	      "WS 二进制帧 opcode 正确");

	// 数据不足时返回 false 而不是崩
	WsFrame partial;
	size_t c2 = 0;
	check(!WebSocketClient::decode_frame(frame.substr(0, 3), partial, c2, nullptr),
	      "WS 数据不足时安全返回 false");

	// 服务端帧（无掩码）解析
	std::string server_frame;
	server_frame += static_cast<char>(0x81); // fin + text
	server_frame += static_cast<char>(2);    // len=2, 无掩码
	server_frame += "ok";
	WsFrame sf;
	size_t c3 = 0;
	check(WebSocketClient::decode_frame(server_frame, sf, c3, nullptr) && sf.payload == "ok",
	      "WS 服务端无掩码帧解析");
}

/* ---------------- 语言代码 ---------------- */

static void test_languages()
{
	bool ok = false;
	check_eq(to_xunfei_lang("zh", &ok), "cn", "zh -> cn");
	check(ok, "zh 被识别为支持");
	check_eq(to_xunfei_lang("zh-CN"), "cn", "zh-CN -> cn");
	check_eq(to_xunfei_lang("en_US"), "en", "en_US -> en");
	check_eq(to_xunfei_lang("ja"), "ja", "ja -> ja");
	check_eq(to_xunfei_lang("JP"), "ja", "JP -> ja");
	check_eq(to_xunfei_lang("yue"), "yue", "yue -> yue");
	check_eq(to_xunfei_lang("fr"), "fr", "fr -> fr");

	bool ok2 = true;
	const std::string unsupported = to_xunfei_lang("klingon", &ok2);
	check(unsupported.empty() && !ok2, "不支持的语言返回空且 ok=false");
}

/* ---------------- 时间与转义 ---------------- */

static void test_misc()
{
	const std::string date = rfc1123_utc_now();
	// 形如 "Wed, 20 Nov 2019 03:14:25 GMT"：总长 29，逗号在 3，两个冒号在 19/22
	if (date.size() != 29 || date.substr(date.size() - 3) != "GMT" || date[3] != ',' ||
	    date[19] != ':' || date[22] != ':') {
		printf("      [debug] date=%s len=%zu tail=%s c3=%c c19=%c c22=%c\n", date.c_str(),
		       date.size(), date.substr(date.size() > 3 ? date.size() - 3 : 0).c_str(),
		       date.size() > 22 ? date[3] : '?', date.size() > 22 ? date[19] : '?',
		       date.size() > 22 ? date[22] : '?');
	}
	check(date.size() == 29 && date.substr(date.size() - 3) == "GMT" && date[3] == ',' &&
		      date[19] == ':' && date[22] == ':',
	      "RFC1123 时间格式（长度/GMT/逗号/冒号）: " + date);
	check(date.find("Mon,") == 0 || date.find("Tue,") == 0 || date.find("Wed,") == 0 ||
		      date.find("Thu,") == 0 || date.find("Fri,") == 0 ||
		      date.find("Sat,") == 0 || date.find("Sun,") == 0,
	      "RFC1123 星期为英文缩写");

	check_eq(json_escape("a\"b\\c\nd\te"), "a\\\"b\\\\c\\nd\\te", "JSON 转义");

	const std::string key1 = websocket_key();
	const std::string key2 = websocket_key();
	check(base64_decode(key1).size() == 16, "WebSocket key 为 16 字节");
	check(key1 != key2, "WebSocket key 随机不重复");
}

/* ---------------- JSON 取值 ---------------- */

static void test_json()
{
	std::string v;
	check(json_find_string("{\"code\":\"0\",\"desc\":\"ok\"}", "desc", v) && v == "ok",
	      "JSON 取字符串（简单）");
	check(json_find_string("{\"a\":\"x\\ny\"}", "a", v) && v == "x\ny", "JSON \\n 反转义");
	check(json_find_string("{\"a\":\"q\\\"q\"}", "a", v) && v == "q\"q", "JSON 引号反转义");
	check(json_find_string("{\"a\":\"\\u4e2d\\u6587\"}", "a", v) && v == "中文",
	      "JSON \\uXXXX 转义 -> UTF-8");

	long long n = 0;
	check(json_find_int("{\"type\":0}", "type", n) && n == 0, "JSON 取整数 type=0");
	check(json_find_int("{\"type\":1}", "type", n) && n == 1, "JSON 取整数 type=1");
	check(!json_find_string("{\"a\":\"b\"}", "zzz", v), "JSON 找不到 key 返回 false");
}

/* ---------------- MD5 / HMAC-SHA1 / RTASR 鉴权 ---------------- */

static void test_rtasr_auth()
{
	// MD5 标准向量
	check_eq(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e", "MD5(\"\") 标准向量");
	check_eq(md5_hex("abc"), "900150983cd24fb0d6963f7d28e17f72", "MD5(abc) 标准向量");
	check_eq(md5_hex("The quick brown fox jumps over the lazy dog"),
		 "9e107d9d372bb6826bd81d3542a419d6", "MD5(quick brown fox) 标准向量");

	// 对拍值由 Python 独立计算：
	//   md5("5d0000001573459200") = abd0bd9c8798910146b9b935d3a16f30
	//   signa = b64(hmac_sha1("FAKE_KEY_0123456789", md5)) = 6k1cvJULQKgiYca67A4QIOJt2lc=
	check_eq(md5_hex("5d0000001573459200"), "abd0bd9c8798910146b9b935d3a16f30",
		 "MD5（RTASR 鉴权链第一步，对拍 Python）");
	check_eq(hmac_sha1_base64("FAKE_KEY_0123456789", "abd0bd9c8798910146b9b935d3a16f30"),
		 "6k1cvJULQKgiYca67A4QIOJt2lc=", "HMAC-SHA1（RTASR signa，对拍 Python）");

	const RtAsrAuth auth = XunfeiRtAsr::make_auth("5d000000", "FAKE_KEY_0123456789",
						      "1573459200", "1", "tech");
	check_eq(auth.ts, "1573459200", "RTASR ts 透传");
	check_eq(auth.signa, "6k1cvJULQKgiYca67A4QIOJt2lc=", "RTASR signa 计算");
	check(auth.url.find("wss://rtasr.xfyun.cn/v1/ws?appid=5d000000&ts=1573459200&signa=") == 0,
	      "RTASR URL 前缀与参数顺序");
	check(auth.url.find("&punc=1") != std::string::npos &&
		      auth.url.find("&pd=tech") != std::string::npos,
	      "RTASR URL 携带可选参数 punc/pd");
}

/* ---------------- RTASR 消息解析 ---------------- */

static void test_rtasr_parse()
{
	// 真实结构：外层 JSON 里 data 是被转义的 JSON 字符串
	const std::string msg =
		"{\"action\":\"result\",\"code\":\"0\",\"data\":\"{\\\"cn\\\":{\\\"st\\\":{"
		"\\\"type\\\":\\\"0\\\",\\\"rt\\\":[{\\\"ws\\\":[{\\\"cw\\\":[{\\\"w\\\":\\\"你好\\\"},"
		"{\\\"w\\\":\\\"世界\\\"}]},{\\\"cw\\\":[{\\\"w\\\":\\\"！\\\"}]}]}]}}}\","
		"\"desc\":\"success\",\"sid\":\"abc\"}";

	RtAsrResult out;
	std::string err;
	const bool ok = XunfeiRtAsr::parse_message(msg, out, &err);
	check(ok, "RTASR 解析最终结果：返回 true");
	check_eq(out.text, "你好世界！", "RTASR 文本拼接（cw.w 顺序拼接）");
	check(out.type == RtAsrResult::FINAL, "RTASR type=0 判定为 FINAL");

	const std::string partial =
		"{\"action\":\"result\",\"code\":\"0\",\"data\":\"{\\\"cn\\\":{\\\"st\\\":{"
		"\\\"type\\\":\\\"1\\\",\\\"rt\\\":[{\\\"ws\\\":[{\\\"cw\\\":[{\\\"w\\\":\\\"正在\\\"}]}]}]}}}\"}";
	RtAsrResult p;
	check(XunfeiRtAsr::parse_message(partial, p, &err) && p.type == RtAsrResult::PARTIAL,
	      "RTASR type=1 判定为 PARTIAL");
	check_eq(p.text, "正在", "RTASR 中间结果文本");

	const std::string started =
		"{\"action\":\"started\",\"code\":\"0\",\"data\":\"\",\"desc\":\"success\"}";
	RtAsrResult s;
	check(!XunfeiRtAsr::parse_message(started, s, &err) && err.empty(),
	      "RTASR started 既不是结果也不报错");

	const std::string errm =
		"{\"action\":\"error\",\"code\":\"10165\",\"desc\":\"invalid appid\"}";
	RtAsrResult e;
	check(!XunfeiRtAsr::parse_message(errm, e, &err) &&
		      err.find("10165") != std::string::npos,
	      "RTASR error 消息带出 code 与 desc");
}

int main()
{
	printf("==================== 讯飞协议层自测 ====================\n");
	test_base64();
	test_sha1();
	test_signature_chain();
	test_websocket_frames();
	test_json();
	test_languages();
	test_misc();
	test_rtasr_auth();
	test_rtasr_parse();

	printf("\n统计: %d 项通过, %d 项失败\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
