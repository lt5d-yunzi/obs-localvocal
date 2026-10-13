#include "xunfei-utils.h"

#include "model-utils/sha256.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <random>

namespace xunfei {

/* ============================ Base64 ============================ */

static const char kB64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const uint8_t *data, size_t len)
{
	std::string out;
	out.reserve(((len + 2) / 3) * 4);

	size_t i = 0;
	while (i + 2 < len) {
		const uint32_t n = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) |
				   uint32_t(data[i + 2]);
		out += kB64Table[(n >> 18) & 0x3F];
		out += kB64Table[(n >> 12) & 0x3F];
		out += kB64Table[(n >> 6) & 0x3F];
		out += kB64Table[n & 0x3F];
		i += 3;
	}

	const size_t rem = len - i;
	if (rem == 1) {
		const uint32_t n = uint32_t(data[i]) << 16;
		out += kB64Table[(n >> 18) & 0x3F];
		out += kB64Table[(n >> 12) & 0x3F];
		out += "==";
	} else if (rem == 2) {
		const uint32_t n = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
		out += kB64Table[(n >> 18) & 0x3F];
		out += kB64Table[(n >> 12) & 0x3F];
		out += kB64Table[(n >> 6) & 0x3F];
		out += '=';
	}
	return out;
}

std::string base64_encode(const std::string &data)
{
	return base64_encode(reinterpret_cast<const uint8_t *>(data.data()), data.size());
}

static int b64_value(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

std::string base64_decode(const std::string &encoded)
{
	std::string out;
	out.reserve(encoded.size() * 3 / 4);

	int buf = 0;
	int bits = 0;
	for (char c : encoded) {
		if (c == '=' || c == '\n' || c == '\r')
			continue;
		const int v = b64_value(c);
		if (v < 0)
			return std::string();
		buf = (buf << 6) | v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out += static_cast<char>((buf >> bits) & 0xFF);
		}
	}
	return out;
}

/* ============================ SHA1 ============================ */

namespace {

struct Sha1Ctx {
	uint32_t h[5];
	uint64_t total_len;
	uint8_t buf[64];
	size_t buf_len;

	Sha1Ctx()
	{
		h[0] = 0x67452301;
		h[1] = 0xEFCDAB89;
		h[2] = 0x98BADCFE;
		h[3] = 0x10325476;
		h[4] = 0xC3D2E1F0;
		total_len = 0;
		buf_len = 0;
	}

	static uint32_t rol(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

	void process_block(const uint8_t *p)
	{
		uint32_t w[80];
		for (int i = 0; i < 16; ++i) {
			w[i] = (uint32_t(p[i * 4]) << 24) | (uint32_t(p[i * 4 + 1]) << 16) |
			       (uint32_t(p[i * 4 + 2]) << 8) | uint32_t(p[i * 4 + 3]);
		}
		for (int i = 16; i < 80; ++i)
			w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

		uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
		for (int i = 0; i < 80; ++i) {
			uint32_t f, k;
			if (i < 20) {
				f = (b & c) | ((~b) & d);
				k = 0x5A827999;
			} else if (i < 40) {
				f = b ^ c ^ d;
				k = 0x6ED9EBA1;
			} else if (i < 60) {
				f = (b & c) | (b & d) | (c & d);
				k = 0x8F1BBCDC;
			} else {
				f = b ^ c ^ d;
				k = 0xCA62C1D6;
			}
			const uint32_t tmp = rol(a, 5) + f + e + k + w[i];
			e = d;
			d = c;
			c = rol(b, 30);
			b = a;
			a = tmp;
		}
		h[0] += a;
		h[1] += b;
		h[2] += c;
		h[3] += d;
		h[4] += e;
	}

	void add(const uint8_t *data, size_t len)
	{
		total_len += len;
		while (len > 0) {
			const size_t take = std::min(len, sizeof(buf) - buf_len);
			memcpy(buf + buf_len, data, take);
			buf_len += take;
			data += take;
			len -= take;
			if (buf_len == sizeof(buf)) {
				process_block(buf);
				buf_len = 0;
			}
		}
	}

	void finish(uint8_t out[20])
	{
		const uint64_t bit_len = total_len * 8;
		const uint8_t pad = 0x80;
		add(&pad, 1);
		const uint8_t zero = 0x00;
		while (buf_len != 56)
			add(&zero, 1);
		uint8_t len_be[8];
		for (int i = 0; i < 8; ++i)
			len_be[i] = uint8_t((bit_len >> (56 - i * 8)) & 0xFF);
		add(len_be, 8);

		for (int i = 0; i < 5; ++i) {
			out[i * 4] = uint8_t((h[i] >> 24) & 0xFF);
			out[i * 4 + 1] = uint8_t((h[i] >> 16) & 0xFF);
			out[i * 4 + 2] = uint8_t((h[i] >> 8) & 0xFF);
			out[i * 4 + 3] = uint8_t(h[i] & 0xFF);
		}
	}
};

} // namespace

void sha1_raw(const uint8_t *data, size_t len, uint8_t out[20])
{
	Sha1Ctx ctx;
	ctx.add(data, len);
	ctx.finish(out);
}

std::string sha1_hex(const std::string &data)
{
	uint8_t digest[20];
	sha1_raw(reinterpret_cast<const uint8_t *>(data.data()), data.size(), digest);
	static const char *hex = "0123456789abcdef";
	std::string out;
	out.reserve(40);
	for (uint8_t b : digest) {
		out += hex[(b >> 4) & 0xF];
		out += hex[b & 0xF];
	}
	return out;
}

std::string sha1_base64(const std::string &data)
{
	uint8_t digest[20];
	sha1_raw(reinterpret_cast<const uint8_t *>(data.data()), data.size(), digest);
	return base64_encode(digest, sizeof(digest));
}

/* ============================ MD5 ============================ */

/*
 * 讯飞 RTASR 鉴权链：
 *   signa = Base64(HMAC-SHA1(MD5hex(appid + ts), apiKey))
 * 需要 MD5 的十六进制字符串形式，这里给一个自包含实现。
 */
namespace {

struct Md5Ctx {
	uint32_t a, b, c, d;
	uint64_t total_len;
	uint8_t buf[64];
	size_t buf_len;

	Md5Ctx() : a(0x67452301), b(0xefcdab89), c(0x98badcfe), d(0x10325476), total_len(0), buf_len(0)
	{
	}

	static uint32_t rol(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

	void process_block(const uint8_t *p)
	{
		static const uint32_t K[64] = {
			0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
			0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
			0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
			0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
			0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
			0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
			0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
			0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
			0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
			0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
			0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
		static const int S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
					  5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
					  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
					  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

		uint32_t M[16];
		for (int i = 0; i < 16; ++i) {
			M[i] = uint32_t(p[i * 4]) | (uint32_t(p[i * 4 + 1]) << 8) |
			       (uint32_t(p[i * 4 + 2]) << 16) | (uint32_t(p[i * 4 + 3]) << 24);
		}

		uint32_t A = a, B = b, C = c, D = d;
		for (int i = 0; i < 64; ++i) {
			uint32_t F;
			int g;
			if (i < 16) {
				F = (B & C) | (~B & D);
				g = i;
			} else if (i < 32) {
				F = (D & B) | (~D & C);
				g = (5 * i + 1) % 16;
			} else if (i < 48) {
				F = B ^ C ^ D;
				g = (3 * i + 5) % 16;
			} else {
				F = C ^ (B | ~D);
				g = (7 * i) % 16;
			}
			F = F + A + K[i] + M[g];
			A = D;
			D = C;
			C = B;
			B = B + rol(F, S[i]);
		}
		a += A;
		b += B;
		c += C;
		d += D;
	}

	void add(const uint8_t *data, size_t len)
	{
		total_len += len;
		while (len > 0) {
			const size_t take = std::min(len, sizeof(buf) - buf_len);
			memcpy(buf + buf_len, data, take);
			buf_len += take;
			data += take;
			len -= take;
			if (buf_len == sizeof(buf)) {
				process_block(buf);
				buf_len = 0;
			}
		}
	}

	void finish(uint8_t out[16])
	{
		const uint64_t bit_len = total_len * 8;
		const uint8_t pad = 0x80;
		add(&pad, 1);
		const uint8_t zero = 0;
		while (buf_len != 56)
			add(&zero, 1);
		uint8_t len_le[8];
		for (int i = 0; i < 8; ++i)
			len_le[i] = uint8_t((bit_len >> (i * 8)) & 0xFF);
		add(len_le, 8);

		const uint32_t vals[4] = {a, b, c, d};
		for (int i = 0; i < 4; ++i) {
			out[i * 4] = uint8_t(vals[i] & 0xFF);
			out[i * 4 + 1] = uint8_t((vals[i] >> 8) & 0xFF);
			out[i * 4 + 2] = uint8_t((vals[i] >> 16) & 0xFF);
			out[i * 4 + 3] = uint8_t((vals[i] >> 24) & 0xFF);
		}
	}
};

} // namespace

std::string md5_hex(const std::string &data)
{
	Md5Ctx ctx;
	ctx.add(reinterpret_cast<const uint8_t *>(data.data()), data.size());
	uint8_t digest[16];
	ctx.finish(digest);
	static const char *hex = "0123456789abcdef";
	std::string out;
	out.reserve(32);
	for (uint8_t b : digest) {
		out += hex[(b >> 4) & 0xF];
		out += hex[b & 0xF];
	}
	return out;
}

std::string hmac_sha1_base64(const std::string &key, const std::string &data)
{
	constexpr size_t kBlockSize = 64;
	std::string k = key;
	if (k.size() > kBlockSize) {
		uint8_t digest[20];
		sha1_raw(reinterpret_cast<const uint8_t *>(k.data()), k.size(), digest);
		k.assign(reinterpret_cast<const char *>(digest), sizeof(digest));
	}

	std::vector<uint8_t> ipad(kBlockSize), opad(kBlockSize);
	for (size_t i = 0; i < kBlockSize; ++i) {
		const uint8_t kb = i < k.size() ? uint8_t(k[i]) : 0x00;
		ipad[i] = kb ^ 0x36;
		opad[i] = kb ^ 0x5C;
	}

	// inner = SHA1(ipad || data)
	{
		// 手动拼接以避免额外拷贝语义问题
		std::vector<uint8_t> inner_input;
		inner_input.reserve(ipad.size() + data.size());
		inner_input.insert(inner_input.end(), ipad.begin(), ipad.end());
		inner_input.insert(inner_input.end(), data.begin(), data.end());
		uint8_t inner[20];
		sha1_raw(inner_input.data(), inner_input.size(), inner);

		std::vector<uint8_t> outer_input;
		outer_input.reserve(opad.size() + sizeof(inner));
		outer_input.insert(outer_input.end(), opad.begin(), opad.end());
		outer_input.insert(outer_input.end(), inner, inner + sizeof(inner));
		uint8_t result[20];
		sha1_raw(outer_input.data(), outer_input.size(), result);
		return base64_encode(result, sizeof(result));
	}
}

/* ========================= SHA256 / HMAC ========================= */

std::string sha256_digest_header(const std::string &body)
{
	SHA256 sha;
	uint8_t digest[SHA256::HashBytes];
	sha.add(body.data(), body.size());
	sha.getHash(digest);
	return std::string("SHA-256=") + base64_encode(digest, sizeof(digest));
}

std::string hmac_sha256_base64(const std::string &key, const std::string &data)
{
	constexpr size_t kBlockSize = 64;
	std::string k = key;
	if (k.size() > kBlockSize) {
		SHA256 sha;
		uint8_t digest[SHA256::HashBytes];
		sha.add(k.data(), k.size());
		sha.getHash(digest);
		k.assign(reinterpret_cast<const char *>(digest), sizeof(digest));
	}

	std::vector<uint8_t> ipad(kBlockSize), opad(kBlockSize);
	for (size_t i = 0; i < kBlockSize; ++i) {
		const uint8_t kb = i < k.size() ? uint8_t(k[i]) : 0x00;
		ipad[i] = kb ^ 0x36;
		opad[i] = kb ^ 0x5C;
	}

	auto sha256_bytes = [](const std::vector<uint8_t> &d1, const std::string &d2,
			       uint8_t out[SHA256::HashBytes]) {
		SHA256 sha;
		if (!d1.empty())
			sha.add(d1.data(), d1.size());
		if (!d2.empty())
			sha.add(d2.data(), d2.size());
		sha.getHash(out);
	};

	uint8_t inner[SHA256::HashBytes];
	sha256_bytes(ipad, data, inner);

	SHA256 outer;
	outer.add(opad.data(), opad.size());
	outer.add(inner, sizeof(inner));
	uint8_t result[SHA256::HashBytes];
	outer.getHash(result);

	return base64_encode(result, sizeof(result));
}

/* ============================ 时间 ============================ */

std::string rfc1123_utc_now()
{
	const std::time_t t = std::time(nullptr);
	std::tm tm_utc{};
#if defined(_WIN32)
	gmtime_s(&tm_utc, &t);
#else
	gmtime_r(&t, &tm_utc);
#endif
	char buf[64];
	// 注意：本地化环境可能影响 %a/%b 输出，这里手动指定英文星期/月份
	static const char *wdays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
	static const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
				       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	snprintf(buf, sizeof(buf), "%s, %02d %s %04d %02d:%02d:%02d GMT", wdays[tm_utc.tm_wday],
		 tm_utc.tm_mday, months[tm_utc.tm_mon], tm_utc.tm_year + 1900, tm_utc.tm_hour,
		 tm_utc.tm_min, tm_utc.tm_sec);
	return std::string(buf);
}

std::string unix_timestamp_str()
{
	return std::to_string(static_cast<long long>(std::time(nullptr)));
}

/* ============================ 随机 ============================ */

std::string websocket_key()
{
	static thread_local std::mt19937_64 rng(std::random_device{}() ^
						static_cast<uint64_t>(std::time(nullptr)));
	uint8_t buf[16];
	for (size_t i = 0; i < sizeof(buf); i += 8) {
		const uint64_t v = rng();
		for (size_t j = 0; j < 8 && i + j < sizeof(buf); ++j)
			buf[i + j] = uint8_t((v >> (j * 8)) & 0xFF);
	}
	return base64_encode(buf, sizeof(buf));
}

/* ============================ 语言 ============================ */

std::string to_xunfei_lang(const std::string &lang, bool *ok)
{
	if (ok)
		*ok = true;

	std::string l;
	l.reserve(lang.size());
	for (char c : lang)
		l += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

	// 去掉地区后缀与分隔符：zh-cn -> zh, pt_BR -> pt
	std::string base = l;
	const size_t sep = base.find_first_of("-_");
	if (sep != std::string::npos)
		base = base.substr(0, sep);

	// 已经是讯飞短码
	if (base == "cn" || base == "en" || base == "ja" || base == "ko" || base == "fr" ||
	    base == "es" || base == "ru" || base == "ar" || base == "th" || base == "yue")
		return base;

	// 常见映射
	if (base == "zh" || base == "cmn" || base == "chs" || base == "zhhans")
		return "cn";
	if (base == "cant" || base == "zhhk" || base == "zhtw" || base == "zht" ||
	    base == "zhhant") {
		// 繁体中文：讯飞机器翻译没有独立代码，粤语用 yue，否则退回 cn
		if (l == "zh-hk" || l == "zh_yue" || l == "yue")
			return "yue";
		return "cn";
	}
	if (base == "eng")
		return "en";
	if (base == "jpn" || base == "jp")
		return "ja";
	if (base == "kor" || base == "kr")
		return "ko";
	if (base == "fra" || base == "fre")
		return "fr";
	if (base == "spa")
		return "es";
	if (base == "rus")
		return "ru";
	if (base == "ara")
		return "ar";
	if (base == "tha")
		return "th";

	if (ok)
		*ok = false;
	return std::string();
}

std::vector<std::pair<std::string, std::string>> xunfei_language_table()
{
	return {
		{"cn", "中文（普通话）"}, {"en", "English"}, {"ja", "日本語"},
		{"ko", "한국어"},        {"fr", "Français"}, {"es", "Español"},
		{"ru", "Русский"},       {"ar", "العربية"},  {"th", "ไทย"},
		{"yue", "粤语"},
	};
}

/* ============================ 字符串 ============================ */

bool starts_with(const std::string &s, const std::string &prefix)
{
	return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

std::string trim(const std::string &s)
{
	size_t b = 0;
	size_t e = s.size();
	while (b < e && std::isspace(static_cast<unsigned char>(s[b])))
		++b;
	while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])))
		--e;
	return s.substr(b, e - b);
}

std::string json_escape(const std::string &s)
{
	std::string out;
	out.reserve(s.size() + 8);
	for (unsigned char c : s) {
		switch (c) {
		case '"':
			out += "\\\"";
			break;
		case '\\':
			out += "\\\\";
			break;
		case '\n':
			out += "\\n";
			break;
		case '\r':
			out += "\\r";
			break;
		case '\t':
			out += "\\t";
			break;
		case '\b':
			out += "\\b";
			break;
		case '\f':
			out += "\\f";
			break;
		default:
			if (c < 0x20) {
				char buf[8];
				snprintf(buf, sizeof(buf), "\\u%04x", c);
				out += buf;
			} else {
				out += static_cast<char>(c);
			}
		}
	}
	return out;
}

} // namespace xunfei
