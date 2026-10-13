#include "xunfei-translate.h"
#include "xunfei-utils.h"

#include <curl/curl.h>

#include <cstdlib>
#include <cstring>
#include <mutex>

#define XF_TRANS_HOST "itrans.xfyun.cn"
#define XF_TRANS_PATH "/v2/its"
#define XF_TRANS_URL "https://" XF_TRANS_HOST XF_TRANS_PATH
// 官方文档自相矛盾（接口说明表 4096 bytes / 请求参数表 1024 bytes），此处按更宽松的 4096 限制
#define XF_TRANS_BODY_LIMIT 4096

namespace xunfei {

/* ---------------- 最小 JSON 取值工具 ---------------- */

namespace {

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	const size_t total = size * nmemb;
	if (userp == nullptr)
		return 0;
	try {
		static_cast<std::string *>(userp)->append(static_cast<char *>(contents), total);
	} catch (...) {
		return 0;
	}
	return total;
}

/**
 * 提取 JSON 中某个 key 对应的字符串值（只处理 "key":"value" 这种最简单形式）。
 * 讯飞响应结构固定，够用；刻意不引入 JSON 库以保持插件依赖面最小。
 */
bool json_find_string(const std::string &json, const std::string &key, std::string &out)
{
	const std::string needle = std::string("\"") + key + "\"";
	size_t pos = json.find(needle);
	if (pos == std::string::npos)
		return false;

	pos = json.find(':', pos + needle.size());
	if (pos == std::string::npos)
		return false;
	++pos;
	while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n' ||
				     json[pos] == '\r'))
		++pos;

	if (pos >= json.size() || json[pos] != '"')
		return false;
	++pos;

	std::string value;
	while (pos < json.size() && json[pos] != '"') {
		if (json[pos] == '\\' && pos + 1 < json.size()) {
			const char esc = json[pos + 1];
			switch (esc) {
			case 'n':
				value += '\n';
				break;
			case 't':
				value += '\t';
				break;
			case 'r':
				value += '\r';
				break;
			case 'b':
				value += '\b';
				break;
			case 'f':
				value += '\f';
				break;
			case '"':
				value += '"';
				break;
			case '\\':
				value += '\\';
				break;
			case '/':
				value += '/';
				break;
			case 'u': {
				// 只处理 \uXXXX 基本平面（音译结果里罕见，做兜底）
				if (pos + 6 <= json.size()) {
					unsigned int cp = 0;
					for (int i = 0; i < 4; ++i) {
						const char c = json[pos + 2 + i];
						cp <<= 4;
						if (c >= '0' && c <= '9')
							cp |= unsigned(c - '0');
						else if (c >= 'a' && c <= 'f')
							cp |= unsigned(c - 'a' + 10);
						else if (c >= 'A' && c <= 'F')
							cp |= unsigned(c - 'A' + 10);
					}
					// UTF-8 编码
					if (cp < 0x80) {
						value += char(cp);
					} else if (cp < 0x800) {
						value += char(0xC0 | (cp >> 6));
						value += char(0x80 | (cp & 0x3F));
					} else {
						value += char(0xE0 | (cp >> 12));
						value += char(0x80 | ((cp >> 6) & 0x3F));
						value += char(0x80 | (cp & 0x3F));
					}
					pos += 4;
				}
				break;
			}
			default:
				value += esc;
				break;
			}
			pos += 2;
			continue;
		}
		value += json[pos];
		++pos;
	}
	out = value;
	return true;
}

std::once_flag g_curl_once;

void ensure_curl_global_init()
{
	std::call_once(g_curl_once, []() { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

} // namespace

/* ---------------- 构造 ---------------- */

XunfeiTranslator::XunfeiTranslator(const std::string &app_id, const std::string &api_key,
				   const std::string &api_secret)
	: app_id_(trim(app_id)), api_key_(trim(api_key)), api_secret_(trim(api_secret))
{
	ensure_curl_global_init();
}

XunfeiTranslator::~XunfeiTranslator() = default;

/* ---------------- 请求构造 ---------------- */

std::string XunfeiTranslator::build_body(const std::string &app_id, const std::string &from,
					 const std::string &to, const std::string &text_b64)
{
	std::string body;
	body.reserve(text_b64.size() + 128);
	body += std::string("{\"common\":{\"app_id\":\"") + json_escape(app_id) + "\"},";
	body += std::string("\"business\":{\"from\":\"") + json_escape(from) + "\",\"to\":\"" +
		json_escape(to) + "\"},";
	body += std::string("\"data\":{\"text\":\"") + text_b64 + "\"}}";
	return body;
}

/* ---------------- 响应解析 ---------------- */

std::string XunfeiTranslator::parse_response(const std::string &response) const
{
	// 失败时服务端可能只给 {"message":"..."}（没有 code 字段）
	std::string message;
	std::string code;
	const bool has_code = json_find_string(response, "code", code);
	const bool has_message = json_find_string(response, "message", message);

	if (has_code && code != "0") {
		last_error_ = std::string("讯飞机器翻译返回错误 code=") + code +
			      (has_message ? std::string(" message=") + message : "");
		return std::string();
	}

	// 成功结构：{"code":0,"data":{"result":{"from":"cn","to":"en","trans_result":{"dst":"..."}}}}
	std::string dst;
	if (json_find_string(response, "dst", dst))
		return dst;

	// 兜底：个别情况 dst 可能是数组或字段名不同
	if (has_message && !has_code) {
		last_error_ = std::string("讯飞机器翻译鉴权/请求失败: ") + message;
	} else if (has_message && code != "0") {
		last_error_ = std::string("讯飞机器翻译失败 code=") + code + " message=" + message;
	} else {
		last_error_ = std::string("讯飞机器翻译响应无法解析: ") + response.substr(0, 300);
	}
	return std::string();
}

/* ---------------- 翻译主流程 ---------------- */

std::string XunfeiTranslator::translate(const std::string &text, const std::string &target_lang,
					const std::string &source_lang)
{
	last_error_.clear();

	if (text.empty())
		return std::string();
	if (api_key_.empty() || api_secret_.empty() || app_id_.empty()) {
		last_error_ = "讯飞翻译缺少 AppId / ApiKey / ApiSecret";
		throw TranslationError(last_error_);
	}

	bool from_ok = true;
	bool to_ok = true;
	std::string from = to_xunfei_lang(source_lang.empty() ? "auto" : source_lang, &from_ok);
	const std::string to = to_xunfei_lang(target_lang, &to_ok);

	if (!to_ok || to.empty()) {
		last_error_ = std::string("讯飞机器翻译不支持的目标语言: ") + target_lang;
		throw TranslationError(last_error_);
	}
	if (!from_ok || from.empty()) {
		// 讯飞要求 business.from 必填；源语言未知时按中文兜底并记录告警
		last_error_ = std::string("讯飞机器翻译不支持的源语言 ") + source_lang + "，已按 cn 处理";
		from = "cn";
	}

	// 文本需 base64 编码后放入 data.text
	const std::string text_b64 = base64_encode(text);
	const std::string body = build_body(app_id_, from, to, text_b64);

	if (body.size() > XF_TRANS_BODY_LIMIT) {
		last_error_ = std::string("待翻译文本过长（base64 后 ") + std::to_string(body.size()) +
			      " 字节，上限 " + std::to_string(XF_TRANS_BODY_LIMIT) + "）";
		throw TranslationError(last_error_);
	}

	// 鉴权头
	const std::string date = rfc1123_utc_now();
	const std::string digest = sha256_digest_header(body);
	const std::string request_line = std::string("POST ") + XF_TRANS_PATH + " HTTP/1.1";
	const std::string signature_origin = std::string("host: ") + XF_TRANS_HOST +
					     "\ndate: " + date + "\n" + request_line +
					     "\ndigest: " + digest;
	const std::string signature = hmac_sha256_base64(api_secret_, signature_origin);
	const std::string authorization = std::string("api_key=\"") + api_key_ +
					  "\", algorithm=\"hmac-sha256\", headers=\"host date "
					  "request-line digest\", signature=\"" +
					  signature + "\"";

	CURL *curl = curl_easy_init();
	if (curl == nullptr) {
		last_error_ = "curl_easy_init 失败";
		throw TranslationError(last_error_);
	}

	std::string response;
	struct curl_slist *headers = nullptr;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "Accept: application/json,version=1.0");
	headers = curl_slist_append(headers, (std::string("Host: ") + std::string(XF_TRANS_HOST)).c_str());
	headers = curl_slist_append(headers, (std::string("Date: ") + date).c_str());
	headers = curl_slist_append(headers, (std::string("Digest: ") + digest).c_str());
	headers = curl_slist_append(headers, (std::string("Authorization: ") + authorization).c_str());

	curl_easy_setopt(curl, CURLOPT_URL, XF_TRANS_URL);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	// 调试用：允许通过环境变量走代理（正式使用无需设置）
	if (const char *proxy = std::getenv("OBS_XUNFEI_PROXY"); proxy != nullptr && proxy[0] != 0)
		curl_easy_setopt(curl, CURLOPT_PROXY, proxy);

	const CURLcode rc = curl_easy_perform(curl);
	long http_code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	if (rc != CURLE_OK) {
		last_error_ = std::string("讯飞机器翻译网络请求失败: ") + curl_easy_strerror(rc);
		throw TranslationError(last_error_);
	}
	if (http_code != 200) {
		last_error_ = std::string("讯飞机器翻译 HTTP ") + std::to_string(http_code) +
			      " 响应: " + response.substr(0, 200);
		throw TranslationError(last_error_);
	}

	const std::string result = parse_response(response);
	if (result.empty() && last_error_.empty())
		last_error_ = "讯飞机器翻译返回空结果";
	return result;
}

} // namespace xunfei
