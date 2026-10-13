/**
 * xunfei-utils.h
 *
 * 讯飞协议公共工具层：Base64 / SHA1 / HMAC-SHA256 / RFC1123 时间 / 语言代码映射。
 *
 * 设计说明：
 *  - SHA256 复用 obs-localvocal 自带的 src/model-utils/sha256.h（无外部依赖）。
 *  - SHA1 / Base64 为本文件自带实现，避免引入 OpenSSL 依赖（OBS 插件分发时
 *    少一个动态库就少一堆麻烦）。
 */

#ifndef XUNFEI_UTILS_H
#define XUNFEI_UTILS_H

#include <cstdint>
#include <string>
#include <vector>

namespace xunfei {

/* ---------------- Base64 ---------------- */

std::string base64_encode(const uint8_t *data, size_t len);
std::string base64_encode(const std::string &data);
/** 解码，遇到非法字符返回空串 */
std::string base64_decode(const std::string &encoded);

/* ---------------- SHA1 ---------------- */

/** 返回 20 字节原始摘要 */
void sha1_raw(const uint8_t *data, size_t len, uint8_t out[20]);
/** 返回 40 位小写十六进制 */
std::string sha1_hex(const std::string &data);
/** 返回 Base64 编码的摘要（WebSocket 握手的 Sec-WebSocket-Accept 用） */
std::string sha1_base64(const std::string &data);
/** MD5，返回 32 位小写十六进制（讯飞 RTASR 鉴权链第一步） */
std::string md5_hex(const std::string &data);
/** HMAC-SHA1，返回 Base64 编码结果（讯飞 RTASR signa） */
std::string hmac_sha1_base64(const std::string &key, const std::string &data);

/* ---------------- SHA256 / HMAC ---------------- */

/** 返回 Base64 编码的 SHA256 摘要（讯飞 Digest 头用，带 "SHA-256=" 前缀） */
std::string sha256_digest_header(const std::string &body);
/** HMAC-SHA256，返回 Base64 编码结果 */
std::string hmac_sha256_base64(const std::string &key, const std::string &data);

/* ---------------- 时间 ---------------- */

/** RFC1123 格式 UTC 时间，如 "Wed, 20 Nov 2019 03:14:25 GMT" */
std::string rfc1123_utc_now();
/** 当前 Unix 秒级时间戳的字符串形式 */
std::string unix_timestamp_str();

/* ---------------- 随机 ---------------- */

/** 生成 WebSocket 握手用的 16 字节随机 Key（Base64 编码返回） */
std::string websocket_key();

/* ---------------- 语言代码 ---------------- */

/**
 * 把 obs-localvocal / whisper 的语言代码（如 "zh"、"zh-cn"、"en"）映射为
 * 讯飞机器翻译使用的短码（cn/en/ja/ko/fr/es/ru/ar/th/yue）。
 *
 * @param lang 输入语言代码
 * @param ok   可选输出参数，表示是否为讯飞支持的语言
 * @return 讯飞语言短码；不支持时返回空字符串
 */
std::string to_xunfei_lang(const std::string &lang, bool *ok = nullptr);

/** 讯飞机器翻译支持的语言短码 -> 人类可读名称 */
std::vector<std::pair<std::string, std::string>> xunfei_language_table();

/* ---------------- 字符串 ---------------- */

bool starts_with(const std::string &s, const std::string &prefix);
std::string trim(const std::string &s);
/** 最小 JSON 字符串转义（含控制字符） */
std::string json_escape(const std::string &s);

} // namespace xunfei

#endif // XUNFEI_UTILS_H
