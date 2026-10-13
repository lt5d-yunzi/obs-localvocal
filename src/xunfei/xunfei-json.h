/**
 * xunfei-json.h
 *
 * 一个极小的 JSON 取值工具（只做「按 key 找字符串/整数」这件事）。
 *
 * 为什么不引入 nlohmann/json：obs-localvocal 里确实有 nlohmann/json，
 * 但讯飞接口只用到几个固定字段的读取；而 RTASR 的返回结构是
 * 「JSON 里套一层被转义的 JSON 字符串」，自己处理会直白得多。
 * 需要更复杂解析时再换库不迟。
 */

#ifndef XUNFEI_JSON_H
#define XUNFEI_JSON_H

#include <cstdint>
#include <string>

namespace xunfei {

/**
 * 在 JSON 文本中查找 `"key"` 之后出现的第一个字符串值。
 * 支持 \" \\ \/ \b \f \n \r \t \uXXXX 转义。
 * @return 找到返回 true；out 为反转义后的值
 */
bool json_find_string(const std::string &json, const std::string &key, std::string &out);

/**
 * 查找 `"key"` 之后的第一个数字（含负号）。
 * @return 找到返回 true
 */
bool json_find_int(const std::string &json, const std::string &key, long long &out);

/** 把 JSON 字符串字面量内容反转义（不带外层引号） */
std::string json_unescape(const std::string &escaped);

} // namespace xunfei

#endif // XUNFEI_JSON_H
