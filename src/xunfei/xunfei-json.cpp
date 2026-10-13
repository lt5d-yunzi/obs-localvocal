#include "xunfei-json.h"

#include <cctype>
#include <cstdio>

namespace xunfei {

std::string json_unescape(const std::string &escaped)
{
	std::string out;
	out.reserve(escaped.size());

	for (size_t i = 0; i < escaped.size(); ++i) {
		const char c = escaped[i];
		if (c != '\\' || i + 1 >= escaped.size()) {
			out += c;
			continue;
		}

		const char esc = escaped[++i];
		switch (esc) {
		case 'n':
			out += '\n';
			break;
		case 't':
			out += '\t';
			break;
		case 'r':
			out += '\r';
			break;
		case 'b':
			out += '\b';
			break;
		case 'f':
			out += '\f';
			break;
		case '"':
			out += '"';
			break;
		case '\\':
			out += '\\';
			break;
		case '/':
			out += '/';
			break;
		case 'u': {
			if (i + 4 >= escaped.size())
				break;
			unsigned int cp = 0;
			for (int k = 0; k < 4; ++k) {
				const char h = escaped[i + 1 + k];
				cp <<= 4;
				if (h >= '0' && h <= '9')
					cp |= unsigned(h - '0');
				else if (h >= 'a' && h <= 'f')
					cp |= unsigned(h - 'a' + 10);
				else if (h >= 'A' && h <= 'F')
					cp |= unsigned(h - 'A' + 10);
			}
			i += 4;

			// 代理对（surrogate pair）拼接
			if (cp >= 0xD800 && cp <= 0xDBFF && i + 6 < escaped.size() &&
			    escaped[i + 1] == '\\' && escaped[i + 2] == 'u') {
				unsigned int low = 0;
				bool ok = true;
				for (int k = 0; k < 4; ++k) {
					const char h = escaped[i + 3 + k];
					if (!isxdigit(static_cast<unsigned char>(h))) {
						ok = false;
						break;
					}
					low <<= 4;
					if (h >= '0' && h <= '9')
						low |= unsigned(h - '0');
					else if (h >= 'a' && h <= 'f')
						low |= unsigned(h - 'a' + 10);
					else
						low |= unsigned(h - 'A' + 10);
				}
				if (ok && low >= 0xDC00 && low <= 0xDFFF) {
					cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
					i += 6;
				}
			}

			// UTF-8 编码
			if (cp < 0x80) {
				out += char(cp);
			} else if (cp < 0x800) {
				out += char(0xC0 | (cp >> 6));
				out += char(0x80 | (cp & 0x3F));
			} else if (cp < 0x10000) {
				out += char(0xE0 | (cp >> 12));
				out += char(0x80 | ((cp >> 6) & 0x3F));
				out += char(0x80 | (cp & 0x3F));
			} else {
				out += char(0xF0 | (cp >> 18));
				out += char(0x80 | ((cp >> 12) & 0x3F));
				out += char(0x80 | ((cp >> 6) & 0x3F));
				out += char(0x80 | (cp & 0x3F));
			}
			break;
		}
		default:
			out += esc;
			break;
		}
	}
	return out;
}

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
	while (pos < json.size() &&
	       (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r'))
		++pos;

	if (pos >= json.size() || json[pos] != '"')
		return false;
	++pos;

	std::string raw;
	while (pos < json.size() && json[pos] != '"') {
		if (json[pos] == '\\' && pos + 1 < json.size()) {
			raw += json[pos];
			raw += json[pos + 1];
			pos += 2;
			continue;
		}
		raw += json[pos];
		++pos;
	}
	out = json_unescape(raw);
	return true;
}

bool json_find_int(const std::string &json, const std::string &key, long long &out)
{
	const std::string needle = std::string("\"") + key + "\"";
	size_t pos = json.find(needle);
	if (pos == std::string::npos)
		return false;

	pos = json.find(':', pos + needle.size());
	if (pos == std::string::npos)
		return false;
	++pos;
	while (pos < json.size() &&
	       (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r'))
		++pos;

	// 也可能是字符串形式的数字
	const bool quoted = (pos < json.size() && json[pos] == '"');
	if (quoted)
		++pos;

	bool negative = false;
	if (pos < json.size() && (json[pos] == '-' || json[pos] == '+')) {
		negative = (json[pos] == '-');
		++pos;
	}

	long long value = 0;
	bool any = false;
	while (pos < json.size() && isdigit(static_cast<unsigned char>(json[pos]))) {
		value = value * 10 + (json[pos] - '0');
		++pos;
		any = true;
	}
	if (!any)
		return false;

	out = negative ? -value : value;
	return true;
}

} // namespace xunfei
