/**
 * xunfei-translate.h
 *
 * 讯飞机器翻译（itrans.xfyun.cn/v2/its）的 ITranslator 实现。
 *
 * 挂接方式：在 cloud-translation/translation-cloud.cpp 的 createTranslator() 中
 * 注册 provider == "xunfei"，即可在「云翻译」下拉框中使用。
 *
 * 与其它云翻译 provider 的区别：讯飞需要 AppId + ApiKey + ApiSecret 三件套，
 * 因此 CloudTranslatorConfig 需要额外携带 app_id（见补丁说明）。
 */

#ifndef XUNFEI_TRANSLATE_H
#define XUNFEI_TRANSLATE_H

#include <string>

#include "translation/cloud-translation/ITranslator.h"

namespace xunfei {

class XunfeiTranslator : public ITranslator {
public:
	/**
	 * @param app_id     讯飞控制台的 AppId
	 * @param api_key    机器翻译服务的 APIKey
	 * @param api_secret 机器翻译服务的 APISecret
	 */
	XunfeiTranslator(const std::string &app_id, const std::string &api_key,
			 const std::string &api_secret);
	~XunfeiTranslator() override;

	std::string translate(const std::string &text, const std::string &target_lang,
			      const std::string &source_lang = "auto") override;

	/** 最近一次错误的可读描述（便于插件日志输出） */
	const std::string &last_error() const { return last_error_; }

private:
	/** 组装请求 body（text 需为 base64 后的内容） */
	static std::string build_body(const std::string &app_id, const std::string &from,
				      const std::string &to, const std::string &text_b64);
	/** 解析响应，返回译文；失败时写 last_error_ */
	std::string parse_response(const std::string &response) const;

	std::string app_id_;
	std::string api_key_;
	std::string api_secret_;
	mutable std::string last_error_;
};

} // namespace xunfei

#endif // XUNFEI_TRANSLATE_H
