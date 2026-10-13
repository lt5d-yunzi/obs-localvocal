#include "xunfei-cloud.h"

#include "xunfei-translate.h"

namespace xunfei {

std::unique_ptr<ITranslator> createTranslatorFromConfig(const CloudTranslatorConfig &config)
{
	if (config.app_id.empty() || config.access_key.empty() || config.secret_key.empty()) {
		throw TranslationError(
			"讯飞翻译需要 AppId + ApiKey + ApiSecret 三项凭证（AppId 见讯飞控制台）");
	}
	return std::make_unique<XunfeiTranslator>(config.app_id, config.access_key,
						  config.secret_key);
}

} // namespace xunfei
