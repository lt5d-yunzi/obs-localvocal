/**
 * xunfei-cloud.h
 *
 * 把讯飞机器翻译接进 obs-localvocal 的「云翻译」体系的桥接层。
 *
 * 为什么要单独一层：
 *   localvocal 的 createTranslator() 里每个 provider 一行分支，直接用
 *   XunfeiTranslator 的构造函数签名（三个参数）会让那一行长到难读；
 *   这里把「从 config 取哪三个字段」的知识收敛到一处，主体只需加一行。
 */

#ifndef XUNFEI_CLOUD_H
#define XUNFEI_CLOUD_H

#include <memory>

#include "translation/cloud-translation/ITranslator.h"
#include "translation/cloud-translation/translation-cloud.h"

namespace xunfei {

/**
 * 依据 CloudTranslatorConfig 创建讯飞机器翻译器。
 * 字段约定：
 *   config.app_id      -> 讯飞 AppId
 *   config.access_key  -> 机器翻译 APIKey
 *   config.secret_key  -> 机器翻译 APISecret
 *
 * @throws TranslationError 缺少必要凭证时抛出（与其它 provider 行为一致）
 */
std::unique_ptr<ITranslator> createTranslatorFromConfig(const CloudTranslatorConfig &config);

/** 讯飞 provider 在 obs_data 中的标识字符串 */
constexpr const char *kXunfeiProviderId = "xunfei";

/** 讯飞云翻译在 UI 上的显示名（同时用于 locale key 回退） */
constexpr const char *kXunfeiProviderName = "Xunfei-Translate";

} // namespace xunfei

#endif // XUNFEI_CLOUD_H
