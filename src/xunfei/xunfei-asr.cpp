#include "xunfei-asr.h"

#include "xunfei-rtasr.h"

#include "transcription-filter-data.h"
#include "transcription-filter-utils.h"
#include "transcription-utils.h"
#include "plugin-support.h"

#include <media-io/audio-resampler.h>
#include <obs-module.h>

#include <algorithm>
#include <cstring>

namespace xunfei {

namespace {

/** 讯飞 RTASR 要求的采样率 */
constexpr uint32_t kTargetRate = 16000;
/** 每帧 40ms = 640 采样点 = 1280 字节 s16le（讯飞建议的节奏） */
constexpr size_t kFrameSamples = kTargetRate / 25;
/** 结果队列上限，防止下游卡住时内存无限增长 */
constexpr size_t kMaxQueuedResults = 64;

/** float32 [-1,1] 转 s16le */
inline int16_t float_to_s16(float v)
{
	if (v > 1.0f)
		v = 1.0f;
	else if (v < -1.0f)
		v = -1.0f;
	return static_cast<int16_t>(v * 32767.0f);
}

} // namespace

/* ---------------- 启动 / 停止 ---------------- */

bool xf_start(transcription_filter_data *gf, const std::string &app_id,
	      const std::string &api_key, bool punc, const std::string &pd)
{
	if (gf == nullptr)
		return false;

	xf_stop(gf);

	gf->xunfei_ctx = new XunfeiAsrContext();

	// 1) 重采样器：输入按 OBS 当前音频格式，输出 16kHz / 单声道 / float32
	//    注意：OBS 滤镜收到的音频是「平面(planar)」格式，每个声道一段连续内存；
	//    格式统一用 AUDIO_FORMAT_FLOAT_PLANAR（与工程里 whisper 重采样器一致）。
	struct resample_info src_info = {};
	struct resample_info dst_info = {};

	src_info.format = AUDIO_FORMAT_FLOAT_PLANAR;
	src_info.samples_per_sec = gf->sample_rate;
	src_info.speakers = convert_speaker_layout(static_cast<uint8_t>(gf->channels));

	dst_info.format = AUDIO_FORMAT_FLOAT_PLANAR;
	dst_info.samples_per_sec = kTargetRate;
	dst_info.speakers = convert_speaker_layout(1); // 直接由重采样器下混为单声道

	static_cast<XunfeiAsrContext *>(gf->xunfei_ctx)->resampler =
		audio_resampler_create(&dst_info, &src_info);
	if (static_cast<XunfeiAsrContext *>(gf->xunfei_ctx)->resampler == nullptr) {
		obs_log(LOG_ERROR, "[讯飞ASR] 创建重采样器失败（%u Hz / %zu 声道 → 16kHz mono）",
			gf->sample_rate, gf->channels);
		delete static_cast<XunfeiAsrContext *>(gf->xunfei_ctx);
		gf->xunfei_ctx = nullptr;
		return false;
	}

	// 2) RTASR 客户端
	auto *client = new XunfeiRtAsr();
	auto *ctx = static_cast<XunfeiAsrContext *>(gf->xunfei_ctx);

	client->set_result_callback([ctx](const RtAsrResult &r) {
		std::lock_guard<std::mutex> lock(ctx->results_mutex);
		if (ctx->results.size() >= kMaxQueuedResults) {
			ctx->results.pop_front();
			++ctx->dropped_results;
		}
		XfAsrPendingResult pending;
		pending.text = r.text;
		pending.is_final = (r.type == RtAsrResult::FINAL);
		pending.ts_ms = now_ms();
		ctx->results.push_back(std::move(pending));
	});

	client->set_error_callback([](const std::string &msg) {
		obs_log(LOG_WARNING, "[讯飞ASR] %s", msg.c_str());
	});

	if (!client->start(app_id, api_key, punc ? "1" : "0", pd == "none" ? "" : pd)) {
		obs_log(LOG_ERROR, "[讯飞ASR] 启动失败：请检查 AppId / ApiKey");
		delete client;
		xf_stop(gf);
		return false;
	}

	ctx->rtasr = client;
	ctx->started = true;
	ctx->last_result_ms = now_ms();

	obs_log(LOG_INFO,
		"[讯飞ASR] 已启动（RTASR，标点=%s，领域=%s），音频将按 40ms 帧推流",
		punc ? "on" : "off", pd.c_str());
	return true;
}

void xf_stop(transcription_filter_data *gf)
{
	if (gf == nullptr || !gf->xunfei_ctx)
		return;

	auto *ctx = static_cast<XunfeiAsrContext *>(gf->xunfei_ctx);

	if (ctx->rtasr != nullptr) {
		static_cast<XunfeiRtAsr *>(ctx->rtasr)->stop();
		delete static_cast<XunfeiRtAsr *>(ctx->rtasr);
		ctx->rtasr = nullptr;
	}
	if (ctx->resampler != nullptr) {
		audio_resampler_destroy(static_cast<audio_resampler_t *>(ctx->resampler));
		ctx->resampler = nullptr;
	}

	ctx->started = false;
	{
		std::lock_guard<std::mutex> lock(ctx->results_mutex);
		ctx->results.clear();
	}

	obs_log(LOG_INFO, "[讯飞ASR] 已停止（累计发送音频 %.1f 秒，丢弃结果 %llu 条）",
		static_cast<double>(ctx->samples_sent) / kTargetRate,
		static_cast<unsigned long long>(ctx->dropped_results));

	delete static_cast<XunfeiAsrContext *>(gf->xunfei_ctx);
	gf->xunfei_ctx = nullptr;
}

bool xf_is_running(const transcription_filter_data *gf)
{
	if (gf == nullptr || gf->xunfei_ctx == nullptr)
		return false;
	return static_cast<XunfeiAsrContext *>(gf->xunfei_ctx)->started;
}

/* ---------------- 音频推流 ---------------- */

void xf_push_audio(transcription_filter_data *gf, const uint8_t *const *audio_data,
		   uint32_t frames, size_t channels, uint32_t sample_rate)
{
	if (gf == nullptr || gf->xunfei_ctx == nullptr ||
	    !static_cast<XunfeiAsrContext *>(gf->xunfei_ctx)->started)
		return;
	if (audio_data == nullptr || audio_data[0] == nullptr || frames == 0)
		return;
	// 采样率由重采样器在创建时（xf_start）按 gf->sample_rate 固定，这里不再需要
	UNUSED_PARAMETER(sample_rate);

	auto *ctx = static_cast<XunfeiAsrContext *>(gf->xunfei_ctx);
	auto *resampler = static_cast<audio_resampler_t *>(ctx->resampler);
	if (resampler == nullptr)
		return;

	// 1) 交给重采样器完成「多声道 → 单声道 + 任意采样率 → 16kHz」
	//    OBS 的 obs_audio_data.data 是平面(planar) float，每声道一段连续内存，
	//    类型上声明为 uint8_t*，这里直接按平面透传给重采样器（格式已声明为 FLOAT_PLANAR）。
	const uint8_t *in_planes[MAX_PREPROC_CHANNELS] = {0};
	const size_t usable = std::min(channels, static_cast<size_t>(MAX_PREPROC_CHANNELS));
	for (size_t c = 0; c < usable; ++c)
		in_planes[c] = audio_data[c];

	float *out_planes[MAX_PREPROC_CHANNELS] = {0};
	uint32_t out_frames = 0;
	uint64_t ts_offset = 0;
	const bool resampled = audio_resampler_resample(
		resampler, reinterpret_cast<uint8_t **>(out_planes), &out_frames, &ts_offset,
		in_planes, frames);
	if (!resampled) {
		return;
	}
	if (out_frames == 0 || out_planes[0] == nullptr)
		return;

	// 2) 累积到 40ms 再以 16bit 字节流推给 RTASR
	ctx->pending_pcm.insert(ctx->pending_pcm.end(), out_planes[0],
				out_planes[0] + out_frames);

	while (ctx->pending_pcm.size() >= kFrameSamples) {
		int16_t pcm16[kFrameSamples];
		for (size_t i = 0; i < kFrameSamples; ++i)
			pcm16[i] = float_to_s16(ctx->pending_pcm[i]);

		static_cast<XunfeiRtAsr *>(ctx->rtasr)
			->push_audio(pcm16, sizeof(pcm16));

		ctx->samples_sent += kFrameSamples;
		ctx->pending_pcm.erase(ctx->pending_pcm.begin(),
				       ctx->pending_pcm.begin() +
					       static_cast<long>(kFrameSamples));
	}
}

/* ---------------- 结果派发 ---------------- */

int xf_drain_results(transcription_filter_data *gf)
{
	if (gf == nullptr || !gf->xunfei_ctx)
		return 0;

	auto *ctx = static_cast<XunfeiAsrContext *>(gf->xunfei_ctx);
	std::deque<XfAsrPendingResult> batch;
	{
		std::lock_guard<std::mutex> lock(ctx->results_mutex);
		if (ctx->results.empty())
			return 0;
		batch.swap(ctx->results);
	}

	const uint64_t now = now_ms();
	int dispatched = 0;
	for (const auto &item : batch) {
		if (item.text.empty())
			continue;

		DetectionResultWithText result;
		result.result = item.is_final ? DETECTION_RESULT_SPEECH : DETECTION_RESULT_PARTIAL;
		result.text = item.text;
		// 用「当前时间 - 估算语句时长」作为起始时间；字幕排序与过期判断只需要单调性
		const uint64_t estimated_ms = static_cast<uint64_t>(item.text.size()) * 120; // 粗估
		result.start_timestamp_ms = now > estimated_ms ? now - estimated_ms : 0;
		result.end_timestamp_ms = now;
		result.language = gf->xunfei_language; // 讯飞 RTASR 当前仅中文普通话

		// 复用 localvocal 既有的字幕输出链路（云翻译 / 本地翻译 / 文件 / WebVTT 全部生效）
		set_text_callback(now, gf, result);

		ctx->last_result_ms = now;
		++dispatched;

		obs_log(gf->log_level, "[讯飞ASR] %s: %s", item.is_final ? "最终" : "中间",
			item.text.c_str());
	}

	return dispatched;
}

double xf_audio_seconds_sent(const transcription_filter_data *gf)
{
	if (gf == nullptr || !gf->xunfei_ctx)
		return 0.0;
	return static_cast<double>(static_cast<XunfeiAsrContext *>(gf->xunfei_ctx)->samples_sent) /
	       kTargetRate;
}

} // namespace xunfei
