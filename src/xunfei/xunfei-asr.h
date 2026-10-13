/**
 * xunfei-asr.h
 *
 * 把讯飞 RTASR 接进 obs-localvocal 滤镜的适配层。
 *
 * 职责边界：
 *   - 本文件负责「OBS 音频 → 16kHz/mono/s16le → RTASR → 字幕结果」这段胶水；
 *   - 协议细节全部在 xunfei-rtasr.cpp / xunfei-websocket.cpp 里；
 *   - 显示与翻译交给 localvocal 既有的 set_text_callback 链路，
 *     因此「云翻译（含讯飞机器翻译）」对讯飞 ASR 是自动生效的。
 *
 * 线程模型：
 *   filter_audio 在 OBS 音频线程调用 xf_push_audio（只做重采样 + 入队），
 *   RTASR 自己的线程负责发送与接收，结果进队列；
 *   OBS 的 whisper 线程每轮调用 xf_drain_results 把结果转成字幕。
 *   这样字幕输出仍然发生在原有线程上，不破坏 localvocal 的既有并发假设。
 */

#ifndef XUNFEI_ASR_H
#define XUNFEI_ASR_H

#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

struct transcription_filter_data;

namespace xunfei {

/** 一条待派发的识别结果 */
struct XfAsrPendingResult {
	std::string text;
	bool is_final = false;
	uint64_t ts_ms = 0;
};

struct XunfeiAsrContext {
	/** 重采样目标：16kHz / 单声道 / float32 */
	void *resampler = nullptr; // audio_resampler_t*
	bool started = false;
	/** 讯飞 RTASR 客户端（xunfei::XunfeiRtAsr*） */
	void *rtasr = nullptr;

	/** 结果队列：RTASR 线程入队、whisper 线程出队 */
	std::mutex results_mutex;
	std::deque<XfAsrPendingResult> results;

	/** 推流累积缓冲（16kHz mono float32），按 40ms 一帧推给 RTASR */
	std::vector<float> pending_pcm;
	/** 已发送音频总采样数（16kHz 计） */
	uint64_t samples_sent = 0;
	/** 最近一次结果派发时间（用于字幕过期清理） */
	uint64_t last_result_ms = 0;
	/** 累计丢弃的结果条数（队列上限保护） */
	uint64_t dropped_results = 0;
};

/**
 * 启动讯飞 ASR（幂等：已启动则先停止再重启）。
 * @param gf          滤镜上下文
 * @param app_id/api_key 讯飞「实时语音转写」凭证
 * @param punc        是否启用标点
 * @param pd          领域优化（none/court/edu/finance/medical/tech）
 * @return true 表示启动成功
 */
bool xf_start(transcription_filter_data *gf, const std::string &app_id,
	      const std::string &api_key, bool punc, const std::string &pd);

/** 停止并释放资源（幂等，可在 destroy 中无条件调用） */
void xf_stop(transcription_filter_data *gf);

/** 是否已启动 */
bool xf_is_running(const transcription_filter_data *gf);

/**
 * 推送一帧 OBS 音频（interleaved float32）。
 * 会做下混/重采样，并按内部缓冲节奏喂给 RTASR。
 */
void xf_push_audio(transcription_filter_data *gf, const uint8_t *const *audio_data,
		   uint32_t frames, size_t channels, uint32_t sample_rate);

/**
 * 取出并派发已到达的识别结果（转成字幕）。
 * 由 whisper 线程每轮调用；返回本次派发的条数。
 */
int xf_drain_results(transcription_filter_data *gf);

/** 已发送给讯飞的音频秒数（用于日志/调试） */
double xf_audio_seconds_sent(const transcription_filter_data *gf);

} // namespace xunfei

#endif // XUNFEI_ASR_H
