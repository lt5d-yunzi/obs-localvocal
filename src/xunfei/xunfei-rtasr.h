/**
 * xunfei-rtasr.h
 *
 * 讯飞「实时语音转写」(RTASR) 客户端。
 *
 * 与普通 WebSocket 服务的区别（易踩坑点）：
 *  1. 鉴权放在 URL query 上：wss://rtasr.xfyun.cn/v1/ws?appid=..&ts=..&signa=..
 *     其中 signa = Base64(HMAC-SHA1(MD5(appid + ts), apiKey))
 *  2. 音频必须按帧推送，每帧 = 4 字节大端状态头 + PCM 数据
 *     状态：0 = 第一帧，1 = 中间帧，2 = 最后一帧
 *  3. 音频格式：16kHz、16bit、单声道（pcm_s16le）
 *  4. 结束时要发一帧只有 4 字节状态头(2) 的空帧，而不是 JSON 文本
 *  5. 服务端返回 {"action":"result","code":"0","data":"<JSON字符串>"}，
 *     data 里是 cn.st.rt[].ws[].cw[].w 拼接出的文本，type 区分最终/中间结果
 *
 * 线程模型：单独一条线程负责「收音频队列 -> 发送 -> 接收结果」，
 * 因此音频推送与结果消费是跨线程安全的（内部有互斥+条件变量）。
 */

#ifndef XUNFEI_RTASR_H
#define XUNFEI_RTASR_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace xunfei {

/** 一条识别结果 */
struct RtAsrResult {
	enum Type {
		PARTIAL, ///< 中间结果（type=1，会随后被修正）
		FINAL,   ///< 最终结果（type=0）
	} type = PARTIAL;
	std::string text;
	uint64_t timestamp_ms = 0;
};

/** RTASR 鉴权参数（可单独构造，便于测试） */
struct RtAsrAuth {
	std::string appid;
	std::string ts;
	std::string signa;
	/** 完整连接 URL */
	std::string url;
};

class XunfeiRtAsr {
public:
	using ResultCallback = std::function<void(const RtAsrResult &)>;
	using ErrorCallback = std::function<void(const std::string &)>;

	XunfeiRtAsr();
	~XunfeiRtAsr();

	XunfeiRtAsr(const XunfeiRtAsr &) = delete;
	XunfeiRtAsr &operator=(const XunfeiRtAsr &) = delete;

	/**
	 * 构造连接 URL 与鉴权参数（不发起连接，便于单测）
	 * @param appid   讯飞 AppId
	 * @param api_key 实时语音转写的 APIKey
	 * @param ts      Unix 秒级时间戳字符串；为空则取当前时间
	 * @param punc    是否启用标点（"1"/"0"），空则不传
	 * @param pd      领域优化（court/edu/finance/medical/tech），空则不传
	 */
	static RtAsrAuth make_auth(const std::string &appid, const std::string &api_key,
				   const std::string &ts = std::string(),
				   const std::string &punc = std::string(),
				   const std::string &pd = std::string());

	/**
	 * 解析服务端返回的一条文本消息。
	 * @return true 表示解析出一条可用结果（写入 out）
	 */
	static bool parse_message(const std::string &message, RtAsrResult &out,
				  std::string *error_out = nullptr);

	/**
	 * 启动：建立连接并开启工作线程。
	 * @param appid/api_key 凭证
	 * @param punc/pd       可选参数
	 * @return true 表示启动流程成功受理（真正的连接错误通过 on_error 回调上报）
	 */
	bool start(const std::string &appid, const std::string &api_key,
		   const std::string &punc = std::string(), const std::string &pd = std::string(),
		   int connect_timeout_ms = 10000);

	/** 推送一段 16kHz/16bit/单声道 PCM（s16le，字节流） */
	void push_audio(const void *pcm_s16le, size_t bytes);

	/** 停止：发送结束帧、关闭连接、回收线程 */
	void stop();

	bool is_running() const { return running_.load(); }
	bool is_connected() const { return connected_.load(); }

	void set_result_callback(ResultCallback cb) { on_result_ = std::move(cb); }
	void set_error_callback(ErrorCallback cb) { on_error_ = std::move(cb); }

	/** 是否校验证书（默认开启） */
	void set_verify_peer(bool v) { verify_peer_ = v; }

	/** 累计发送的音频字节数（调试用） */
	size_t bytes_sent() const { return bytes_sent_.load(); }

private:
	void worker();
	/** 构造一帧讯飞 RTASR 音频帧（20 字节帧头 + PCM），返回待发送的字节串 */
	static std::string build_audio_frame(const void *data, size_t bytes, uint8_t status);
	void emit_error(const std::string &msg);

	std::thread thread_;
	std::atomic<bool> running_{false};
	std::atomic<bool> connected_{false};
	std::atomic<bool> stop_requested_{false};
	std::atomic<size_t> bytes_sent_{0};

	std::mutex queue_mutex_;
	std::condition_variable queue_cv_;
	std::deque<std::vector<uint8_t>> audio_queue_;
	size_t queued_bytes_ = 0;

	std::string appid_;
	std::string api_key_;
	std::string punc_;
	std::string pd_;
	int connect_timeout_ms_ = 10000;
	bool verify_peer_ = true;

	ResultCallback on_result_;
	ErrorCallback on_error_;
};

} // namespace xunfei

#endif // XUNFEI_RTASR_H
