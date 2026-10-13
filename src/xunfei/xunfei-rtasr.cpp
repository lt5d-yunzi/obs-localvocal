#include "xunfei-rtasr.h"
#include "xunfei-json.h"
#include "xunfei-utils.h"
#include "xunfei-websocket.h"

#include <chrono>
#include <cstring>

namespace xunfei {

/* ---------------- 鉴权 ---------------- */

RtAsrAuth XunfeiRtAsr::make_auth(const std::string &appid, const std::string &api_key,
				const std::string &ts_in, const std::string &punc,
				const std::string &pd)
{
	RtAsrAuth auth;
	auth.appid = trim(appid);
	auth.ts = ts_in.empty() ? unix_timestamp_str() : ts_in;

	// signa = Base64(HMAC-SHA1(MD5hex(appid + ts), apiKey))
	const std::string base_string = auth.appid + auth.ts;
	const std::string md5 = md5_hex(base_string);
	auth.signa = hmac_sha1_base64(trim(api_key), md5);

	auth.url = std::string("wss://rtasr.xfyun.cn/v1/ws?appid=") + auth.appid + "&ts=" + auth.ts +
		   "&signa=" + auth.signa;
	if (!punc.empty())
		auth.url += std::string("&punc=") + punc;
	if (!pd.empty())
		auth.url += std::string("&pd=") + pd;

	return auth;
}

/* ---------------- 结果解析 ---------------- */

bool XunfeiRtAsr::parse_message(const std::string &message, RtAsrResult &out,
				std::string *error_out)
{
	std::string action;
	if (!json_find_string(message, "action", action)) {
		if (error_out)
			*error_out = std::string("响应缺少 action 字段: ") + message.substr(0, 200);
		return false;
	}

	if (action == "error") {
		std::string desc;
		std::string code;
		json_find_string(message, "desc", desc);
		json_find_string(message, "code", code);
		if (error_out)
			*error_out = std::string("RTASR 服务端错误 code=") + code + " desc=" + desc;
		return false;
	}

	if (action == "started") {
		if (error_out)
			error_out->clear();
		return false; // 只是握手确认，不是识别结果
	}

	if (action != "result") {
		if (error_out)
			*error_out = std::string("未知 action: ") + action;
		return false;
	}

	// 外层 code 非 0 视为错误
	long long code = 0;
	if (json_find_int(message, "code", code) && code != 0) {
		std::string desc;
		json_find_string(message, "desc", desc);
		if (error_out)
			*error_out = std::string("RTASR code=") + std::to_string(code) + " desc=" + desc;
		return false;
	}

	// data 是被转义的 JSON 字符串，需要再解析一层
	std::string data;
	if (!json_find_string(message, "data", data) || data.empty()) {
		if (error_out)
			*error_out = "响应缺少 data 字段";
		return false;
	}

	long long type = 0;
	if (!json_find_int(data, "type", type)) {
		if (error_out)
			*error_out = "data 中缺少 st.type，无法判定最终/中间结果";
		return false;
	}

	// 拼接 cn.st.rt[].ws[].cw[].w
	// 结构固定，用顺序扫描 cw 数组里的 "w" 字段即可
	std::string text;
	size_t pos = 0;
	for (;;) {
		const size_t cw = data.find("\"cw\"", pos);
		if (cw == std::string::npos)
			break;
		// 从这个 cw 数组的起点开始，收集其中所有 "w" 字段
		const size_t ws_arr = data.find('[', cw);
		if (ws_arr == std::string::npos)
			break;

		// 找到匹配的右括号（一层层数，避免跨元素误收集）
		int depth = 0;
		size_t end = ws_arr;
		for (; end < data.size(); ++end) {
			if (data[end] == '[')
				++depth;
			else if (data[end] == ']') {
				--depth;
				if (depth == 0)
					break;
			}
		}
		if (end >= data.size())
			break;

		const std::string segment = data.substr(ws_arr, end - ws_arr + 1);
		size_t wpos = 0;
		for (;;) {
			const size_t w = segment.find("\"w\"", wpos);
			if (w == std::string::npos)
				break;
			std::string word;
			if (json_find_string(segment.substr(w), "w", word))
				text += word;
			wpos = w + 3;
		}

		pos = end + 1;
	}

	if (text.empty()) {
		if (error_out)
			*error_out = "解析出的文本为空";
		return false;
	}

	out.text = text;
	out.type = (type == 0) ? RtAsrResult::FINAL : RtAsrResult::PARTIAL;
	out.timestamp_ms = 0;
	if (error_out)
		error_out->clear();
	return true;
}

/* ---------------- 生命周期 ---------------- */

XunfeiRtAsr::XunfeiRtAsr() = default;

XunfeiRtAsr::~XunfeiRtAsr()
{
	stop();
}

bool XunfeiRtAsr::start(const std::string &appid, const std::string &api_key,
			const std::string &punc, const std::string &pd, int connect_timeout_ms)
{
	if (running_.load())
		return false;

	appid_ = trim(appid);
	api_key_ = trim(api_key);
	punc_ = punc;
	pd_ = pd;
	connect_timeout_ms_ = connect_timeout_ms;

	if (appid_.empty() || api_key_.empty()) {
		emit_error("RTASR 启动失败：AppId 或 ApiKey 为空");
		return false;
	}

	{
		std::lock_guard<std::mutex> lock(queue_mutex_);
		audio_queue_.clear();
		queued_bytes_ = 0;
	}
	stop_requested_.store(false);
	bytes_sent_.store(0);
	running_.store(true);

	thread_ = std::thread([this]() { worker(); });
	return true;
}

void XunfeiRtAsr::push_audio(const void *pcm_s16le, size_t bytes)
{
	if (!running_.load() || pcm_s16le == nullptr || bytes == 0)
		return;

	// 队列上限：约 3 秒音频（16000 * 2 字节 * 3），防止网络卡顿时无限堆积内存
	constexpr size_t kMaxQueued = 16000 * 2 * 3;

	std::vector<uint8_t> chunk(static_cast<const uint8_t *>(pcm_s16le),
				   static_cast<const uint8_t *>(pcm_s16le) + bytes);
	{
		std::lock_guard<std::mutex> lock(queue_mutex_);
		if (queued_bytes_ + bytes > kMaxQueued) {
			// 丢最旧的，保实时性
			while (!audio_queue_.empty() && queued_bytes_ + bytes > kMaxQueued) {
				queued_bytes_ -= audio_queue_.front().size();
				audio_queue_.pop_front();
			}
		}
		queued_bytes_ += bytes;
		audio_queue_.push_back(std::move(chunk));
	}
	queue_cv_.notify_one();
}

void XunfeiRtAsr::stop()
{
	if (!running_.load() && !thread_.joinable())
		return;

	stop_requested_.store(true);
	queue_cv_.notify_all();

	if (thread_.joinable())
		thread_.join();

	running_.store(false);
	connected_.store(false);
}

void XunfeiRtAsr::emit_error(const std::string &msg)
{
	if (on_error_)
		on_error_(msg);
}

/* ---------------- 音频帧 ---------------- */

std::string XunfeiRtAsr::build_audio_frame(const void *data, size_t bytes, uint8_t status)
{
	/*
	 * 讯飞 RTASR 音频帧头 = 20 字节：
	 *   [0..3]  音频数据长度（大端 uint32，不含帧头自身）
	 *   [4..7]  帧状态（大端 uint32）：0=第一帧 1=中间帧 2=最后一帧
	 *   [8..15] 保留
	 *   [16..19]参数（0 = 不压缩 / 默认格式）
	 * 之后紧跟 PCM 数据（s16le）。结束帧没有数据，只发这 20 字节。
	 */
	const uint32_t audio_len = static_cast<uint32_t>(bytes);

	uint8_t header[20] = {0};
	header[0] = static_cast<uint8_t>((audio_len >> 24) & 0xFF);
	header[1] = static_cast<uint8_t>((audio_len >> 16) & 0xFF);
	header[2] = static_cast<uint8_t>((audio_len >> 8) & 0xFF);
	header[3] = static_cast<uint8_t>(audio_len & 0xFF);
	header[4] = 0;
	header[5] = 0;
	header[6] = 0;
	header[7] = status;

	std::string frame(header, header + sizeof(header));
	if (bytes > 0 && data != nullptr)
		frame.append(static_cast<const char *>(data), bytes);
	return frame;
}

/* ---------------- 工作线程 ---------------- */

void XunfeiRtAsr::worker()
{
	const RtAsrAuth auth = make_auth(appid_, api_key_, std::string(), punc_, pd_);

	WebSocketClient ws;
	ws.set_verify_peer(verify_peer_);

	const WsResult conn = ws.connect(auth.url, {}, connect_timeout_ms_);
	if (!conn.ok) {
		emit_error(std::string("RTASR 连接失败: ") + conn.error);
		running_.store(false);
		return;
	}
	connected_.store(true);

	// 讯飞建议每 40ms 一帧（1280 字节 = 640 采样点）
	constexpr size_t kFrameBytes = 1280;
	// 维护一个发送缓冲区，把上游不定长数据切成固定 40ms 帧
	std::vector<uint8_t> pending;
	pending.reserve(kFrameBytes * 4);

	bool first_frame_sent = false;
	bool closed = false;
	std::string ws_error;

	auto flush_frames = [&](bool force_remainder) -> bool {
		while (pending.size() >= kFrameBytes ||
		       (force_remainder && !pending.empty())) {
			const size_t take = pending.size() >= kFrameBytes ? kFrameBytes : pending.size();
			const uint8_t status = first_frame_sent ? 1 : 0;
			const std::string frame = build_audio_frame(pending.data(), take, status);

			std::string err;
			const WsResult wr = ws.send_binary(frame.data(), frame.size());
			if (!wr.ok) {
				ws_error = wr.error;
				return false;
			}
			bytes_sent_.fetch_add(take);
			first_frame_sent = true;
			pending.erase(pending.begin(), pending.begin() + static_cast<long>(take));
		}
		return true;
	};

	while (!stop_requested_.load()) {
		// 1) 取出音频，切成帧发出去
		{
			std::unique_lock<std::mutex> lock(queue_mutex_);
			if (audio_queue_.empty()) {
				queue_cv_.wait_for(lock, std::chrono::milliseconds(20));
			}
			while (!audio_queue_.empty()) {
				auto &front = audio_queue_.front();
				pending.insert(pending.end(), front.begin(), front.end());
				queued_bytes_ -= front.size();
				audio_queue_.pop_front();
			}
		}

		if (!flush_frames(false)) {
			emit_error(std::string("RTASR 发送音频失败: ") + ws_error);
			break;
		}

		// 2) 收结果（非阻塞，把缓冲区里的都处理掉）
		const bool alive = ws.poll(0, [this](const WsFrame &frame) {
			if (frame.opcode != WsFrame::TEXT && frame.opcode != WsFrame::BINARY)
				return;
			RtAsrResult result;
			std::string err;
			if (parse_message(frame.payload, result, &err)) {
				if (on_result_)
					on_result_(result);
			} else if (!err.empty()) {
				// "started" 之类的正常消息不当作错误
				if (err.find("未知 action") != std::string::npos ||
				    err.find("服务端错误") != std::string::npos)
					emit_error(std::string("RTASR: ") + err);
			}
		}, &ws_error);

		if (!alive) {
			if (!stop_requested_.load())
				emit_error(std::string("RTASR 连接中断: ") + ws_error);
			closed = true;
			break;
		}
	}

	// 收尾：把剩余音频发完，再发结束帧（只有 4 字节状态头，status=2）
	if (!closed) {
		flush_frames(true);
		// 结束帧：只有 20 字节帧头，状态位 = 2
		const std::string end_frame = build_audio_frame(nullptr, 0, 2);
		ws.send_binary(end_frame.data(), end_frame.size());
		ws.send_close();
	}

	ws.close();
	connected_.store(false);
	running_.store(false);
}

} // namespace xunfei
