#!/usr/bin/env python3
"""
本地 WebSocket 回显服务端 —— 用于在没有真实讯飞凭证的情况下，
端到端验证 xunfei-websocket.cpp 的握手与帧收发路径。

用法: python3 ws_echo_server.py [port]
行为:
  - 完成 RFC6455 握手（校验 Sec-WebSocket-Key，返回正确的 Accept）
  - 对每个收到的 text/binary 帧原样回显（text 回 text，binary 回 binary）
  - 收到 payload == b'__ping__' 时主动发一个 ping 帧
  - 收到 close 帧后响应 close 并退出
"""
import base64
import hashlib
import socket
import struct
import sys
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_frame(conn):
    hdr = recv_exact(conn, 2)
    if hdr is None:
        return None
    b0, b1 = hdr[0], hdr[1]
    fin = b0 & 0x80
    opcode = b0 & 0x0F
    masked = b1 & 0x80
    length = b1 & 0x7F
    if length == 126:
        length = struct.unpack(">H", recv_exact(conn, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", recv_exact(conn, 8))[0]
    mask = recv_exact(conn, 4) if masked else b"\x00\x00\x00\x00"
    payload = recv_exact(conn, length) if length else b""
    if masked and payload:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return fin, opcode, payload


def make_frame(opcode, payload, fin=True):
    out = bytes([(0x80 if fin else 0) | opcode])
    n = len(payload)
    if n < 126:
        out += bytes([n])
    elif n <= 0xFFFF:
        out += bytes([126]) + struct.pack(">H", n)
    else:
        out += bytes([127]) + struct.pack(">Q", n)
    return out + payload


def handle(conn, addr):
    try:
        # ---- 读握手请求 ----
        req = b""
        while b"\r\n\r\n" not in req:
            chunk = conn.recv(4096)
            if not chunk:
                return
            req += chunk
        text = req.decode("utf-8", "replace")
        key = None
        for line in text.split("\r\n"):
            if line.lower().startswith("sec-websocket-key:"):
                key = line.split(":", 1)[1].strip()
        if key is None:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return

        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        resp = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        )
        conn.sendall(resp.encode())
        print(f"[server] 握手完成 client={addr} accept={accept}", flush=True)

        text_count = 0
        bin_bytes = 0
        while True:
            frame = read_frame(conn)
            if frame is None:
                print("[server] 客户端断开", flush=True)
                break
            fin, opcode, payload = frame

            if opcode == 0x8:  # close
                conn.sendall(make_frame(0x8, payload[:2] if payload else b""))
                print("[server] 收到 close，回复并结束", flush=True)
                break
            if opcode == 0x9:  # ping -> pong
                conn.sendall(make_frame(0xA, payload))
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x1:  # text
                text_count += 1
                if payload == b"__ping__":
                    conn.sendall(make_frame(0x9, b"probe"))
                    continue
                conn.sendall(make_frame(0x1, b"echo:" + payload))
            elif opcode == 0x2:  # binary
                bin_bytes += len(payload)
                conn.sendall(make_frame(0x2, b"B" + struct.pack(">I", len(payload))))

        print(f"[server] 统计: text帧={text_count} 二进制字节={bin_bytes}", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[server] 异常: {exc}", flush=True)
    finally:
        conn.close()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9911
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(4)
    print(f"[server] 监听 ws://127.0.0.1:{port}/", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
