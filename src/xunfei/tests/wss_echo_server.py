#!/usr/bin/env python3
"""
TLS(wss://) WebSocket 回显服务端 —— 验证 xunfei-websocket.cpp 的 wss 路径。

用法:
  python3 wss_echo_server.py [port] [certfile] [keyfile]
默认使用同目录自签证书 cert.pem / key.pem（不存在则用 openssl 现场生成）。

行为与 ws_echo_server.py 一致：text/binary 原样回显，close 后退出。
  - text 回显 "echo:" + payload
  - binary 回显 b'B' + uint32BE(len(payload))
  - 收到 payload == b'__ping__' 时主动发一个 ping 帧
  - 握手完成时打印协商到的 TLS 版本与密码套件（便于确认走的是 TLS 而非明文）
"""
import base64, hashlib, os, socket, ssl, struct, subprocess, sys, threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
HERE = os.path.dirname(os.path.abspath(__file__))


def ensure_cert(cert, key):
    if os.path.exists(cert) and os.path.exists(key):
        return
    subprocess.check_call([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key, "-out", cert, "-days", "365",
        "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ])


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
    opcode, masked, length = b0 & 0x0F, b1 & 0x80, b1 & 0x7F
    if length == 126:
        length = struct.unpack(">H", recv_exact(conn, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", recv_exact(conn, 8))[0]
    mask = recv_exact(conn, 4) if masked else b"\x00\x00\x00\x00"
    payload = recv_exact(conn, length) if length else b""
    if masked and payload:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def make_frame(opcode, payload):
    out = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        out += bytes([n])
    elif n <= 0xFFFF:
        out += bytes([126]) + struct.pack(">H", n)
    else:
        out += bytes([127]) + struct.pack(">Q", n)
    return out + payload


def handle(conn):
    try:
        req = b""
        while b"\r\n\r\n" not in req:
            chunk = conn.recv(4096)
            if not chunk:
                return
            req += chunk
        key = None
        for line in req.decode("utf-8", "replace").split("\r\n"):
            if line.lower().startswith("sec-websocket-key:"):
                key = line.split(":", 1)[1].strip()
        if not key:
            return
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        conn.sendall((
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
        ).encode())
        print(f"[wss] TLS + WS 握手完成 (TLS={conn.version()} cipher={conn.cipher()[0]})",
              flush=True)
        total = 0
        while True:
            frame = read_frame(conn)
            if frame is None:
                break
            opcode, payload = frame
            if opcode == 0x8:
                conn.sendall(make_frame(0x8, b""))
                break
            if opcode == 0x9:
                conn.sendall(make_frame(0xA, payload))
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x1:
                if payload == b"__ping__":
                    conn.sendall(make_frame(0x9, b"probe"))
                    continue
                conn.sendall(make_frame(0x1, b"echo:" + payload))
            elif opcode == 0x2:
                total += len(payload)
                # 与 ws_echo_server.py 保持一致：b'B' + uint32BE(长度)
                conn.sendall(make_frame(0x2, b"B" + struct.pack(">I", len(payload))))
        print(f"[wss] 会话结束，收到二进制音频共 {total} 字节", flush=True)
    finally:
        conn.close()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9912
    cert = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "cert.pem")
    key = sys.argv[3] if len(sys.argv) > 3 else os.path.join(HERE, "key.pem")
    ensure_cert(cert, key)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(4)
    print(f"[wss] 监听 wss://127.0.0.1:{port}/ (cert={cert})", flush=True)
    while True:
        raw, _ = srv.accept()
        try:
            conn = ctx.wrap_socket(raw, server_side=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[wss] TLS 握手失败: {exc}", flush=True)
            raw.close()
            continue
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
