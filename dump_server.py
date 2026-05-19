#!/usr/bin/env python3
import threading
import socket
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

DATA_PORT = 9999
LOG_PORT  = 8080

class LogHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        length = int(self.headers['Content-Length'])
        log_msg = self.rfile.read(length).decode('utf-8')
        print(log_msg, flush=True)
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

def handle_data_client(conn, addr):
    print(f"[data] Connected from {addr[0]}:{addr[1]}", flush=True)
    SEP_MAGIC = b'\xBE\xBA\xFE\xCA\xDE\xC0\xAD\xDE'
    buf = b""
    current_name = "unknown"
    current_file = None

    try:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk

            os.makedirs("dumps", exist_ok=True)

            while True:
                idx = buf.find(SEP_MAGIC)
                if idx == -1:
                    break
                if current_file:
                    current_file.write(buf[:idx])
                    current_file.close()
                name_bytes = buf[idx+8:idx+24].rstrip(b'\x00')
                current_name = name_bytes.decode('utf-8', errors='replace')
                safe_name = "".join(c if c.isalnum() or c in '._-' else '_' for c in current_name)
                fname = os.path.join("dumps", f"module_{safe_name}.bin")
                current_file = open(fname, "ab")
                print(f"[data] New module: {current_name} -> {fname}", flush=True)
                buf = buf[idx+24:]

        if current_file:
            current_file.write(buf)
            current_file.close()

    except Exception as e:
        print(f"[data] Error: {e}", flush=True)
        if current_file:
            current_file.close()
    finally:
        conn.close()
        print(f"[data] Connection closed", flush=True)

def data_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', DATA_PORT))
    srv.listen(5)
    print(f"[data] Listening on port {DATA_PORT}...", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_data_client, args=(conn, addr), daemon=True).start()

threading.Thread(target=data_server, daemon=True).start()
print(f"[log] Listening on port {LOG_PORT}...", flush=True)
HTTPServer(('0.0.0.0', LOG_PORT), LogHandler).serve_forever()
