"""HTTP server cục bộ (stdlib) phục vụ web UI + JSON API.

Bảo vệ cơ bản (UI không có đăng nhập, chạy cục bộ):
  - kiểm tra Host (chống DNS rebinding) khi bind loopback;
  - mọi POST phải có header X-PA-Request (trình duyệt không gửi được cross-site mà không preflight);
  - nếu có Origin thì phải cùng host với Host.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..config import Config
from ..live import CaptureError
from ..report import write_csv, write_xlsx
from .state import AppState

STATIC = Path(__file__).parent / "static"
FILES = {"/": ("index.html", "text/html; charset=utf-8"),
         "/static/app.css": ("app.css", "text/css; charset=utf-8"),
         "/static/app.js": ("app.js", "text/javascript; charset=utf-8")}
PCAP_EXT = (".pcap", ".pcapng", ".cap")
MAX_UPLOAD = 4 << 30  # 4 GiB
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def make_handler(st: AppState, bind_host: str):
    check_host = bind_host in LOOPBACK

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        # ---------------------------------------------------------- helpers
        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def _host_ok(self) -> bool:
            host = urlparse("//" + self.headers.get("Host", "")).hostname or ""
            if check_host and host not in LOOPBACK:
                return False
            origin = self.headers.get("Origin")
            return not origin or (urlparse(origin).hostname or "") == host

        def _body_json(self) -> dict:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n) or b"{}") if n else {}

        # ---------------------------------------------------------- GET
        def do_GET(self):
            if not self._host_ok():
                return self._json({"error": "Host không hợp lệ"}, 403)
            u = urlparse(self.path)
            if u.path in FILES:
                name, ctype = FILES[u.path]
                return self._send(200, (STATIC / name).read_bytes(), ctype)
            if u.path == "/api/state":
                return self._json(st.state())
            if u.path in ("/api/export.xlsx", "/api/export.csv"):
                return self._export(u.path.endswith(".xlsx"))
            self._json({"error": "not found"}, 404)

        def _export(self, xlsx: bool):
            suffix = ".xlsx" if xlsx else ".csv"
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                name = tmp.name
            try:
                with st.lock:
                    days = st.an.results()
                    (write_xlsx if xlsx else write_csv)(days, st.cfg, name)
                body = Path(name).read_bytes()
            except SystemExit as e:  # thiếu openpyxl
                return self._json({"error": str(e)}, 501)
            finally:
                os.unlink(name)
            ctype = ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" if xlsx else "text/csv")
            self._send(200, body, ctype, {"Content-Disposition": f'attachment; filename="latency_heatmap{suffix}"'})

        # ---------------------------------------------------------- POST
        def do_POST(self):
            if not self._host_ok():
                return self._json({"error": "Host không hợp lệ"}, 403)
            if self.headers.get("X-PA-Request") != "1":
                return self._json({"error": "Thiếu header X-PA-Request"}, 403)
            u = urlparse(self.path)
            try:
                if u.path == "/api/import":  # body = nội dung file thô
                    return self._upload(u)
                if u.path == "/api/import-path":
                    path = Path(self._body_json().get("path", "")).expanduser()
                    if not path.is_file() or path.suffix.lower() not in PCAP_EXT:
                        return self._json({"error": "File không tồn tại hoặc không phải pcap/pcapng"}, 400)
                    st.import_file(path)
                    return self._json({"ok": True})
                if u.path == "/api/capture/start":
                    b = self._body_json()
                    st.start_capture(b["iface"], b.get("backend", "auto"), b.get("bpf"))
                    return self._json({"ok": True})
                if u.path == "/api/capture/stop":
                    st.stop_capture()
                    return self._json({"ok": True})
                if u.path == "/api/reset":
                    st.reset()
                    return self._json({"ok": True})
                if u.path == "/api/note":
                    b = self._body_json()
                    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(b.get("date", ""))):
                        return self._json({"error": "date không hợp lệ"}, 400)
                    st.set_note(b["date"], str(b.get("note", "")))
                    return self._json({"ok": True})
            except CaptureError as e:
                return self._json({"error": str(e)}, 400)
            except KeyError as e:
                return self._json({"error": f"Thiếu tham số {e}"}, 400)
            except Exception as e:
                return self._json({"error": f"{type(e).__name__}: {e}"}, 500)
            self._json({"error": "not found"}, 404)

        def _upload(self, u):
            name = re.sub(r"[^\w.\-]", "_", parse_qs(u.query).get("name", ["upload.pcapng"])[0])
            if not name.lower().endswith(PCAP_EXT):
                return self._json({"error": "Chỉ nhận .pcap / .pcapng"}, 400)
            size = int(self.headers.get("Content-Length", 0))
            if size > MAX_UPLOAD:
                return self._json({"error": "File quá lớn (tối đa 4 GiB)"}, 413)
            if st.job["running"]:
                return self._json({"error": "Đang import file khác, vui lòng đợi."}, 409)
            dest = st.data_dir / name
            with open(dest, "wb") as f:
                left = size
                while left > 0:
                    chunk = self.rfile.read(min(1 << 20, left))
                    if not chunk:
                        break
                    f.write(chunk)
                    left -= len(chunk)
            st.import_file(dest)
            self._json({"ok": True})

    return H


def serve(cfg: Config, host: str, port: int, data_dir: str) -> None:
    st = AppState(cfg, Path(data_dir))
    srv = ThreadingHTTPServer((host, port), make_handler(st, host))
    warn = "" if host in LOOPBACK else "  [CẢNH BÁO: không loopback, UI không có xác thực]"
    print(f"packet-analytics UI: http://{host}:{port}  (Ctrl+C để dừng; dữ liệu ở {data_dir}){warn}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        st.stop_capture()
