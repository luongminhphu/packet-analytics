"""Web UI cục bộ (stdlib): import pcap, capture realtime, Latency Heatmap, Export Excel/CSV."""
from __future__ import annotations

import io
import json
import os
import re
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .analyzer import LatencyAnalyzer
from .config import Config
from .live import CaptureError, CaptureSession, available_backends, list_interfaces
from .pcap_reader import read_packets
from .report import table_data, write_csv, write_xlsx


class AppState:
    def __init__(self, cfg: Config, data_dir: Path):
        self.cfg, self.data_dir = cfg, data_dir
        data_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.an = LatencyAnalyzer(cfg)
        self.cap: CaptureSession | None = None
        self.job = {"running": False, "name": "", "packets": 0, "error": ""}

    def reset(self) -> None:
        with self.lock:
            self.an = LatencyAnalyzer(self.cfg)

    def import_file(self, path: Path) -> None:
        def run():
            self.job = {"running": True, "name": path.name, "packets": 0, "error": ""}
            try:
                with self.lock:
                    self.an.new_stream()
                n = 0
                for p in read_packets(path):
                    with self.lock:
                        self.an.feed(p, str(path))
                    n += 1
                    if n % 2000 == 0:
                        self.job["packets"] = n
                self.job["packets"] = n
            except Exception as e:
                self.job["error"] = str(e)
            finally:
                self.job["running"] = False
        threading.Thread(target=run, daemon=True).start()

    def start_capture(self, iface: str, backend: str, bpf: str | None) -> None:
        if self.cap and self.cap.running:
            raise CaptureError("Đang capture.")
        out = self.data_dir / f"capture_{time.strftime('%Y%m%d_%H%M%S')}.pcapng"
        self.cap = CaptureSession(self.an, self.lock, iface, backend, str(out), bpf or None).start()

    def state(self) -> dict:
        with self.lock:
            days = self.an.results()
            data = table_data(days, self.cfg)
        c = self.cap
        data["capture"] = {
            "running": bool(c and c.running), "iface": c.iface if c else "", "backend": c.backend if c else "",
            "frames": c.frames if c else 0, "error": c.error if c else None,
            "file": os.path.basename(c.out_path) if c and c.out_path else "",
        }
        data["interfaces"] = list_interfaces()
        data["backends"] = available_backends()
        data["job"] = self.job
        return data


def make_handler(st: AppState):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # im lặng
            pass

        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj).encode(), "application/json")

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/":
                return self._send(200, INDEX_HTML.encode(), "text/html; charset=utf-8")
            if u.path == "/api/state":
                return self._json(st.state())
            if u.path in ("/api/export.xlsx", "/api/export.csv"):
                with st.lock:
                    days = st.an.results()
                    suffix = u.path[-5:] if u.path.endswith("xlsx") else ".csv"
                    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                        name = tmp.name
                    try:
                        (write_xlsx if suffix == ".xlsx" else write_csv)(days, st.cfg, name)
                        body = Path(name).read_bytes()
                    except SystemExit as e:
                        return self._json({"error": str(e)}, 501)
                    finally:
                        os.unlink(name)
                ctype = ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                         if suffix == ".xlsx" else "text/csv")
                return self._send(200, body, ctype,
                                  {"Content-Disposition": f'attachment; filename="latency_heatmap{suffix}"'})
            self._json({"error": "not found"}, 404)

        def _body(self) -> bytes:
            return self.rfile.read(int(self.headers.get("Content-Length", 0)))

        def do_POST(self):
            u = urlparse(self.path)
            try:
                if u.path == "/api/import":  # body = nội dung file thô
                    name = re.sub(r"[^\w.\-]", "_", parse_qs(u.query).get("name", ["upload.pcapng"])[0])
                    if not name.lower().endswith((".pcap", ".pcapng", ".cap")):
                        return self._json({"error": "Chỉ nhận .pcap/.pcapng"}, 400)
                    dest = st.data_dir / name
                    with open(dest, "wb") as f:
                        remaining = int(self.headers.get("Content-Length", 0))
                        while remaining > 0:
                            chunk = self.rfile.read(min(1 << 20, remaining))
                            if not chunk:
                                break
                            f.write(chunk)
                            remaining -= len(chunk)
                    st.import_file(dest)
                    return self._json({"ok": True})
                if u.path == "/api/import-path":
                    path = Path(json.loads(self._body())["path"]).expanduser()
                    if not path.is_file() or path.suffix.lower() not in (".pcap", ".pcapng", ".cap"):
                        return self._json({"error": "File không tồn tại hoặc không phải pcap/pcapng"}, 400)
                    st.import_file(path)
                    return self._json({"ok": True})
                if u.path == "/api/capture/start":
                    b = json.loads(self._body())
                    st.start_capture(b["iface"], b.get("backend", "auto"), b.get("bpf"))
                    return self._json({"ok": True})
                if u.path == "/api/capture/stop":
                    if st.cap:
                        st.cap.stop()
                    return self._json({"ok": True})
                if u.path == "/api/reset":
                    st.reset()
                    return self._json({"ok": True})
            except CaptureError as e:
                return self._json({"error": str(e)}, 400)
            except Exception as e:
                return self._json({"error": f"{type(e).__name__}: {e}"}, 500)
            self._json({"error": "not found"}, 404)

    return H


def serve(cfg: Config, host: str, port: int, data_dir: str) -> None:
    st = AppState(cfg, Path(data_dir))
    srv = ThreadingHTTPServer((host, port), make_handler(st))
    print(f"packet-analytics UI: http://{host}:{port}  (Ctrl+C để dừng; dữ liệu lưu ở {data_dir})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if st.cap:
            st.cap.stop()


INDEX_HTML = r"""<!doctype html><html lang="vi"><head><meta charset="utf-8">
<title>Packet Analytics — Latency Heatmap</title>
<style>
body{font:14px "Segoe UI",system-ui,sans-serif;background:#f4f2ee;margin:0;padding:18px;color:#222}
.card{background:#fff;border:1px solid #ddd;border-radius:14px;padding:16px 20px;margin-bottom:16px}
h2{margin:0 0 2px;font-size:18px}.sub{color:#666;font-size:12px;margin-bottom:10px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
button,select,input[type=text]{font:inherit;padding:6px 12px;border:1px solid #bbb;border-radius:8px;background:#fff}
button{cursor:pointer}button.pri{background:#2d6a4f;color:#fff;border-color:#2d6a4f}button.dng{background:#b23a3a;color:#fff;border-color:#b23a3a}
button:disabled{opacity:.5;cursor:default}
table{border-collapse:collapse;width:100%}th{background:#eeebe4;padding:8px;text-align:center;font-weight:600;font-size:13px}
td{padding:8px;text-align:right;border-bottom:1px solid #eee;font-variant-numeric:tabular-nums}
td:first-child,th:first-child{text-align:left}td.note{text-align:left;color:#666;font-size:12px}
td.best{background:#e6f0da;color:#c00000;font-weight:700}
.st{font-size:12px;color:#555}.err{color:#b23a3a}.ok{color:#2d6a4f}
</style></head><body>
<div class="card"><h2>Nguồn dữ liệu</h2><div class="sub">Import file pcap/pcapng hoặc capture realtime trên cổng mạng</div>
<div class="row" style="margin-bottom:10px">
 <input type="file" id="f" accept=".pcap,.pcapng,.cap"><button class="pri" onclick="upload()">Import</button>
 <input type="text" id="p" size="38" placeholder="hoặc đường dẫn file trên máy chạy app"><button onclick="imp()">Đọc đường dẫn</button>
</div>
<div class="row">
 <select id="if"></select><select id="be"></select><input type="text" id="bpf" size="26" placeholder="BPF filter (scapy)">
 <button class="pri" id="go" onclick="cap(1)">Bắt đầu capture</button><button class="dng" id="no" onclick="cap(0)">Dừng</button>
 <button onclick="post('/api/reset').then(poll)">Xoá kết quả</button>
</div><div class="st" id="s" style="margin-top:8px"></div></div>
<div class="card"><div class="row" style="justify-content:space-between"><div><h2>Latency Heatmap</h2>
<div class="sub">First-arrival delay (ms)</div></div>
<div class="row"><button onclick="location='/api/export.csv'">Export CSV</button><button onclick="location='/api/export.xlsx'">Export Excel</button></div></div>
<table id="t"></table></div>
<script>
const $=id=>document.getElementById(id);
async function post(u,b){const r=await fetch(u,{method:'POST',body:b===undefined?null:JSON.stringify(b)});const j=await r.json();if(j.error)alert(j.error);return j}
async function upload(){const f=$('f').files[0];if(!f)return;const r=await fetch('/api/import?name='+encodeURIComponent(f.name),{method:'POST',body:f});const j=await r.json();if(j.error)alert(j.error)}
function imp(){const v=$('p').value.trim();if(v)post('/api/import-path',{path:v})}
function cap(on){on?post('/api/capture/start',{iface:$('if').value,backend:$('be').value,bpf:$('bpf').value}):post('/api/capture/stop')}
let filled=false;
async function poll(){const d=await (await fetch('/api/state')).json();
 if(!filled||$('if').options.length!=d.interfaces.length){$('if').innerHTML=d.interfaces.map(i=>`<option>${i}</option>`).join('');
  $('be').innerHTML='<option value="auto">backend: auto</option>'+d.backends.map(i=>`<option>${i}</option>`).join('');filled=true}
 const c=d.capture,j=d.job;$('go').disabled=c.running;$('no').disabled=!c.running;
 let s='';if(c.running)s+=`<span class="ok">● Đang capture ${c.iface} (${c.backend}) — ${c.frames.toLocaleString()} frame → ${c.file}</span> `;
 else if(c.frames)s+=`Đã dừng capture (${c.frames.toLocaleString()} frame, ${c.file}) `;
 if(c.error)s+=`<span class="err">Lỗi capture: ${c.error}</span> `;
 if(j.name)s+=j.running?`Đang đọc ${j.name}: ${j.packets.toLocaleString()} gói…`:(j.error?`<span class="err">${j.error}</span>`:`Đã import ${j.name} (${j.packets.toLocaleString()} gói)`);
 $('s').innerHTML=s;
 let h='<tr><th>Date</th>'+d.columns.map(k=>`<th>${d.labels[k].replace(/^(First) /,'$1<br>')}</th>`).join('')+'<th>Noted</th></tr>';
 for(const r of d.rows){h+=`<tr><td>${r.date}</td>`+d.columns.map(k=>{const v=r.cells[k];return `<td class="${k===r.best?'best':''}">${v==null?'-':v.toFixed(2)}</td>`}).join('')+`<td class="note">${r.note||''}</td></tr>`}
 $('t').innerHTML=h}
poll();setInterval(poll,1000);
</script></body></html>"""
