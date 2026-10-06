"""Trạng thái dùng chung của web UI (analyzer, capture, job import, ghi chú, live feed)."""
from __future__ import annotations

import json
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..analyzer import FirstArrival, LatencyAnalyzer
from ..config import Config
from ..live import CaptureError, CaptureSession, available_backends, list_interfaces_detailed
from ..pcap_reader import read_packets
from ..report import table_data

BATCH = 500  # số gói xử lý mỗi lần giữ lock khi import


class AppState:
    def __init__(self, cfg: Config, data_dir: Path):
        self.cfg, self.data_dir = cfg, data_dir
        data_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.tz = timezone(timedelta(hours=cfg.tz_offset_hours))
        self.events: deque = deque(maxlen=300)
        self.cap: CaptureSession | None = None
        self.job = {"running": False, "name": "", "packets": 0, "error": ""}
        self._ifaces: tuple[float, list[dict]] | None = None
        self.notes_path = data_dir / "notes.json"
        try:
            cfg.notes.update(json.loads(self.notes_path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
        self.an = self._new_analyzer()

    # ------------------------------------------------------------ helpers
    def _new_analyzer(self) -> LatencyAnalyzer:
        return LatencyAnalyzer(self.cfg, on_first=self._on_first)

    def _on_first(self, day, fa: FirstArrival) -> None:
        t = datetime.fromtimestamp(fa.ts_ns // 1_000_000_000, self.tz)
        self.events.append({
            "date": day.date, "time": f"{t:%H:%M:%S}.{fa.ts_ns % 1_000_000_000 // 1000:06d}",
            "key": fa.key, "delay_ms": None if fa.delay_ms is None else round(fa.delay_ms, 2),
            "flow": f"{fa.src}:{fa.sport} \u2192 {fa.dst}:{fa.dport}",
        })

    def interfaces(self) -> list[dict]:
        if not self._ifaces or time.monotonic() - self._ifaces[0] > 30:  # scapy liệt kê khá chậm -> cache
            self._ifaces = (time.monotonic(), list_interfaces_detailed())
        return self._ifaces[1]

    # ------------------------------------------------------------ actions
    def reset(self) -> None:
        with self.lock:
            self.an = self._new_analyzer()
            self.events.clear()
            if self.cap and self.cap.running:  # capture đang chạy phải trỏ sang analyzer mới
                self.cap.analyzer = self.an

    def set_note(self, date: str, note: str) -> None:
        with self.lock:
            if note.strip():
                self.cfg.notes[date] = note.strip()[:200]
            else:
                self.cfg.notes.pop(date, None)
            self.notes_path.write_text(json.dumps(self.cfg.notes, ensure_ascii=False, indent=1), encoding="utf-8")

    def import_file(self, path: Path) -> None:
        if self.job["running"]:
            raise CaptureError("Đang import file khác, vui lòng đợi.")

        def run():
            self.job = {"running": True, "name": path.name, "packets": 0, "error": ""}
            try:
                with self.lock:
                    self.an.new_stream()
                batch, n = [], 0
                for p in read_packets(path):
                    batch.append(p)
                    if len(batch) >= BATCH:
                        with self.lock:
                            for q in batch:
                                self.an.feed(q, str(path))
                        n += len(batch)
                        batch.clear()
                        self.job["packets"] = n
                with self.lock:
                    for q in batch:
                        self.an.feed(q, str(path))
                self.job["packets"] = n + len(batch)
            except Exception as e:
                self.job["error"] = f"{type(e).__name__}: {e}"
            finally:
                self.job["running"] = False

        self.job = {"running": True, "name": path.name, "packets": 0, "error": ""}
        threading.Thread(target=run, daemon=True).start()

    def start_capture(self, iface: str, backend: str, bpf: str | None) -> None:
        if self.cap and self.cap.running:
            raise CaptureError("Đang capture.")
        out = self.data_dir / f"capture_{time.strftime('%Y%m%d_%H%M%S')}.pcapng"
        self.cap = CaptureSession(self.an, self.lock, iface, backend, str(out), bpf or None).start()

    def stop_capture(self) -> None:
        if self.cap:
            self.cap.stop()

    # ------------------------------------------------------------ view
    def state(self) -> dict:
        with self.lock:
            data = table_data(self.an.results(), self.cfg)
            events = list(self.events)[-60:][::-1]
        c = self.cap
        data["capture"] = {
            "running": bool(c and c.running), "iface": c.iface if c else "", "backend": c.backend if c else "",
            "frames": c.frames if c else 0, "error": c.error if c else None,
            "file": c.out_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] if c and c.out_path else "",
            "elapsed_s": round((time.time_ns() - c.started_ns) / 1e9) if c and c.running else 0,
        }
        data["interfaces"] = self.interfaces()
        data["backends"] = available_backends()
        data["job"] = dict(self.job)
        data["events"] = events
        data["meta"] = {"mode": self.cfg.latency_mode, "reference": self.cfg.reference_clock,
                        "tz": f"UTC{self.cfg.tz_offset_hours:+g}"}
        return data
