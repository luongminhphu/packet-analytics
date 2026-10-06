"""Capture realtime trên cổng mạng.

Backend:
  afpacket : Linux, thuần stdlib, timestamp kernel SO_TIMESTAMPNS (ns), cần root/CAP_NET_RAW.
  scapy    : Linux/Windows (Windows cần Npcap), pip install scapy; hỗ trợ BPF filter.
Mỗi frame được ghi ra pcapng (nếu có out_path) và đưa vào LatencyAnalyzer.
"""
from __future__ import annotations

import os
import queue
import socket
import struct
import threading
import time
from typing import Iterator

from .pcap_reader import decode_frame
from .pcap_writer import PcapngWriter

NS = 1_000_000_000
SO_TIMESTAMPNS = 35


class CaptureError(RuntimeError):
    pass


def available_backends() -> list[str]:
    out = []
    if hasattr(socket, "AF_PACKET"):
        out.append("afpacket")
    try:
        import scapy  # noqa: F401
        out.append("scapy")
    except ImportError:
        pass
    return out


def list_interfaces() -> list[str]:
    try:
        from scapy.all import get_if_list
        return list(get_if_list())
    except Exception:
        pass
    return sorted(os.listdir("/sys/class/net")) if os.path.isdir("/sys/class/net") else []


def _afpacket(iface: str, stop: threading.Event) -> Iterator[tuple[int, bytes]]:
    if not hasattr(socket, "AF_PACKET"):
        raise CaptureError("AF_PACKET chỉ có trên Linux — trên Windows dùng --backend scapy (cần Npcap).")
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 << 20)
        s.bind((iface, 0))
    except PermissionError as e:
        raise CaptureError("Cần quyền root / CAP_NET_RAW để capture.") from e
    except OSError as e:
        raise CaptureError(f"Không mở được interface {iface!r}: {e}") from e
    s.settimeout(0.5)
    try:
        while not stop.is_set():
            try:
                data, anc, _, _ = s.recvmsg(65535, 256)
            except socket.timeout:
                continue
            ts = None
            for lvl, typ, d in anc:
                if lvl == socket.SOL_SOCKET and typ == SO_TIMESTAMPNS and len(d) >= 16:
                    sec, nsec = struct.unpack("qq", d[:16])
                    ts = sec * NS + nsec
            yield (ts if ts is not None else time.time_ns()), data
    finally:
        s.close()


def _scapy(iface: str, stop: threading.Event, bpf: str | None) -> Iterator[tuple[int, bytes]]:
    try:
        from scapy.all import AsyncSniffer
    except ImportError as e:
        raise CaptureError("Backend scapy cần: pip install scapy (Windows: cài thêm Npcap).") from e
    q: queue.Queue = queue.Queue(maxsize=1_000_000)
    sn = AsyncSniffer(iface=iface, filter=bpf, store=False,
                      prn=lambda p: q.put((int(float(p.time) * 1e9), bytes(p))))
    sn.start()
    try:
        while not stop.is_set() or not q.empty():
            try:
                yield q.get(timeout=0.5)
            except queue.Empty:
                continue
    finally:
        try:
            sn.stop()
        except Exception:
            pass


class CaptureSession:
    def __init__(self, analyzer, lock, iface: str, backend: str = "auto",
                 out_path: str | None = None, bpf: str | None = None, on_error=None):
        if backend == "auto":
            av = available_backends()
            if not av:
                raise CaptureError("Không có backend capture (Linux: AF_PACKET; Windows: pip install scapy + Npcap).")
            backend = av[0]
        self.analyzer, self.lock, self.iface, self.backend = analyzer, lock, iface, backend
        self.out_path, self.bpf, self.on_error = out_path, bpf, on_error
        self.stop_evt = threading.Event()
        self.frames = 0
        self.error: str | None = None
        self.started_ns = 0
        self.thread = threading.Thread(target=self._run, daemon=True)

    @property
    def running(self) -> bool:
        return self.thread.is_alive()

    def start(self) -> "CaptureSession":
        self.started_ns = time.time_ns()
        self.thread.start()
        return self

    def stop(self, wait: float = 5.0) -> None:
        self.stop_evt.set()
        self.thread.join(wait)

    def _run(self) -> None:
        writer = PcapngWriter(self.out_path) if self.out_path else None
        last_flush = time.monotonic()
        try:
            src = (_afpacket(self.iface, self.stop_evt) if self.backend == "afpacket"
                   else _scapy(self.iface, self.stop_evt, self.bpf))
            with self.lock:
                self.analyzer.new_stream()
            for ts, data in src:
                self.frames += 1
                if writer:
                    writer.write(ts, data)
                    if time.monotonic() - last_flush > 2:
                        writer.flush()
                        last_flush = time.monotonic()
                pkt = decode_frame(self.frames, ts, data, 1, len(data))
                if pkt:
                    with self.lock:
                        self.analyzer.feed(pkt, f"live:{self.iface}")
        except Exception as e:  # CaptureError hoặc lỗi khác
            self.error = str(e)
            if self.on_error:
                self.on_error(e)
        finally:
            if writer:
                writer.close()
