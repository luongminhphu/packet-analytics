from __future__ import annotations

import argparse
import threading
import time
from datetime import datetime, timedelta, timezone

from .analyzer import LatencyAnalyzer, analyze
from .live import CaptureError, CaptureSession, available_backends, list_interfaces
from .config import load_config
from .decoder import Decoder
from .pcap_reader import read_packets
from .report import render_race, render_table, write_csv, write_xlsx


def cmd_inspect(a) -> int:
    cfg = load_config(a.config)
    dec = Decoder(cfg.decoder)
    tz = timezone(timedelta(hours=cfg.tz_offset_hours))
    shown = 0
    for p in read_packets(a.file):
        msgs = dec.decode(p)
        if a.only_decoded and not msgs:
            continue
        t = datetime.fromtimestamp(p.ts_ns // 1000 / 1e6, tz)
        frac = p.ts_ns % 1_000_000_000
        ts = f"{t:%Y-%m-%d %H:%M:%S}.{frac:09d}"
        keys = ",".join(m.key for m in msgs) or "-"
        print(f"#{p.no:<7} {ts}  {p.proto} {p.src}:{p.sport} -> {p.dst}:{p.dport}  "
              f"len={len(p.payload):<5} types={keys}")
        if a.hex:
            print("         ", p.payload[:a.hex].hex(" "))
        shown += 1
        if a.limit and shown >= a.limit:
            break
    return 0


def cmd_analyze(a) -> int:
    cfg = load_config(a.config)
    days = analyze(a.files, cfg)
    if not days:
        print("Không có gói tin nào.")
        return 1
    print(render_table(days, cfg))
    if a.race:
        print("\nThứ tự tới nơi:\n" + render_race(days))
    if a.csv:
        write_csv(days, cfg, a.csv)
        print(f"Đã ghi {a.csv}")
    if a.xlsx:
        write_xlsx(days, cfg, a.xlsx)
        print(f"Đã ghi {a.xlsx}")
    return 0


def _wait_until(clock: str, tz) -> None:
    h, m, sec = (clock.split(":") + ["0", "0"])[:3]
    now = datetime.now(tz)
    target = now.replace(hour=int(h), minute=int(m), second=int(float(sec)), microsecond=0)
    while (left := (target - datetime.now(tz)).total_seconds()) > 0:
        time.sleep(min(left, 1))


def cmd_capture(a) -> int:
    cfg = load_config(a.config)
    tz = timezone(timedelta(hours=cfg.tz_offset_hours))

    def on_first(day, fa):
        d = f"{fa.delay_ms:+.2f} ms" if fa.delay_ms is not None else "n/a"
        t = datetime.fromtimestamp(fa.ts_ns // 1000 / 1e6, tz)
        print(f"[{t:%H:%M:%S}.{fa.ts_ns % 10**9:09d}] first {fa.key:<10} {d:>12}  {fa.src}:{fa.sport} -> {fa.dst}:{fa.dport}")

    an = LatencyAnalyzer(cfg, on_first=on_first)
    out = a.out or f"capture_{datetime.now(tz):%Y%m%d_%H%M}.pcapng"
    if a.start_at:
        print(f"Chờ đến {a.start_at} ...")
        _wait_until(a.start_at, tz)
    try:
        sess = CaptureSession(an, threading.RLock(), a.iface, a.backend, out, a.bpf).start()
    except CaptureError as e:
        print(f"Lỗi: {e}")
        return 2
    print(f"Đang capture {a.iface} ({sess.backend}) -> {out}. Ctrl+C để dừng.")
    deadline = time.time() + a.duration if a.duration else None
    try:
        while sess.running:
            time.sleep(0.5)
            if deadline and time.time() >= deadline:
                break
            if a.stop_at and datetime.now(tz).strftime("%H:%M:%S") >= (a.stop_at + ":00")[:8]:
                break
    except KeyboardInterrupt:
        pass
    sess.stop()
    if sess.error:
        print(f"Lỗi capture: {sess.error}")
        return 2
    days = an.results()
    print(f"\n{sess.frames} frame đã ghi vào {out}\n")
    if days:
        print(render_table(days, cfg))
        if a.xlsx:
            write_xlsx(days, cfg, a.xlsx)
    return 0


def cmd_interfaces(a) -> int:
    print("Backend khả dụng:", ", ".join(available_backends()) or "(không có)")
    for i in list_interfaces():
        print(" ", i)
    return 0


def cmd_serve(a) -> int:
    from .web.server import serve
    serve(load_config(a.config), a.host, a.port, a.data_dir)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="packet-analytics",
                                 description="Phân tích gói tin đầu ngày & first-arrival latency")
    sub = ap.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("inspect", help="liệt kê gói tin + message type (giống Wireshark list)")
    i.add_argument("file")
    i.add_argument("-c", "--config")
    i.add_argument("-n", "--limit", type=int, default=50, help="0 = không giới hạn")
    i.add_argument("--hex", type=int, nargs="?", const=48, default=0, metavar="N",
                   help="in N byte payload đầu (mặc định 48)")
    i.add_argument("--only-decoded", action="store_true")
    i.set_defaults(fn=cmd_inspect)

    z = sub.add_parser("analyze", help="tính first-arrival delay theo ngày × message type")
    z.add_argument("files", nargs="+")
    z.add_argument("-c", "--config", required=True)
    z.add_argument("--race", action="store_true", help="in thứ tự tới nơi + gap")
    z.add_argument("--csv")
    z.add_argument("--xlsx")
    z.set_defaults(fn=cmd_analyze)

    c = sub.add_parser("capture", help="capture realtime trên cổng mạng, đo first-arrival, lưu pcapng")
    c.add_argument("-i", "--iface", required=True)
    c.add_argument("-c", "--config", required=True)
    c.add_argument("--backend", default="auto", choices=["auto", "afpacket", "scapy"])
    c.add_argument("--bpf", help="BPF filter (chỉ backend scapy)")
    c.add_argument("-o", "--out", help="file pcapng đầu ra")
    c.add_argument("--start-at", metavar="HH:MM[:SS]", help="chờ đến giờ này (giờ VN trong config)")
    c.add_argument("--stop-at", metavar="HH:MM", help="dừng lúc này")
    c.add_argument("--duration", type=float, help="dừng sau N giây")
    c.add_argument("--xlsx")
    c.set_defaults(fn=cmd_capture)

    sub.add_parser("interfaces", help="liệt kê interface/backend").set_defaults(fn=cmd_interfaces)

    w = sub.add_parser("serve", help="web UI: import pcap / capture realtime / heatmap / export Excel")
    w.add_argument("-c", "--config", required=True)
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8080)
    w.add_argument("--data-dir", default="data")
    w.set_defaults(fn=cmd_serve)

    a = ap.parse_args(argv)
    return a.fn(a)
