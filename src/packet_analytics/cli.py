from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone

from .analyzer import analyze
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
        msgs = dec.decode(p.payload)
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

    a = ap.parse_args(argv)
    return a.fn(a)
