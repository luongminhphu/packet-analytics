"""Tính first-arrival delay theo (ngày, message key)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .config import Config
from .decoder import Decoder
from .pcap_reader import Packet, read_packets

NS = 1_000_000_000


@dataclass
class FirstArrival:
    key: str
    ts_ns: int
    packet_no: int
    src: str
    dst: str
    sport: int
    dport: int
    ref_ns: int | None = None
    delay_ms: float | None = None
    count: int = 1


@dataclass
class DayResult:
    date: str
    first: dict[str, FirstArrival] = field(default_factory=dict)
    packets: int = 0
    matched: int = 0
    files: set[str] = field(default_factory=set)

    def race(self) -> list[tuple[str, float]]:
        """Thứ tự tới nơi: [(key, gap_ms so với message đầu tiên)]."""
        items = sorted(self.first.values(), key=lambda a: a.ts_ns)
        if not items:
            return []
        t0 = items[0].ts_ns
        return [(a.key, (a.ts_ns - t0) / 1e6) for a in items]


def _passes(p: Packet, cfg: Config) -> bool:
    if cfg.protocol != "any" and p.proto != cfg.protocol:
        return False
    return (
        (not cfg.src_ip or p.src in cfg.src_ip)
        and (not cfg.dst_ip or p.dst in cfg.dst_ip)
        and (not cfg.src_port or p.sport in cfg.src_port)
        and (not cfg.dst_port or p.dport in cfg.dst_port)
    )


def _clock_secs(s: str) -> float:
    h, m, rest = (s.split(":") + ["0", "0"])[:3]
    return int(h) * 3600 + int(m) * 60 + float(rest)


def analyze(paths: Iterable[str], cfg: Config) -> list[DayResult]:
    tz = timezone(timedelta(hours=cfg.tz_offset_hours))
    dec = Decoder(cfg.decoder)
    days: dict[str, DayResult] = {}
    ref_clock = _clock_secs(cfg.reference_clock)

    for path in paths:
        for p in read_packets(path):
            dt = datetime.fromtimestamp(p.ts_ns / NS, tz)
            date = dt.strftime("%Y-%m-%d")
            day = days.setdefault(date, DayResult(date))
            day.files.add(str(path))
            day.packets += 1
            if not _passes(p, cfg):
                continue
            msgs = dec.decode(p.payload)
            if not msgs:
                continue
            day.matched += 1
            midnight_ns = int(datetime(dt.year, dt.month, dt.day, tzinfo=tz).timestamp()) * NS
            for m in msgs:
                cur = day.first.get(m.key)
                if cur is not None:
                    if p.ts_ns < cur.ts_ns:  # file nạp không theo thứ tự thời gian
                        cur.ts_ns, cur.packet_no = p.ts_ns, p.no
                        cur.src, cur.dst, cur.sport, cur.dport = p.src, p.dst, p.sport, p.dport
                    cur.count += 1
                    continue
                fa = FirstArrival(m.key, p.ts_ns, p.no, p.src, p.dst, p.sport, p.dport)
                if cfg.latency_mode == "clock":
                    fa.ref_ns = midnight_ns + int(ref_clock * NS)
                elif cfg.latency_mode == "exchange_ts" and m.exchange_ts:
                    try:
                        t = datetime.strptime(m.exchange_ts, cfg.exchange_ts_format)
                        fa.ref_ns = (midnight_ns
                                     + (t.hour * 3600 + t.minute * 60 + t.second) * NS
                                     + t.microsecond * 1000)
                    except ValueError:
                        pass
                day.first[m.key] = fa

    # reference còn lại + delay
    for day in days.values():
        if cfg.latency_mode == "first_packet" and day.first:
            t0 = min(a.ts_ns for a in day.first.values())
            for a in day.first.values():
                a.ref_ns = t0
        for a in day.first.values():
            if a.ref_ns is not None:
                a.delay_ms = (a.ts_ns - a.ref_ns) / 1e6
    return [days[d] for d in sorted(days)]
