"""Tính first-arrival delay theo (ngày, message key) — dạng streaming (dùng cho file lẫn live)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable

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


def _clock_secs(s: str) -> float:
    h, m, rest = (s.split(":") + ["0", "0"])[:3]
    return int(h) * 3600 + int(m) * 60 + float(rest)


class LatencyAnalyzer:
    def __init__(self, cfg: Config, on_first: Callable[[DayResult, FirstArrival], None] | None = None):
        self.cfg = cfg
        self.tz = timezone(timedelta(hours=cfg.tz_offset_hours))
        self.dec = Decoder(cfg.decoder)
        self.days: dict[str, DayResult] = {}
        self.on_first = on_first
        self._ref_clock = _clock_secs(cfg.reference_clock)
        self.total = 0

    def new_stream(self) -> None:
        """Bắt đầu nguồn mới (file/phiên capture khác): reset trạng thái ghép TCP."""
        self.dec = Decoder(self.cfg.decoder)

    def _passes(self, p: Packet) -> bool:
        c = self.cfg
        if c.protocol != "any" and p.proto != c.protocol:
            return False
        return ((not c.src_ip or p.src in c.src_ip) and (not c.dst_ip or p.dst in c.dst_ip)
                and (not c.src_port or p.sport in c.src_port) and (not c.dst_port or p.dport in c.dst_port))

    def feed(self, p: Packet, source: str = "") -> None:
        cfg = self.cfg
        self.total += 1
        dt = datetime.fromtimestamp(p.ts_ns // 1000 / 1e6, self.tz)
        date = dt.strftime("%Y-%m-%d")
        day = self.days.setdefault(date, DayResult(date))
        if source:
            day.files.add(source)
        day.packets += 1
        if not p.payload or not self._passes(p):
            return
        msgs = self.dec.decode(p)
        if not msgs:
            return
        day.matched += 1
        midnight_ns = int(datetime(dt.year, dt.month, dt.day, tzinfo=self.tz).timestamp()) * NS
        for m in msgs:
            ref = None
            if cfg.latency_mode == "clock":
                ref = midnight_ns + int(self._ref_clock * NS)
                if cfg.after_reference_only and p.ts_ns < ref:
                    continue  # message tới trước giờ mở cửa -> không tính
            elif cfg.latency_mode == "exchange_ts" and m.exchange_ts:
                ref = _parse_exchange_ts(m.exchange_ts, cfg.exchange_ts_format, midnight_ns)
            cur = day.first.get(m.key)
            if cur is not None:
                cur.count += 1
                if p.ts_ns < cur.ts_ns:
                    cur.ts_ns, cur.packet_no = p.ts_ns, p.no
                    cur.src, cur.dst, cur.sport, cur.dport = p.src, p.dst, p.sport, p.dport
                    cur.ref_ns = ref if ref is not None else cur.ref_ns
                    if cur.ref_ns is not None:
                        cur.delay_ms = (cur.ts_ns - cur.ref_ns) / 1e6
                continue
            fa = FirstArrival(m.key, p.ts_ns, p.no, p.src, p.dst, p.sport, p.dport, ref)
            if ref is not None:
                fa.delay_ms = (p.ts_ns - ref) / 1e6
            day.first[m.key] = fa
            if self.on_first:
                self.on_first(day, fa)

    def results(self) -> list[DayResult]:
        if self.cfg.latency_mode == "first_packet":
            for day in self.days.values():
                if day.first:
                    t0 = min(a.ts_ns for a in day.first.values())
                    for a in day.first.values():
                        a.ref_ns, a.delay_ms = t0, (a.ts_ns - t0) / 1e6
        # bỏ ngày không có message nào được giải mã
        return [self.days[d] for d in sorted(self.days) if self.days[d].first or self.days[d].matched]


def _parse_exchange_ts(s: str, fmt: str, midnight_ns: int) -> int | None:
    try:
        t = datetime.strptime(s, fmt)
    except ValueError:
        return None
    return midnight_ns + (t.hour * 3600 + t.minute * 60 + t.second) * NS + t.microsecond * 1000


def analyze(paths: Iterable[str], cfg: Config) -> list[DayResult]:
    an = LatencyAnalyzer(cfg)
    for path in paths:
        an.new_stream()
        for p in read_packets(path):
            an.feed(p, str(path))
    return an.results()
