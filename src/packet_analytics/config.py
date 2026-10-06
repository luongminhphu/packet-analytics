"""Nạp cấu hình TOML."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    # capture / filter
    tz_offset_hours: float = 7.0
    protocol: str = "any"                 # udp | tcp | any
    src_ip: list[str] = field(default_factory=list)
    dst_ip: list[str] = field(default_factory=list)
    src_port: list[int] = field(default_factory=list)
    dst_port: list[int] = field(default_factory=list)
    # decoder
    decoder: dict = field(default_factory=dict)
    # latency
    latency_mode: str = "clock"           # clock | exchange_ts | first_packet
    reference_clock: str = "09:00:00"
    exchange_ts_format: str = "%H%M%S%f"
    after_reference_only: bool = True     # clock mode: bỏ message tới trước reference_clock
    # report
    columns: list[str] = field(default_factory=list)
    highlight: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    notes: dict[str, str] = field(default_factory=dict)   # ngày -> ghi chú (cột Noted)


def load_config(path: str | Path | None) -> Config:
    if not path:
        return Config()
    raw = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    cap, lat, rep = raw.get("capture", {}), raw.get("latency", {}), raw.get("report", {})
    return Config(
        tz_offset_hours=cap.get("timezone_offset_hours", 7.0),
        protocol=cap.get("protocol", "any"),
        src_ip=cap.get("src_ip", []),
        dst_ip=cap.get("dst_ip", []),
        src_port=cap.get("src_port", []),
        dst_port=cap.get("dst_port", []),
        decoder=raw.get("decoder", {}),
        latency_mode=lat.get("mode", "clock"),
        reference_clock=lat.get("reference_clock", "09:00:00"),
        exchange_ts_format=lat.get("exchange_ts_format", "%H%M%S%f"),
        after_reference_only=lat.get("after_reference_only", True),
        columns=rep.get("columns", []),
        highlight=rep.get("highlight", []),
        labels=rep.get("labels", {}),
        notes=rep.get("notes", {}),
    )
