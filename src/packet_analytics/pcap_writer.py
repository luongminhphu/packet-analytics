"""Ghi pcapng (timestamp độ phân giải ns) — dùng để lưu lại capture realtime."""
from __future__ import annotations

import struct
from pathlib import Path


def _blk(btype: int, body: bytes) -> bytes:
    body += b"\x00" * (-len(body) % 4)
    n = len(body) + 12
    return struct.pack("<II", btype, n) + body + struct.pack("<I", n)


class PcapngWriter:
    def __init__(self, path: str | Path, linktype: int = 1, snaplen: int = 65535):
        self.f = open(path, "wb")
        self.f.write(_blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        opts = struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0)  # if_tsresol = 10^-9
        self.f.write(_blk(1, struct.pack("<HHI", linktype, 0, snaplen) + opts))

    def write(self, ts_ns: int, data: bytes) -> None:
        body = struct.pack("<IIIII", 0, ts_ns >> 32, ts_ns & 0xFFFFFFFF, len(data), len(data)) + data
        self.f.write(_blk(6, body))

    def flush(self) -> None:
        self.f.flush()

    def close(self) -> None:
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
