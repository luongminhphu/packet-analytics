"""Tách message FIX từ payload UDP / luồng TCP.

FIX message: bắt đầu bằng '8=FIX', kết thúc bằng '10=xxx<SOH>'.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SOH = b"\x01"
_END = re.compile(rb"\x0110=\d{3}\x01")


def parse_tags(raw: bytes) -> dict[str, str]:
    """Trả về dict tag -> value (giá trị xuất hiện đầu tiên của mỗi tag)."""
    tags: dict[str, str] = {}
    for part in raw.split(SOH):
        k, eq, v = part.partition(b"=")
        if eq and k:
            tags.setdefault(k.decode("ascii", "replace"), v.decode("ascii", "replace"))
    return tags


def split_messages(buf: bytes) -> tuple[list[bytes], bytes]:
    """Cắt buffer thành các message hoàn chỉnh. Trả về (messages, phần dư chưa đủ message).

    Phần đầu buffer trước '8=FIX' (đuôi message dở do bắt giữa chừng) bị bỏ.
    """
    out: list[bytes] = []
    pos = 0
    while True:
        start = buf.find(b"8=FIX", pos)
        if start < 0:
            return out, b""
        m = _END.search(buf, start)
        if not m:
            return out, buf[start:]
        out.append(buf[start:m.end()])
        pos = m.end()


@dataclass
class _Flow:
    next_seq: int | None = None
    buf: bytes = b""


class TcpReassembler:
    """Ghép luồng TCP theo từng chiều (src,dst,sport,dport) -> list message FIX.

    Giả định gói tới đúng thứ tự (đúng với capture tại 1 điểm); retransmit được cắt bỏ,
    mất gói thì resync ở message kế tiếp.
    """

    def __init__(self) -> None:
        self.flows: dict[tuple, _Flow] = {}
        self.gaps = 0

    def feed(self, p) -> list[bytes]:
        if not p.payload:
            return []
        M, HALF = 0xFFFFFFFF, 0x80000000
        fl = self.flows.setdefault((p.src, p.dst, p.sport, p.dport), _Flow())
        data = p.payload
        end = (p.seq + len(p.payload)) & M
        if fl.next_seq is None:
            fl.next_seq = end
        else:
            diff = (p.seq - fl.next_seq) & M
            if diff >= HALF:            # seq cũ -> retransmit, cắt phần đã nhận
                skip = (fl.next_seq - p.seq) & M
                if skip >= len(data):
                    return []
                data = data[skip:]
            elif diff > 0:              # mất gói -> bỏ buffer dở, resync
                self.gaps += 1
                fl.buf = b""
            if ((end - fl.next_seq) & M) < HALF:
                fl.next_seq = end
        msgs, fl.buf = split_messages(fl.buf + data)
        if len(fl.buf) > 1 << 20:
            fl.buf = b""
        return msgs
