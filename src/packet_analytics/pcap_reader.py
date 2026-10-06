"""Đọc pcap / pcapng thuần Python (stdlib), giải mã Ethernet/VLAN -> IPv4 -> UDP/TCP.

Chỉ đọc file, không can thiệp hệ thống. Timestamp trả về dạng int nanosecond (epoch).
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator


@dataclass(slots=True)
class Packet:
    no: int          # số thứ tự frame trong file (như Wireshark)
    ts_ns: int       # thời điểm capture, epoch ns
    proto: str       # "udp" | "tcp"
    src: str
    dst: str
    sport: int
    dport: int
    payload: bytes   # payload tầng ứng dụng
    frame_len: int


# ---------------------------------------------------------------- L2/L3/L4
def _ip_from_frame(data: bytes, linktype: int) -> bytes | None:
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None
        et = struct.unpack("!H", data[12:14])[0]
        off = 14
        while et in (0x8100, 0x88A8, 0x9100):  # VLAN tag(s)
            if len(data) < off + 4:
                return None
            et = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        return data[off:] if et == 0x0800 else None
    if linktype == 113:  # Linux cooked
        if len(data) < 16:
            return None
        return data[16:] if struct.unpack("!H", data[14:16])[0] == 0x0800 else None
    if linktype in (101, 12, 14):  # raw IP
        return data
    if linktype == 0:  # BSD loopback
        return data[4:]
    return None


def _decode_frame(no: int, ts_ns: int, data: bytes, linktype: int, orig_len: int) -> Packet | None:
    ip = _ip_from_frame(data, linktype)
    if not ip or len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    if struct.unpack("!H", ip[6:8])[0] & 0x1FFF:  # fragment không phải đầu
        return None
    proto = ip[9]
    src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    l4 = ip[ihl:total] if ihl <= total <= len(ip) else ip[ihl:]
    if proto == 17 and len(l4) >= 8:
        sport, dport, ulen = struct.unpack("!HHH", l4[:6])
        payload = l4[8:ulen] if 8 <= ulen <= len(l4) else l4[8:]
        return Packet(no, ts_ns, "udp", src, dst, sport, dport, payload, orig_len)
    if proto == 6 and len(l4) >= 20:
        sport, dport = struct.unpack("!HH", l4[:4])
        off = (l4[12] >> 4) * 4
        return Packet(no, ts_ns, "tcp", src, dst, sport, dport, l4[off:], orig_len)
    return None


# ---------------------------------------------------------------- pcap cổ điển
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000),
    b"\x4d\x3c\xb2\xa1": ("<", 1),
    b"\xa1\xb2\xc3\xd4": (">", 1000),
    b"\xa1\xb2\x3c\x4d": (">", 1),
}


def _read_pcap(f: BinaryIO, magic: bytes) -> Iterator[Packet]:
    endian, mult = _PCAP_MAGICS[magic]
    hdr = f.read(20)
    if len(hdr) < 20:
        return
    linktype = struct.unpack(endian + "HHiIII", hdr)[5]
    no = 0
    while True:
        rh = f.read(16)
        if len(rh) < 16:
            return
        sec, frac, incl, orig = struct.unpack(endian + "IIII", rh)
        data = f.read(incl)
        if len(data) < incl:
            return
        no += 1
        pkt = _decode_frame(no, sec * 1_000_000_000 + frac * mult, data, linktype, orig)
        if pkt:
            yield pkt


# ---------------------------------------------------------------- pcapng
def _read_pcapng(f: BinaryIO, first4: bytes) -> Iterator[Packet]:
    endian = "<"
    ifaces: list[tuple[int, int]] = []  # (linktype, ticks_per_second)
    no = 0
    pending = first4
    while True:
        head = pending + f.read(8 - len(pending))
        pending = b""
        if len(head) < 8:
            return
        if head[:4] == b"\x0a\x0d\x0d\x0a":  # Section Header Block
            bom = f.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", head[4:8])[0]
            f.read(blen - 12)
            ifaces = []
            continue
        btype, blen = struct.unpack(endian + "II", head)
        data = f.read(blen - 8)
        if len(data) < blen - 8:
            return
        body = data[:-4]
        if btype == 1:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[:2])[0]
            tps, pos = 10 ** 6, 8
            while pos + 4 <= len(body):
                code, olen = struct.unpack(endian + "HH", body[pos:pos + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:
                    v = body[pos + 4]
                    tps = 2 ** (v & 0x7F) if v & 0x80 else 10 ** v
                pos += 4 + ((olen + 3) & ~3)
            ifaces.append((linktype, tps))
        elif btype == 6:  # Enhanced Packet Block
            iid, thi, tlo, cap, orig = struct.unpack(endian + "IIIII", body[:20])
            no += 1
            if iid >= len(ifaces):
                continue
            linktype, tps = ifaces[iid]
            ts_ns = ((thi << 32) | tlo) * 1_000_000_000 // tps
            pkt = _decode_frame(no, ts_ns, body[20:20 + cap], linktype, orig)
            if pkt:
                yield pkt


# ---------------------------------------------------------------- API
def read_packets(path: str | Path) -> Iterator[Packet]:
    """Duyệt các gói IPv4 UDP/TCP trong file .pcap/.pcapng theo thứ tự trong file."""
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from _read_pcapng(f, magic)
        elif magic in _PCAP_MAGICS:
            yield from _read_pcap(f, magic)
        else:
            raise ValueError(f"{path}: không phải file pcap/pcapng")
