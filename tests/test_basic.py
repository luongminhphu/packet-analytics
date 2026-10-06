import socket
import struct
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from packet_analytics.analyzer import analyze
from packet_analytics.config import Config
from packet_analytics.pcap_reader import read_packets

VN = timezone(timedelta(hours=7))


def frame(payload: bytes, dst="233.1.1.1", dport=5000) -> bytes:
    udp = struct.pack("!HHHH", 4000, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     socket.inet_aton("10.0.0.1"), socket.inet_aton(dst))
    return b"\x01\x00\x5e\x01\x01\x01" + b"\x00" * 6 + b"\x08\x00" + ip + udp


def epoch_ns(h, m, s, ms_frac) -> int:
    base = datetime(2026, 9, 28, h, m, s, tzinfo=VN)
    return int(base.timestamp()) * 10**9 + ms_frac


def write_pcap(path, pkts):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))  # ns pcap
        for ts, data in pkts:
            f.write(struct.pack("<IIII", ts // 10**9, ts % 10**9, len(data), len(data)) + data)


def write_pcapng(path, pkts):
    def blk(t, body):
        body += b"\x00" * (-len(body) % 4)
        return struct.pack("<II", t, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += blk(1, struct.pack("<HHI", 1, 0, 65535) + struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0))
    for ts, data in pkts:
        out += blk(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(data), len(data)) + data)
    Path(path).write_bytes(out)


class T(unittest.TestCase):
    def setUp(self):
        self.pkts = [
            (epoch_ns(9, 0, 0, 8_740_000), frame(b"..T=M1|")),
            (epoch_ns(9, 0, 0, 4_590_000), frame(b"..T=MM|")),
            (epoch_ns(9, 0, 0, 20_000_000), frame(b"T=MM|T=D|")),  # 2 message / datagram
            (epoch_ns(9, 0, 0, 30_000_000), frame(b"T=K04|S=AD2|")),
        ]
        self.cfg = Config(protocol="udp", decoder={"pattern": r"T=(?P<type>[A-Z0-9]+)\|(?:S=(?P<sub>[A-Z0-9]+)\|)?",
                                                   "key": "{type}"})

    def _check(self, path):
        pk = list(read_packets(path))
        self.assertEqual(len(pk), 4)
        res = analyze([str(path)], self.cfg)
        self.assertEqual(len(res), 1)
        d = res[0]
        self.assertEqual(d.date, "2026-09-28")
        self.assertAlmostEqual(d.first["M1"].delay_ms, 8.74, places=3)
        self.assertAlmostEqual(d.first["MM"].delay_ms, 4.59, places=3)
        self.assertAlmostEqual(d.first["D"].delay_ms, 20.0, places=3)
        self.assertEqual(d.first["MM"].count, 2)
        self.assertEqual(d.race()[0][0], "MM")

    def test_pcap(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "a.pcap"
            write_pcap(p, self.pkts)
            self._check(p)

    def test_pcapng(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "a.pcapng"
            write_pcapng(p, self.pkts)
            self._check(p)

    def test_exchange_ts(self):
        cfg = Config(protocol="udp", latency_mode="exchange_ts", exchange_ts_format="%H%M%S%f",
                     decoder={"pattern": r"T=(?P<type>[A-Z0-9]+)\|TS=(?P<ts>\d+)\|"})
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "b.pcap"
            write_pcap(p, [(epoch_ns(9, 0, 0, 12_500_000), frame(b"T=M1|TS=090000010|"))])
            d = analyze([str(p)], cfg)[0]
            self.assertAlmostEqual(d.first["M1"].delay_ms, 2.5, places=3)


if __name__ == "__main__":
    unittest.main()
