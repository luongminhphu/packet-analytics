import os
import socket
import struct
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from packet_analytics.analyzer import analyze
from packet_analytics.config import Config, load_config
from packet_analytics.fix import split_messages
from packet_analytics.pcap_reader import read_packets
from packet_analytics.pcap_writer import PcapngWriter

VN = timezone(timedelta(hours=7))
RULES = [
    {"match": {"35": "MM"}, "key": "MM"},
    {"match": {"35": "M1"}, "key": "M1"},
    {"match": {"35": "K08"}, "src_port": 30115, "key": "K08"},
    {"match": {"35": "K04"}, "src_port": 30115, "key": "K04:{20005}"},
    {"match": {"35": "D"}, "dst_ip": "10.1.1.1", "dst_port": 30111, "key": "D"},
]


def fix(t, extra=""):
    body = f"35={t}\x0149=GW\x0156=X\x0134=1\x0152=20260917-02:00:00\x01{extra}"
    return (f"8=FIX.4.4\x019={len(body)}\x01" + body + "10=000\x01").encode()


def ip_frame(proto, l4):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0,
                     socket.inet_aton("10.0.0.1"), socket.inet_aton("10.1.1.1"))
    return b"\x01\x00\x5e\x01\x01\x01" + b"\x00" * 6 + b"\x08\x00" + ip + l4


def udp(payload, dport=5000):
    return ip_frame(17, struct.pack("!HHHH", 4000, dport, 8 + len(payload), 0) + payload)


def tcp(payload, seq, sport=30115, dport=43716):
    return ip_frame(6, struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, 0x18, 65535, 0, 0) + payload)


def ts(h, m, s, nanos):
    return int(datetime(2026, 9, 17, h, m, s, tzinfo=VN).timestamp()) * 10**9 + nanos


def write_pcap(path, pkts):  # pcap cổ điển, ns
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
        for t, d in pkts:
            f.write(struct.pack("<IIII", t // 10**9, t % 10**9, len(d), len(d)) + d)


def write_ng(path, pkts):
    with PcapngWriter(path) as w:
        for t, d in pkts:
            w.write(t, d)


def cfg():
    return Config(decoder={"rules": RULES})


class T(unittest.TestCase):
    def sample(self):
        k04 = fix("K04", "20005=AB1\x01")
        k08 = fix("K08")
        return [
            (ts(8, 59, 59, 900_000_000), udp(fix("MM"))),                      # trước giờ mở cửa -> bỏ
            (ts(9, 0, 0, 4_590_000), udp(fix("MM"))),
            (ts(9, 0, 0, 8_740_000), udp(fix("M1") + fix("M1"))),              # 2 message / datagram
            (ts(9, 0, 0, 114_090_000), tcp(k04, 1000)),
            (ts(9, 0, 0, 150_000_000), tcp(k08[:40], 1000 + len(k04))),        # message cắt đôi
            (ts(9, 0, 0, 160_000_000), tcp(k08[40:], 1000 + len(k04) + 40)),
            (ts(9, 0, 0, 170_000_000), tcp(k08[40:], 1000 + len(k04) + 40)),   # retransmit
        ]

    def check(self, path):
        self.assertEqual(len(list(read_packets(path))), 7)
        d = analyze([str(path)], cfg())[0]
        self.assertEqual(d.date, "2026-09-17")
        self.assertAlmostEqual(d.first["MM"].delay_ms, 4.59, places=3)   # gói 08:59:59 không làm âm
        self.assertAlmostEqual(d.first["M1"].delay_ms, 8.74, places=3)
        self.assertEqual(d.first["M1"].count, 2)
        self.assertAlmostEqual(d.first["K04:AB1"].delay_ms, 114.09, places=3)
        self.assertAlmostEqual(d.first["K08"].delay_ms, 160.0, places=3)  # tính tại segment hoàn tất message
        self.assertEqual(d.first["K08"].count, 1)                         # retransmit không đếm lại
        self.assertEqual(d.race()[0][0], "MM")

    def test_pcap(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "a.pcap"
            write_pcap(p, self.sample())
            self.check(p)

    def test_pcapng(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "a.pcapng"
            write_ng(p, self.sample())
            self.check(p)

    def test_flow_filter(self):
        pk = [(ts(9, 0, 0, 5_000_000), tcp(fix("D"), 1, 59000, 40111)),   # sai cổng -> bỏ
              (ts(9, 0, 0, 9_000_000), tcp(fix("D"), 1, 59000, 30111))]
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "d.pcap"
            write_pcap(p, pk)
            d = analyze([str(p)], cfg())[0]
            self.assertAlmostEqual(d.first["D"].delay_ms, 9.0, places=3)

    def test_split_messages(self):
        msgs, rest = split_messages(b"tail=1\x0110=111\x01" + fix("MM") + fix("M1")[:30])
        self.assertEqual(len(msgs), 1)
        self.assertTrue(rest.startswith(b"8=FIX"))

    def test_exchange_ts(self):
        c = Config(latency_mode="exchange_ts", exchange_ts_format="%Y%m%d-%H:%M:%S.%f",
                   decoder={"rules": [{"match": {"35": "D"}, "key": "D"}]})
        m = fix("D").replace(b"52=20260917-02:00:00", b"52=20260917-09:00:00.010")
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "e.pcap"
            write_pcap(p, [(ts(9, 0, 0, 12_500_000), udp(m))])
            self.assertAlmostEqual(analyze([str(p)], c)[0].first["D"].delay_ms, 2.5, places=3)

    @unittest.skipUnless(os.environ.get("PA_SAMPLE_PCAP"), "đặt PA_SAMPLE_PCAP=<file pcapng mẫu>")
    def test_golden_sample(self):
        d = analyze([os.environ["PA_SAMPLE_PCAP"]], load_config("config.example.toml"))[0]
        want = {"M1": 8.74, "MM": 4.59, "K08": 147.53, "K04:AD2": 748.17, "K04:AA1": 750.99,
                "K04:AB1": 114.09, "D": 881.53}
        for k, v in want.items():
            self.assertAlmostEqual(d.first[k].delay_ms, v, places=2, msg=k)


if __name__ == "__main__":
    unittest.main()
