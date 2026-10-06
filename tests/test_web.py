import http.client
import json
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from packet_analytics.config import Config
from packet_analytics.web.server import make_handler
from packet_analytics.web.state import AppState
from test_basic import RULES, fix, tcp, ts, udp, write_pcap


class WebTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.cfg = Config(decoder={"rules": RULES}, columns=["M1", "MM"], highlight=["M1", "MM"])
        self.st = AppState(self.cfg, self.dir / "data")
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.st, "127.0.0.1"))
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.tmp.cleanup()

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = {"X-PA-Request": "1", "Content-Type": "application/json", **(headers or {})}
        c.request(method, path, json.dumps(body) if body is not None else None, h)
        r = c.getresponse()
        data = r.read()
        return r.status, data

    def test_static_and_state(self):
        for p in ("/", "/static/app.js", "/static/app.css"):
            self.assertEqual(self.req("GET", p)[0], 200)
        code, data = self.req("GET", "/api/state")
        self.assertEqual(code, 200)
        self.assertIn("rows", json.loads(data))

    def test_csrf_and_host_guard(self):
        self.assertEqual(self.req("POST", "/api/reset", {}, {"X-PA-Request": "0"})[0], 403)
        self.assertEqual(self.req("GET", "/api/state", headers={"Host": "evil.example.com"})[0], 403)
        self.assertEqual(self.req("POST", "/api/reset", {}, {"Origin": "http://evil.example.com"})[0], 403)
        self.assertEqual(self.req("POST", "/api/reset", {})[0], 200)

    def test_import_note_export(self):
        f = self.dir / "a.pcap"
        write_pcap(f, [(ts(9, 0, 0, 4_590_000), udp(fix("MM"))), (ts(9, 0, 0, 8_740_000), udp(fix("M1")))])
        self.assertEqual(self.req("POST", "/api/import-path", {"path": str(f)})[0], 200)
        for _ in range(50):
            d = json.loads(self.req("GET", "/api/state")[1])
            if not d["job"]["running"] and d["rows"]:
                break
            time.sleep(0.1)
        row = d["rows"][0]
        self.assertEqual(row["cells"], {"M1": 8.74, "MM": 4.59})
        self.assertEqual(row["best"], "MM")
        self.assertEqual([x["key"] for x in row["race"]], ["MM", "M1"])
        self.assertEqual(len(d["events"]), 2)
        # ghi chú được lưu và xuất ra CSV
        self.assertEqual(self.req("POST", "/api/note", {"date": row["date"], "note": "No race day"})[0], 200)
        self.assertEqual(self.req("POST", "/api/note", {"date": "../x", "note": "x"})[0], 400)
        code, csv = self.req("GET", "/api/export.csv")
        self.assertEqual(code, 200)
        self.assertIn(b"No race day", csv)
        self.assertTrue((self.dir / "data" / "notes.json").exists())
        # path không phải pcap bị từ chối
        self.assertEqual(self.req("POST", "/api/import-path", {"path": "/etc/passwd"})[0], 400)


if __name__ == "__main__":
    unittest.main()
