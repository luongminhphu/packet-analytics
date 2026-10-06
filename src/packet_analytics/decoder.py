"""Trích message type (và tuỳ chọn exchange timestamp) từ payload.

Hai chế độ:
  regex : pattern có named group `type` (bắt buộc), `sub`, `ts` (tuỳ chọn).
          `key` là template ghép khoá cột, vd "{type}" hoặc "{type}:{sub}".
  fixed : lấy `type_length` byte tại `type_offset`; `ts_offset`/`ts_length` tuỳ chọn.
Một payload (datagram) có thể chứa nhiều message -> regex trả về nhiều kết quả.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(slots=True)
class Message:
    key: str
    exchange_ts: str | None = None


class Decoder:
    def __init__(self, cfg: dict):
        self.mode = cfg.get("mode", "regex")
        self.key_tpl = cfg.get("key", "{type}")
        self.encoding = cfg.get("encoding", "ascii")
        if self.mode == "regex":
            pat = cfg.get("pattern")
            if not pat:
                self.rx = None
            else:
                self.rx = re.compile(pat.encode("latin-1"))
                if "type" not in self.rx.groupindex:
                    raise ValueError("decoder.pattern phải có named group (?P<type>...)")
        elif self.mode == "fixed":
            self.t_off = int(cfg["type_offset"])
            self.t_len = int(cfg["type_length"])
            self.ts_off = cfg.get("ts_offset")
            self.ts_len = cfg.get("ts_length")
        else:
            raise ValueError(f"decoder.mode không hợp lệ: {self.mode}")

    def _txt(self, b: bytes | None) -> str:
        return b.decode(self.encoding, "replace").strip() if b else ""

    def decode(self, payload: bytes) -> list[Message]:
        if self.mode == "fixed":
            raw = payload[self.t_off:self.t_off + self.t_len]
            if len(raw) < self.t_len:
                return []
            ts = None
            if self.ts_off is not None and self.ts_len:
                ts = self._txt(payload[self.ts_off:self.ts_off + self.ts_len]) or None
            return [Message(self.key_tpl.format(type=self._txt(raw)), ts)]
        if self.rx is None:
            return []
        out = []
        for m in self.rx.finditer(payload):
            g = {k: self._txt(v) for k, v in m.groupdict().items()}
            g.setdefault("sub", "")
            out.append(Message(self.key_tpl.format(**g), g.get("ts") or None))
        return out
