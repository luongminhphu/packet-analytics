"""Giải mã message FIX và gán 'key' cột heatmap theo rule trong config.

Mỗi rule:
  [[decoder.rules]]
  match = { "35" = "K04" }          # điều kiện theo tag FIX (so sánh bằng)
  key   = "K04:{20005}"             # template, {tag} lấy giá trị tag trong message
  src_ip/dst_ip/src_port/dst_port   # (tuỳ chọn) giới hạn theo flow
Rule đầu tiên khớp quyết định key; không rule nào khớp -> bỏ qua message.
Nếu không khai báo rule: key = giá trị tag 35 (mọi message type).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .fix import TcpReassembler, parse_tags, split_messages


@dataclass(slots=True)
class Message:
    key: str
    tags: dict
    exchange_ts: str | None = None


_TPL = re.compile(r"\{(\d+)\}")
_T35 = re.compile(rb"\x0135=([^\x01]+)\x01")


class Decoder:
    def __init__(self, cfg: dict):
        self.rules = cfg.get("rules", [])
        self.ts_tag = str(cfg.get("exchange_ts_tag", "52"))
        self.tcp = TcpReassembler()
        # Nếu mọi rule đều ràng buộc tag 35, bỏ qua sớm message không liên quan (nhanh hơn nhiều)
        want = {str(r.get("match", {}).get("35")) for r in self.rules if "35" in r.get("match", {})}
        self.want = want if self.rules and len(want) and all("35" in r.get("match", {}) for r in self.rules) else None

    @staticmethod
    def _flow_ok(r: dict, p) -> bool:
        for f, v in (("src_ip", p.src), ("dst_ip", p.dst), ("src_port", p.sport), ("dst_port", p.dport)):
            want = r.get(f)
            if want is not None and v not in (want if isinstance(want, list) else [want]):
                return False
        return True

    def _key(self, tags: dict, p) -> str | None:
        if not self.rules:
            return tags.get("35")
        for r in self.rules:
            if all(tags.get(t) == str(v) for t, v in r.get("match", {}).items()) and self._flow_ok(r, p):
                return _TPL.sub(lambda m: tags.get(m.group(1), ""), r["key"])
        return None

    def decode(self, p) -> list[Message]:
        if p.proto == "tcp":
            raws = self.tcp.feed(p)
        else:
            raws, _ = split_messages(p.payload)
        out = []
        for raw in raws:
            if self.want is not None:
                m = _T35.search(raw)
                if not m or m.group(1).decode("ascii", "replace") not in self.want:
                    continue
            tags = parse_tags(raw)
            key = self._key(tags, p)
            if key:
                out.append(Message(key, tags, tags.get(self.ts_tag)))
        return out
