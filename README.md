# packet-analytics

Công cụ **chỉ đọc / chỉ lắng nghe** (không gửi gì vào mạng, không can thiệp hệ thống giao dịch) để phân tích gói tin đầu ngày
giao dịch: giải mã message FIX do Sở gửi (M1, MM, K08, K04/AD2·AA1·AB1, D, ...), đo **first-arrival delay** theo ngày × message type
và dựng **Latency Heatmap** (CSV / Excel).

Hai nguồn dữ liệu: **import file `.pcap/.pcapng`** hoặc **capture realtime trên cổng mạng** (đồng thời lưu pcapng để đối soát lại).

Đã đối soát với capture mẫu `Capture_20260917_0858.pcapng`: kết quả khớp heatmap ngày 2026-09-17
(M1 8.74 · MM 4.59 · K08 147.53 · K04 AD2 748.17 / AA1 750.99 / AB1 114.09 · D 881.53 ms).

## Cài đặt
```bash
pip install -e ".[all]"        # openpyxl (Excel) + scapy (capture Windows / BPF). Linux tối thiểu: không cần gói nào, Excel cần openpyxl
```

## Cách dùng
```bash
# Web UI (import file, capture realtime, heatmap, Export Excel) — mặc định chỉ lắng nghe 127.0.0.1
packet-analytics serve -c config.example.toml --port 8080

# CLI
packet-analytics inspect Capture.pcapng -c config.example.toml -n 30 --hex --only-decoded
packet-analytics analyze Capture_*.pcapng -c config.example.toml --race --csv out.csv --xlsx out.xlsx
packet-analytics interfaces
sudo packet-analytics capture -i eth0 -c config.example.toml --start-at 08:58 --stop-at 09:05 -o capture.pcapng --xlsx out.xlsx
```

### Capture realtime
| Backend | Nền tảng | Ghi chú |
|---|---|---|
| `afpacket` | Linux | thuần stdlib, timestamp kernel `SO_TIMESTAMPNS` (ns), cần root / `CAP_NET_RAW`; lọc ở user-space |
| `scapy` | Linux / Windows | `pip install scapy` (+ Npcap trên Windows), hỗ trợ `--bpf` |

Lưu ý độ chính xác: capture bằng phần mềm có sai số vài chục µs trở lên và có thể rớt gói khi tải cao. Với đo đạc đua lệnh nghiêm túc,
nên capture bằng NIC/switch hỗ trợ hardware timestamp (hoặc SPAN/TAP + dumpcap) rồi **import** file vào công cụ này.

## Giao diện web
`packet-analytics serve -c config.example.toml` → http://127.0.0.1:8080
- **Import file**: kéo thả (có thanh tiến trình) hoặc nhập đường dẫn; **Capture realtime**: chọn interface/backend, xem số frame và thời gian chạy, file pcapng được lưu trong `data/`.
- **Latency Heatmap**: tô màu theo mức trễ (bật/tắt), ô sớm nhất của nhóm `highlight` in đậm đỏ, bấm vào dòng ngày để xem **thứ tự tới nơi** + gap; cột **Noted** sửa trực tiếp (lưu ở `data/notes.json`); Export CSV/Excel.
- **Live feed**: message đầu tiên của từng loại theo thời gian thực. Hỗ trợ dark mode, dùng được bằng bàn phím.
- Mã giao diện nằm ở `src/packet_analytics/web/static/` (HTML/CSS/JS thuần, không phụ thuộc thư viện ngoài).

## Cách đo (khớp feed Sở trong file mẫu)
- Feed là **FIX 4.4**: market data qua UDP multicast (`35=MM`, `M1`, `X`, `ME`...) và phiên TCP gateway (`35=K08`, `K04`, `D`...).
- Message FIX được tách theo `8=FIX ... 10=xxx<SOH>`; UDP có thể chứa nhiều message/datagram, TCP được **ghép lại theo luồng**
  (message bị cắt giữa các segment, retransmit). Thời điểm tới = timestamp của gói **hoàn tất** message.
- `delay = thời điểm tới − 09:00:00 (giờ VN)`, chỉ tính message tới **từ** 09:00:00 (`after_reference_only`).
- Cột `K04:AD2/AA1/AB1` tách theo tag `20005`. Mỗi cột được xác định bằng **rule** trong config (`[[decoder.rules]]`): điều kiện theo tag FIX
  + giới hạn theo flow (IP/port), vd `D` chỉ tính lệnh từ `172.24.11.160 → 172.24.251.15:30111` (flow khác cùng gửi `35=D` sớm hơn, 294 ms, **không** nằm trong heatmap gốc).
- Chế độ khác: `latency.mode = "exchange_ts"` (đo so với `SendingTime` tag 52, UTC, cần đồng bộ giờ) hoặc `"first_packet"`.
- Nếu đổi IP/port gateway, sửa `[[decoder.rules]]` trong config.

## Kiểm thử
```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PA_SAMPLE_PCAP=Capture_20260917_0858.pcapng PYTHONPATH=src python -m unittest discover -s tests -v   # đối soát file mẫu
```

## Bảo mật
Web UI không có xác thực → chỉ bind `127.0.0.1` (mặc định). Không commit file pcap/kết quả (đã có trong `.gitignore`).
