# packet-analytics

Công cụ **chỉ đọc** (offline) để phân tích file capture (`.pcap` / `.pcapng`) đầu ngày giao dịch:
giải mã message type do Sở gửi (M1, MM, K08, K04/AD2, AA1, AB1, D, ...) và đo **first-arrival delay** theo ngày × message type,
phục vụ phân tích đua lệnh. Thuần Python stdlib (Excel export cần `openpyxl`).

## Cài đặt
```bash
pip install -e .            # hoặc: pip install -e ".[excel]"
```

## Quy trình dùng
1. Capture đầu ngày bằng tcpdump/Wireshark/card capture (lưu ra pcap/pcapng, có hardware timestamp càng tốt).
2. Xem thử gói tin & kiểm tra decoder:
   ```bash
   packet-analytics inspect 2026-09-28.pcap -c config.toml -n 30 --hex
   ```
3. Phân tích và xuất báo cáo:
   ```bash
   packet-analytics analyze 2026-09-2*.pcap -c config.toml --race --csv out/heatmap.csv --xlsx out/heatmap.xlsx
   ```

## Cấu hình (`config.example.toml`)
- `[capture]`: lọc protocol / IP / port của feed Sở, múi giờ tách ngày.
- `[decoder]`: cách lấy message type từ payload (`regex` với named group `type`/`sub`/`ts`, hoặc `fixed` theo offset).
  **Phải chỉnh theo format thực tế của feed.** `key = "{type}:{sub}"` để tách các cột như K04 (AD2/AA1/AB1).
- `[latency].mode`:
  - `clock`: delay = giờ nhận − mốc `reference_clock` (vd 09:00:00).
  - `exchange_ts`: delay = giờ nhận − timestamp trong message (cần group `ts`; yêu cầu đồng bộ giờ máy capture, PTP/NTP).
  - `first_packet`: delay so với message đầu tiên trong ngày.
- `[report]`: danh sách cột, nhóm `highlight` (ô nhỏ nhất tô xanh), nhãn cột.

## Kiểm thử
```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Lưu ý vận hành
- Công cụ chỉ đọc file capture, không tương tác hệ thống giao dịch.
- Độ chính xác latency phụ thuộc nguồn timestamp của capture (NIC/hardware vs kernel) và đồng bộ đồng hồ.
- Không commit file pcap/kết quả lên git (đã có trong `.gitignore`).
