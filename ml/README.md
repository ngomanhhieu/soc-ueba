# ml/ – Người A (Data & ML)

```bash
cd ml
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 0. Chạy thử ngay (chưa cần tải LANL)
```bash
SYNTH=1 bash run_lanl.sh
```
Sinh dữ liệu giả đúng định dạng LANL vào `data/raw/synthetic/` rồi chạy hết pipeline.
Chỉ để kiểm tra code — **không dùng số liệu này trong báo cáo** (dữ liệu giả rất dễ, metric ~1.0).

## 1. Dữ liệu thật
Tải từ https://csr.lanl.gov/data/auth/ (cần đăng ký): `auth.txt.gz` (~7GB nén, ~1 tỷ dòng, 58 ngày)
và `redteam.txt.gz` (749 sự kiện) → đặt vào `data/raw/`. Không commit (đã có trong `.gitignore`).

## 2. Chạy toàn bộ
```bash
bash run_lanl.sh                                    # mặc định: ngày 0–30, 5% user + mọi user red team
END_DAY=20 USER_SAMPLE=0.02 bash run_lanl.sh        # máy ít RAM
TRAIN_END=12 VAL_END=16 bash run_lanl.sh            # tự chọn mốc chia train/val/test
```
Nên chạy `python src/lanl_explore_redteam.py` trước để xem red team rơi vào ngày nào, rồi chọn
`TRAIN_END/VAL_END` sao cho **cả val và test đều có red team** (script sẽ cảnh báo nếu test trống).

## 3. Từng bước (ứng với TASKS.md)
| Task | Script | Đầu ra |
|---|---|---|
| A1 | `src/lanl_load_auth.py` – đọc theo chunk, lọc ngày, giữ mọi user red team + mẫu user khác + mẫu tài khoản máy | `data/processed/auth_subset.*`, `redteam_subset.*` |
| A2 | `src/features.py` – 32 feature theo user × giờ (khối lượng, host mới, Kerberos/NTLM, logon type, ngoài giờ, bot-like) + nhãn red team | `data/processed/features.*` |
| A3 | `src/statistical.py` – z-score theo user, IQR, z theo peer group (KMeans) | cột `score_zscore/iqr/peer_z/stat` |
| A4 | `src/models.py` + `src/train.py` – Isolation Forest, Autoencoder (PyTorch), LOF; tinh chỉnh theo PR-AUC trên val | `models/ueba_models.joblib`, `models/train_config.json` |
| A5 | `src/human_bot.py` – Random Forest người/bot với nhãn yếu (C$ = bot, user có logon Interactive = người), chỉ dùng feature bot-like | cột `is_human_prob` |
| A6 | `src/evaluate.py` – P/R/F1, ROC-AUC, PR-AUC, confusion matrix, so sánh 9 phương pháp + RF có giám sát, mức cửa sổ và mức user, ablation | `reports/metrics.md/.csv`, `roc_pr.png`, `confusion_combined.png`, `ablation.csv` |
| A7 | `src/mitre_mapping.json` – hành vi → tactic/technique; feature/rule → hành vi | |
| A8 | `src/export_alerts.py` – alert đúng `schema/alert.schema.json` (có kiểm tra), tuỳ chọn đẩy ES | `reports/alerts.json` |

`src/rules.py` là bản rule-only tối giản để so sánh trong A6; rule chính thức do B viết ở `platform/rules/` — giữ ngưỡng đồng bộ.

## 4. Bàn giao cho Người B
```bash
python src/export_alerts.py --split test --min-score 0.995           # -> reports/alerts.json
python src/export_alerts.py --es http://localhost:9200 --index alerts-ueba   # sau khi B dựng Elastic
```
- `anomaly_score` = percentile của điểm kết hợp so với giai đoạn train (0..1).
- Điểm kết hợp = 0.35·IF + 0.25·AE + 0.25·thống kê + 0.15·rule (đổi bằng `train.py --weights '{...}'`).
- `severity`: ≥0.9995 hoặc (≥0.998 và có rule) → critical; ≥0.998 high; ≥0.996 medium; còn lại low.
- `mitre` lấy theo rule đã kích hoạt, nếu không có thì theo feature lệch nhiều nhất (`features.top_feature`).
- `timestamp`: LANL dùng giây tương đối → cộng vào mốc `--base-date` (mặc định 2026-10-01Z).
- `alert_id` là UUID cố định theo (user, cửa sổ) → đẩy lại ES không bị trùng.

## 4b. Log thật từ ELK (Winlogbeat + Filebeat)
```bash
# 1) ECS -> bảng auth dạng LANL (đọc thẳng ES trên Ubuntu, hoặc --file <export.ndjson>)
ELASTIC_PASSWORD=... python src/ecs_to_auth.py --es https://<ip-ubuntu>:9200 --since now-14d/d
# 2) baseline 3 ngày đầu -> chấm phần còn lại -> reports/real_report.md, reports/alerts_real.json
python src/score_real.py --baseline-days 3 [--labels attacks.csv] [--es https://<ip>:9200]
```
- Windows: 4624/4625/4648/4634/4647/4768/4769/4776 → `user@DOMAIN`, `LogonType`, Kerberos/NTLM/Negotiate.
- Linux: sshd/login trong `system.auth` → `user@HOST`, auth `SSH-key`/`SSH-password`, logon `RemoteInteractive`.
- Mặc định `--mode local`: học "bình thường" của chính môi trường lab (UEBA thực tế); `--mode lanl` dùng model LANL để so sánh.
- `attacks.csv` (`user,start,end`, ISO có múi giờ) ghi các lần tự tấn công trong lab để đo P/R/F1.
- Windows console: đặt `PYTHONIOENCODING=utf-8` để in được tiếng Việt.

## 5. Ghi chú phương pháp (dùng khi viết báo cáo)
- Chia train/val/test **theo thời gian**, không shuffle. Ngưỡng cảnh báo = percentile điểm train (không nhìn nhãn); cột `best_f1` chỉ để tham khảo.
- Mặc định train **có** lẫn cửa sổ red team (giống thực tế). `train.py --clean-train` để so sánh với baseline sạch.
- Giờ trong ngày của LANL là tương đối `(time//3600)%24`; "ngoài giờ" = ngoài 8–18 theo mốc đó.
- `new_src/new_dst` cần lịch sử → 2 ngày đầu (`--warmup-days`) chỉ dùng làm lịch sử.
- Chưa cài torch thì Autoencoder tự dùng sklearn MLP (kém hơn) — cài đủ `requirements.txt` trước khi lấy số liệu báo cáo.
- Bước tiếp theo: thêm CERT Insider Threat (logon/device/email/file/http) vào `features.py`; các behavior `usb_exfil/email_exfil/web_exfil` đã có sẵn trong mapping.
