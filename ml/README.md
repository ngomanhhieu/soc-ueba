# ml/ – Dữ liệu & ML

Phát hiện hành vi bất thường của người dùng (UEBA) trên 2 bộ dữ liệu SOC chuẩn:

| Dataset | Hành vi | Nhãn đánh giá | Dùng cho |
|---|---|---|---|
| **LANL** auth (Los Alamos) | xác thực Windows/AD trong mạng nội bộ | `redteam.txt` – 749 sự kiện tấn công thật | di chuyển ngang, chiếm tài khoản, người/máy |
| **CERT r4.2** (CMU) | logon, USB, file, email, web của 1000 nhân viên | `answers/` – 70 insider | insider threat, vi phạm chính sách |

## 1. Cài đặt (Windows)

```powershell
cd ml
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt   # torch CPU: pip install torch --index-url https://download.pytorch.org/whl/cpu
```

Dữ liệu gốc rất nặng nên **để ngoài repo**: mặc định `F:/soc-ueba-data`, đổi bằng biến môi trường
`SOC_DATA_DIR`. Dữ liệu đã xử lý (`data/processed`), model (`models`) không commit.

## 2. Tải dữ liệu

```powershell
python src/download_data.py cert                                  # ~4.8GB, kiểm tra SHA-256
python src/download_data.py lanl --email <email> --lanl-gb 4.4    # phần đầu file (ngày 0–29)
```
- LANL bắt điền email + mục đích để cấp link (token lưu ở `lanl/.token`, hết hạn sau ~1 ngày →
  xoá file đó rồi chạy lại). Server có lúc giới hạn ~8KB/s mỗi kết nối nên script tải song song;
  **chạy lại sẽ tải tiếp**, tăng `--lanl-gb` thì chỉ tải thêm phần sau rồi nối vào.
- Vì sao 4.4GB (/7.6GB): file auth sắp theo thời gian, **toàn bộ 749 sự kiện red team nằm ở
  ngày 1–29** (`reports/lanl_redteam_by_day.csv`).
- CERT: giải nén `r4.2.tar.bz2` và `answers.tar.bz2` vào `<SOC_DATA_DIR>/cert/`.

## 3. Chạy pipeline

```powershell
cd src
# LANL
python lanl_explore_redteam.py                       # A1: red team ở ngày nào
python lanl_load_auth.py --start-day 0 --end-day 29  # A1: lọc auth → parquet theo ngày
python features.py --workers 3                       # A2: feature user × ngày (~15 phút)
python experiments_lanl.py                           # A6: so sánh phương án, chọn trên val
python lanl_online.py                                # A6: mô phỏng triển khai từng ngày (các biến thể)
python run_pipeline.py [--ioc-feedback]              # A3–A8 với phương án đã chọn → alerts.json

# CERT
python cert_http_domains.py                          # A1: rút gọn http.csv 14GB theo domain (~3 phút)
python cert_features.py                              # A1+A2
python experiments_cert.py                           # A6: so sánh phương án × 3 seed
python cert_pipeline.py --split-date 2010-09-01      # A3–A8 → alerts_cert.json

python visualize.py lanl ; python visualize.py cert  # biểu đồ cho báo cáo
```

## 4. Các thành phần

| File | Việc | Ghi chú |
|---|---|---|
| `config.py` | đường dẫn, hằng số | `SOC_DATA_DIR` |
| `download_data.py` | tải LANL/CERT | song song + resume |
| `lanl_explore_redteam.py` | A1 | phân bố red team theo ngày |
| `lanl_load_auth.py` | A1 | đọc gzip theo luồng, gắn nhãn red team |
| `features.py` | A2 | 33 feature: khối lượng, kiểu xác thực, **so với lịch sử** (máy nguồn/đích mới, giờ lạ, cạnh mới toàn mạng), fan-in máy nguồn, nhịp thời gian. Hai giai đoạn: tổng hợp từng ngày (song song) + novelty tuần tự (có thể cách ly) |
| `statistical.py` | A3 | self-baseline (z-score theo lịch sử) + peer-baseline (median/IQR theo nhóm) |
| `models.py` | A4 | Isolation Forest + Autoencoder (PyTorch); điểm = percentile so với train |
| `experiments_lanl.py` | A4+A6 | thêm **ECOD**, IF trên nhóm feature di chuyển ngang, các kiểu ensemble; chọn trên val |
| `lanl_online.py` | A4+A6 | chạy từng ngày như thật: **cách ly baseline**, fan-in, độ hiếm, vòng phản hồi IOC |
| `lanl_rarity.py` | A2 | độ hiếm có tần suất + suy giảm theo thời gian (max trong ngày) |
| `lanl_hosts.py` | A4 | ML **mức máy**: máy bàn đạp – nhiều tài khoản đăng nhập NTLM từ máy mà với họ là lạ |
| `human_bot.py` | A5 | người/máy: nhãn yếu từ tên tài khoản (`U*` vs `C*$`, `SYSTEM`), học từ **nhịp hành vi** |
| `evaluate.py` | A6 | ROC-AUC, PR-AUC, precision/recall@k, FPR ở ngưỡng, biểu đồ ROC/PR |
| `mitre_mapping.json` | A7 | lý do bất thường → MITRE ATT&CK |
| `export_alerts.py` | A8 | `reports/alerts.json` đúng `schema/alert.schema.json`, tuỳ chọn `--es-url` đẩy Elasticsearch |
| `cert_http_domains.py`, `cert_features.py`, `cert_pipeline.py` | A1–A8 cho CERT | peer group = vai trò LDAP; độ hiếm domain; tổng 7/30 ngày |
| `experiments_cert.py` | A6 cho CERT | phương án × bộ feature × 3 seed, chọn trên val |

## 5. Thiết kế đánh giá (để bảo vệ)

- **Chia theo thời gian**, không xáo trộn: học quá khứ, phát hiện tương lai (giống triển khai thật).
- **Ba tập: train / validation / test.** Mọi lựa chọn (mô hình, ensemble, bộ feature) làm trên
  validation theo PR-AUC; test chỉ để báo cáo.
  - LANL: ngày 0 chỉ làm lịch sử, train 1–7, val 8–19, **test 20–29 – chưa từng nhìn khi thiết kế
    feature** (feature cũ được thiết kế khi đã xem red team ngày 8–15).
  - CERT: 30 ngày đầu làm lịch sử, train → 2010-06, val 2010-07/08, test từ 2010-09.
- Mô hình **không giám sát** – nhãn chỉ dùng để chấm điểm, không dùng để train. Riêng biến thể
  "phản hồi IOC" dùng nhãn để mô phỏng analyst → báo cáo tách riêng.
- **Không rò nhãn vào feature**: không lấy danh sách domain/máy từ file nhãn.
- Dữ liệu cực kỳ mất cân bằng → báo PR-AUC, precision@k, FPR; **không** dùng accuracy. So sánh
  công bằng bằng **ngân sách cảnh báo cố định** (analyst xem K cảnh báo/ngày).
- Mô hình ngẫu nhiên (IF, AE) chạy 3 seed, báo trung bình ± độ lệch chuẩn.
- Điểm = percentile so với train: `alert_score ≥ 0.99` = bất thường hơn 99% user-ngày lúc train.
- LANL ẩn danh thời gian (giây từ 1) → `timestamp` trong alerts quy đổi từ mốc giả định 2026-09-01.

## 6. Kết quả

Chi tiết: `notebooks/01_xem_ket_qua_cert.ipynb`, `notebooks/02_xem_ket_qua_lanl.ipynb`,
`reports/*_experiments.csv`, `reports/lanl_online.csv`.

### CERT r4.2 (test từ 2010-09-01, 52 insider)

Pipeline hiện tại (`cert_pipeline.py`): feature theo ngày + tổng 7/30 ngày + **xu hướng** (30 ngày
gần nhất so với 60 ngày trước – nhắm hành vi tăng dần). Val chọn **Autoencoder** (PR-AUC val 0.138 vs
IF 0.134 – trong mức dao động giữa seed; thử nghiệm 3 seed chọn IF → hai mô hình ngang nhau trên val).

| Phương án (test) | ROC-AUC | PR-AUC | Bắt insider, 2 cảnh báo/ngày | 5 cảnh báo/ngày |
|---|---|---|---|---|
| Thống kê (self + peer) | 0.856 | 0.014 | 9 | 12 |
| ECOD | 0.903 | 0.021 | 5 | 6 |
| IF, ngày + cửa sổ (bản trước) | 0.950 | 0.058 | 27 | 35 (KB1 21/22, KB2 9/25, KB3 5/5) |
| **AE, ngày + cửa sổ + xu hướng (pipeline)** | **0.937** | **0.079** | **27** | **38** (KB1 22/22, KB2 11/25, KB3 5/5) |
| *Bản cũ – feature rò nhãn* | *0.907* | *0.095* | – | – |

3 seed (`experiments_cert.py`, `reports/cert_experiments.csv`): thêm xu hướng – IF PR-AUC 0.061 →
0.070, AE 0.089 → 0.095; kịch bản 2 vẫn khó với IF (7–9/25), AE tốt hơn (16–19/25).

- **Đã sửa rò nhãn**: bản cũ có `http_leak`/`http_keylogger` = danh sách domain lấy từ `answers/`
  → bật ở 68+10 ngày insider và **0** ngày bình thường. Thay bằng **độ hiếm domain** (tỉ lệ nhân
  viên từng vào, tính nhân quả) + danh mục URL chọn theo tên (trang tuyển dụng, đối thủ). Không cần
  danh sách mà kịch bản 1 (wikileaks) vẫn bắt 21/22: wikileaks và trang keylogger tự nổi lên vì
  < 1% nhân viên từng vào.
- Kịch bản 2 (lấy dữ liệu dần dần nhiều tuần) vẫn khó: 9/25. Đã thử làm mượt điểm 7 ngày → **kém
  hơn trên val** (mất các đột biến 1 ngày của KB1, KB3) nên không dùng.
- AE trên test tốt hơn IF, nhưng val chọn IF (val chỉ có 24 insider, chênh lệch ~1.5 độ lệch chuẩn)
  → giữ nguyên lựa chọn, không chọn lại theo test.

### LANL (test ngày 20–29: 34 user-ngày red team, 26 tài khoản)

| Phương án | Val PR-AUC | **Test ROC** | **Test PR-AUC** | TK bắt được (25 cảnh báo/ngày) |
|---|---|---|---|---|
| Ensemble cũ (stat + IF + AE) | 0.082 | 0.716 | 0.001 | 0/26 |
| ECOD + IF di chuyển ngang (chọn trên val) | 0.158 | 0.860 | 0.010 | 1/26 |
| + cách ly baseline + fan-in máy nguồn | 0.165 | 0.901 | 0.036 | 3/26 |
| + độ hiếm tần suất, suy giảm theo thời gian (**`run_pipeline.py`**) | **0.170** | **0.971** | **0.087** | 4/26 |
| + phản hồi IOC từ analyst (`--ioc-feedback`, **dùng nhãn**) | 0.428 | 0.9998 | 0.486 | 24/26 |
| Tham chiếu có giám sát (học nhãn val → test) | – | 0.949 | 0.028 | – |

**Mức máy (`lanl_hosts.py`, thiết kế sau chẩn đoán):** xem 5 máy/ngày bắt **10/26** tài khoản ở test
(93/97 ở val); ghép vào Lớp 4 thành 2 hàng đợi (20 tài khoản + 5 máy) → **13/26** ở test (trước 4/26)
với cùng 25 incident/ngày. Bài học: chấm theo lịch sử riêng của máy lại bị **đầu độc ở mức máy**
(máy bàn đạp "học" rằng mình vốn toàn người lạ → 0/26); chuẩn hoá theo tỉ lệ toàn mạng thì không.
Thêm 2 bước sau chẩn đoán: incident máy liệt kê **mọi** tài khoản dùng máy đó (máy ≤ 50 tài khoản) → 22/26; theo dõi máy đã bị nghi trong 7 ngày → **26/26** (đổi lại ~39 incident/ngày thay vì 25; val đã gần kịch trần 96/97 nên không xác nhận độc lập được).

Phương án trong pipeline (chọn trên val theo PR-AUC): val ROC 0.985, PR-AUC 0.170, bắt 66/97 tài
khoản ở ngưỡng 0.99; test bắt **13/26** tài khoản ở ngưỡng 0.99 – nhưng với **~115 cảnh báo/ngày**
(cách ly + độ hiếm làm điểm cao hơn theo thời gian). Ở cùng ngân sách 25 cảnh báo/ngày, mức tăng
chỉ còn 3 → 4 tài khoản: cải thiện thật nhưng khiêm tốn; Lớp 4 (risk, top-K) gánh phần lưu lượng.

- **Con số cũ (ROC 0.91) là lạc quan**: trên ngày 20–29 chưa từng nhìn, ensemble cũ chỉ còn ROC
  0.72, PR-AUC 0.001. Gần như mất khả năng phát hiện.
- **Nguyên nhân – baseline bị đầu độc**: 57/60 sự kiện red team ngày 20–29 dùng lại đúng cặp
  (tài khoản, máy C17693) đã dùng ở ngày 8–19. Feature "mới so với lịch sử" đã học chúng thành
  bình thường (trung vị `n_new_src_comp` của red team test = 0).
- **Sửa (không cần nhãn)**: user-ngày bị cảnh báo không được học vào lịch sử (`lanl_online.py`) +
  fan-in máy nguồn không phụ thuộc lịch sử + **độ hiếm có tần suất** (`lanl_rarity.py`): lịch sử
  là số đếm suy giảm (bán rã 7 ngày) thay vì cờ "đã thấy", lấy MAX trong ngày thay vì gộp – máy
  C17693 dùng ở ngày 8 vẫn hiếm ở ngày 26. Cải thiện cả val lẫn test, nhưng test vẫn khó: tấn
  công giai đoạn sau rất "êm" (1–2 sự kiện/ngày từ tài khoản đã chiếm).
- **Vòng phản hồi IOC** (analyst xác nhận cảnh báo → máy tấn công thành IOC → luật cảnh báo) bắt
  gần hết, nhưng LANL chỉ có 1–2 máy tấn công nên kết quả này phụ thuộc mạnh vào dataset. Đây là
  lý lẽ cho kiến trúc **ML + luật + AI Agent/SOAR** (`soc/`): ML tìm ra, analyst xác nhận, agent
  rút IOC thành luật.
- Các biến thể cách ly/fan-in/IOC được thiết kế **sau khi** chẩn đoán test → đã kiểm tra chúng
  cũng tốt hơn trên val, nhưng con số test của chúng vẫn kém khách quan hơn dòng "chọn trên val".

### Bộ phân loại người / máy (A5)

- Phân biệt tài khoản người vs máy/dịch vụ trên user chưa thấy: accuracy 0.988, ROC-AUC 0.999.
- **Không phát hiện được tài khoản bị chiếm**: dùng `1 − is_human_prob` làm điểm cho red team →
  ROC 0.33–0.40; độ tụt so với thói quen của chính user → ROC 0.40–0.45. Tài khoản bị chiếm vẫn
  hành xử "giống người". `is_human_prob` chỉ giữ làm ngữ cảnh trong cảnh báo.

### Điều đã học được (đưa vào báo cáo)

- **Đánh giá trên dữ liệu thật sự chưa nhìn** quan trọng hơn mọi tinh chỉnh: LANL từ ROC 0.91 →
  0.72 khi đổi sang ngày 20–29.
- **Rò nhãn rất dễ xảy ra**: danh sách domain "đáng ngờ" lấy từ file nhãn làm kết quả đẹp giả.
- **Gộp nhiều mô hình không phải lúc nào cũng tốt**: ensemble cũ thua cả 1 feature đơn
  (`new_src_max_fanin`). ECOD (không tham số, giải thích được từng feature) tốt nhất trên LANL.
- UEBA dựa trên "mới so với lịch sử" dễ bị **đầu độc baseline** khi kẻ tấn công ở lâu trong mạng.
- Thêm "độ lệch so với thói quen của chính user" (self z-score) tăng PR-AUC của AE trên CERT ~2 lần.
- Làm mượt tỉ lệ (Bayesian smoothing) loại báo động giả từ tài khoản chỉ có 1–2 sự kiện.
