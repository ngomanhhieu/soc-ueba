# soc/ – Nền tảng SOC: Elastic, luật Sigma, rủi ro, chuỗi tấn công + playbook SOAR, web app

Phần ML (dữ liệu, feature, mô hình) ở `ml/`. Thư mục này ghép mọi thứ thành một SOC chạy được.

| Thư mục | Lớp | Nội dung |
|---|---|---|
| `elastic/` | hạ tầng | cài + cấu hình Elasticsearch/Kibana 9.5.5 (zip Windows, không Docker), index, nạp dữ liệu |
| `mitre/` | – | MITRE ATT&CK Enterprise chính thức (706 technique) + ánh xạ ATT&CK → D3FEND (API d3fend.mitre.org) |
| `rules/` | 1 | engine Sigma tự viết (pandas), luật LANL + CERT, dò ngưỡng, đánh giá |
| `risk/` | 4 | điểm rủi ro theo thực thể, chuẩn hoá cảnh báo, incident |
| `graph/` | 5 | tái dựng chuỗi tấn công LANL (đồ thị xác thực), dòng thời gian nội gián CERT |
| `playbooks/` | 5 | SOAR: playbook tất định theo loại incident, đề xuất ứng phó gắn MITRE D3FEND |
| `api/` | – | web app SOC (FastAPI + HTML/JS thuần, giao diện tiếng Anh, theme tối/sáng), bảo mật, kiểm thử |
| `replay.py` | – | demo "SOC chạy từng ngày" (LANL + CERT, workflow B7–B15), vòng phản hồi IOC |
| `reports/` | – | kết quả đánh giá (CSV/JSON) |

## Cài & chạy (từ gốc repo)

```powershell
python soc/elastic/install_elastic.py              # tải + kiểm tra SHA-512 → F:\soc-ueba-data\elastic
python -m soc.elastic.elastic_ctl setup            # lần đầu: bảo mật, mật khẩu, token Kibana, bật
python -m soc.elastic.elastic_ctl start|stop|status
python -m soc.elastic.indices                      # index + user `soc_app`, `soc_pipeline` (quyền tối thiểu)
python -m soc.elastic.kibana_setup                 # data view Kibana cho các index soc-*
python -m soc.mitre.build_attack                   # ATT&CK → soc/mitre/attack_techniques.json
python -m soc.mitre.build_d3fend                   # ATT&CK → D3FEND → soc/mitre/d3fend_map.json

python -m soc.rules.run_rules tune                 # chọn ngưỡng luật trên TRAIN (không nhãn)
python -m soc.rules.run_rules run                  # chạy luật LANL ngày 1–29 + CERT, đánh giá
python -m soc.risk.risk                            # điểm rủi ro: chỉ luật / chỉ ML / cả hai
python -m soc.graph.edges                          # đồ thị xác thực LANL theo ngày (~280k cạnh/ngày)
python -m soc.risk.incidents                       # cảnh báo + incident (test) + chuỗi tấn công + playbook
python -m soc.graph.attack_graph                   # chấm điểm tái dựng chuỗi tấn công (val/test)
python -m soc.graph.insider_timeline               # chấm điểm dòng thời gian nội gián
python -m soc.elastic.ingest [--dataset lanl|cert] # nạp cảnh báo, incident, sự kiện vào ES

python -m soc.api.users demo                       # tài khoản analyst1 / lead1 (mật khẩu → .env)
python -m soc.api.users add hieu --role lead --password 1 --allow-weak   # tài khoản demo cục bộ (hieu/1 lead,
python -m soc.api.users add khoa --role analyst --password 2 --allow-weak #  khoa/2 analyst) – bỏ yêu cầu ≥ 12 ký tự
python -m soc.start                                # bật ES + Kibana + web: http://127.0.0.1:8000 (Kibana :5601)
python -m soc.api.smoke_test                       # kiểm thử đăng nhập, quyền, CSRF, khoá

```

### Demo vận hành từng ngày + vòng phản hồi IOC (`replay.py`)
Làm ngay trên web: đăng nhập `lead1` → menu **Demo replay**, mỗi bộ dữ liệu có Reset / Tiếp theo /
Khôi phục (LANL: 1 ngày/lần, ~1,5 phút; CERT: 7 ngày/lần, ~15 giây/ngày).
Hoặc bằng lệnh:
```powershell
python -m soc.replay status
python -m soc.replay reset          # LANL trên ES về trước ngày 20 (giai đoạn test)
python -m soc.replay next --days 2  # SOC xử lý ngày 20, 21
# trên web: mở incident của U66@DOM1 → playbook tái dựng chuỗi tấn công, chỉ ra máy bàn đạp C17693
#           → lead duyệt "Chặn máy nguồn (thêm IOC)" → C17693 vào danh sách IOC
python -m soc.replay next --days 8  # ngày 22–29: luật Sigma IOC bắt mọi đăng nhập từ C17693
python -m soc.elastic.ingest --dataset lanl   # khôi phục trạng thái đầy đủ sau demo

python -m soc.replay reset --dataset live          # LANL NGÀY MỚI 30–57 (tải thêm, không nhãn red team)
python -m soc.replay next --dataset live --days 3  # chạy như log thật mới tới
python -m soc.live_report                          # độ ổn định trên ngày mới → reports/live_days.json

python -m soc.replay reset --dataset cert          # CERT về trước 01/09/2010
python -m soc.replay next --dataset cert --days 7 # 7 ngày tiếp theo
python -m soc.elastic.ingest --dataset cert       # khôi phục
```
Replay ghi vào file riêng (`replay_*.parquet`), không làm nhiễm kết quả đánh giá offline. CERT: luật
không phụ thuộc IOC và đã tính nhân quả → replay chỉ cắt cảnh báo / rủi ro tới ngày đang xử lý.
Khôi phục đầy đủ thì đồng hồ demo của bộ đó bị xoá (phải reset trước khi chạy tiếp).

## Thiết kế từng lớp

**Lớp 1 – luật Sigma** (`rules/sigma/*.yml`). Engine hỗ trợ selection/condition/modifier chuẩn
Sigma, luật tương quan Sigma v2 (`event_count`, `value_count`, `temporal`) và placeholder
`%ioc_hosts%` (`|expand`). Sự kiện được làm giàu như pipeline ingest của SIEM (loại tài khoản,
nguồn ≠ đích, ngoài giờ, độ phổ biến domain tính nhân quả, danh mục URL). Luật dựa trên kiến thức
tấn công công khai (Pass-the-Hash, password spraying, rò dữ liệu USB/web, cài keylogger, nhân viên
sắp nghỉ), **không** soi sự kiện red team / insider. Ngưỡng chọn chỉ theo lưu lượng cảnh báo ở
train (≤ 3 cảnh báo/ngày/luật).

**Lớp 4 – rủi ro.** `R(ngày) = R(hôm trước) × decay + Σ điểm phát hiện`. Điểm luật = trọng số
theo level × **hệ số độ ồn** (luật bắn nhiều ở train bị giảm, luật hiếm được tăng – không dùng
nhãn); điểm ML theo `alert_score`. Analyst xem top-K thực thể/ngày (LANL 25, CERT 5) → incident.
Tham số chọn trên val. Mức độ incident theo thứ hạng rủi ro trong bộ dữ liệu (10% critical,
30% high).

**Lớp 5 – SOAR: chuỗi tấn công + playbook** (thay AI Agent LLM – mô hình cục bộ chỉ đúng 9/20,
không kiểm chứng được). Mỗi incident tự chạy 1 playbook tất định:
- **PB-LANL-HOST / PB-LANL-USER** – tái dựng chuỗi lateral movement trên đồ thị xác thực
  (`graph/attack_graph.py`): từ máy bàn đạp (hoặc máy nguồn không quen của tài khoản) lấy mọi đăng
  nhập từ xa không quen → tài khoản bị chiếm, máy bị chạm tới, máy bàn đạp chính, bán kính ảnh hưởng;
  mở rộng sang máy khác khi ≥ 3 tài khoản bị chiếm cùng xuất hiện (≥ 80% tài khoản lạ của máy đó).
  **Độ tin cậy** của chuỗi = percentile số máy bị chạm tới so với các chuỗi dựng ở train (không
  nhãn); chỉ đề xuất chặn máy khi ≥ 0,8 (trung bình) và ≥ 3 tài khoản, còn lại "theo dõi".
  Chỉ dùng dữ liệu tới ngày incident. Tham số chọn trên val.
- **PB-CERT** – dòng thời gian nội gián theo pha Truy cập → Chuẩn bị → Cài đặt → Đánh cắp
  (`graph/insider_timeline.py`), đánh dấu bước MỚI so với 30 ngày trước của chính nhân viên.
- Hành động đề xuất (chặn máy nguồn → IOC, khoá + cấp lại mật khẩu, theo dõi máy bị chạm, chặn USB,
  chặn gửi dữ liệu ra ngoài, thu hẹp quyền) gắn **MITRE D3FEND**; mã D3FEND được kiểm tra có trong
  ánh xạ ATT&CK → D3FEND chính thức. Lead duyệt; thực thi mô phỏng, riêng chặn máy → IOC thật.

## Giao diện web (tiếng Anh, theme tối mặc định + sáng)

Thiết kế theo hướng "kể chuyện" thay vì bảng: mỗi incident có **một câu tóm tắt tự sinh** (template
tất định từ chuỗi tấn công / dòng thời gian – `api/narrative.py`, không dùng LLM).
- **Overview**: số incident mở / critical / chưa kết luận, danh sách critical, phát hiện theo ngày (luật
  vs ML), thực thể rủi ro nhất, các giai đoạn ATT&CK đã thấy, "How it works" 4 bước.
- **Incidents**: hàng đợi dạng danh sách câu, lọc theo trạng thái / mức / bộ dữ liệu.
- **Incident**: câu chuyện tấn công (LANL: đồ thị máy tấn công → tài khoản → máy bị chạm; CERT: 4 pha
  Access → Preparation → Installation → Exfiltration, bước MỚI nổi bật), "Why it was flagged" (lý do ML
  bằng lời), bằng chứng; cột phải: Response plan (playbook + D3FEND, Approve/Reject) và verdict.
- **Profile** (`/entity/...`): "Normal vs ngày bất thường nhất" – so từng chỉ số với trung vị 30 ngày
  trước của chính người dùng đó (lưu sẵn trong cảnh báo ML), lịch sử phát hiện, các incident.

## Bảo mật của chính hệ thống

| Thành phần | Biện pháp |
|---|---|
| Elasticsearch | xpack.security bật, HTTPS (CA tự sinh), chỉ nghe 127.0.0.1, mật khẩu ngẫu nhiên trong `.env` |
| Kibana | nối ES bằng service account token (không dùng superuser), khoá mã hoá saved objects |
| Web app → ES | user `soc_app`: chỉ đọc cảnh báo/sự kiện, ghi incident/IOC, **chỉ thêm** vào nhật ký kiểm toán |
| Pipeline → ES | user `soc_pipeline`: ghi các index phát hiện, không quản trị cluster, kiểm toán chỉ thêm; superuser `elastic` chỉ dùng khi cài đặt. Web chạy replay thành tiến trình riêng, 1 tác vụ/lúc, chỉ lead |
| Đăng nhập | PBKDF2-SHA256 310k vòng + salt; so sánh hằng thời gian; khoá 15 phút sau 5 lần sai theo (IP, user); đổi phiên khi đăng nhập (chống fixation) |
| Phân quyền | analyst: xem, kết luận; lead: + duyệt hành động playbook, quản lý IOC, xem kiểm toán, chế độ đánh giá |
| Web | CSRF token mọi POST; CSP `default-src 'self'` (không script/style inline, không CDN); X-Frame-Options DENY; nosniff; Referrer-Policy; cookie HttpOnly + SameSite=Strict |
| Playbook | tất định, chỉ đọc dữ liệu đã có; không tự thực thi – mọi hành động cần lead duyệt; không thấy nhãn đánh giá |
| Kiểm toán | mọi đăng nhập, kết luận, duyệt hành động, IOC, demo replay → `soc-audit` |
| Bí mật | `.env` (không commit); dữ liệu, mô hình, trạng thái ngoài repo |

`python -m soc.api.smoke_test`: 17/17 kiểm thử đạt (thử khoá trên tài khoản tạm, tự xoá) (chuyển hướng khi chưa đăng nhập, header bảo
mật, chặn POST thiếu CSRF, analyst bị chặn trang kiểm toán + chế độ đánh giá với mã 403, khoá sau
5 lần sai, khoá chỉ áp cho tài khoản bị dò).

## Kết quả (giai đoạn TEST, chưa từng dùng khi thiết kế/chọn)

### Lớp 1 – luật Sigma (`reports/rules_eval_all.csv`)

| Luật | Cảnh báo/ngày | Precision | Bắt được |
|---|---|---|---|
| CERT: USB ngoài giờ + web cực hiếm cùng ngày | 0.03 | **1.00** | 7/52 insider (val 11/24) |
| CERT: web cực hiếm + chép .exe ra USB | 0.02 | **1.00** | 5/52 (val 3/24) |
| CERT: tìm việc + chép file ra USB | 29.2 | 0.035 | 27/52 – ồn |
| CERT – mọi luật | 32.4 | 0.034 | **35/52** |
| LANL: Pass-the-Hash (NTLM tới ≥ 10 máy/giờ) | 0.9 | 0.00 | 0/26 (val 7/97, precision 0.46) |
| LANL – mọi luật | 25.6 | 0.004 | **1/26** |

Luật bắt rất chính xác các mẫu insider đã biết; với LANL giai đoạn cuối (kẻ tấn công dùng lại
tài khoản đã chiếm, 1–2 đăng nhập/ngày) gần như bất lực. Luật brute force ồn (28 cảnh báo/ngày ở
val dù chỉ 2/ngày ở train) và không bắt red team nào (red team không dò mật khẩu).

### Lớp 4 – kết hợp (`reports/risk_eval.csv`, ngân sách cố định)

| Test | Chỉ luật | Chỉ ML | Luật + ML |
|---|---|---|---|
| CERT (5 incident/ngày, 52 insider) | 12 | 33 | **35** |
| LANL (25 incident/ngày, 26 tài khoản) – 1 hàng đợi | 1 | 4 | 4 |
| LANL – 2 hàng đợi: 20 tài khoản + 5 máy bàn đạp (incident máy liệt kê mọi tài khoản, máy ≤ 50) | – | – | 22 (val 96/97) |
| LANL – **+ theo dõi máy đã bị nghi trong 7 ngày** (~39 incident/ngày) | – | – | **26** (val 96/97) |

- Không có hệ số độ ồn, "luật + ML" trên CERT chỉ đạt 16/52 (luật ồn chiếm hết ngân sách).
- LANL: ML mức máy (`ml/src/lanl_hosts.py` – nhiều tài khoản đăng nhập NTLM từ một máy mà với
  họ là lạ) bắt máy bàn đạp C17693 của kẻ tấn công; điểm percentile của ML bị "kẹt" ở 1.0 khi dữ
  liệu trôi nên tách thành hàng đợi máy riêng xếp theo mức bất ngờ gốc. Thiết kế **sau khi**
  chẩn đoán test → báo cáo tách riêng; trên val (đợt tấn công đầu) cũng bắt 93/97 tài khoản.
- Mức độ incident xếp hạng riêng cho incident tài khoản và incident máy (thang điểm khác nhau).

### Lớp 5 – chuỗi tấn công (`reports/attack_graph_eval.json`, `reports/insider_timeline_eval.json`)

LANL – hạt giống = incident máy trong hàng đợi (không dùng nhãn); chấm trên các hạt giống là máy
tấn công thật (C17693), so với red team trong cửa sổ 7 ngày:

| | Val (ngày 8–19) | Test (ngày 20–29) |
|---|---|---|
| Tài khoản bị chiếm tìm được (recall) | 98.7% | **98.8%** |
| Tỉ lệ tài khoản trong chuỗi là red team (precision) | 42.5% | 53.0% |
| Máy bị chạm tới tìm được | 99.6% | 92.9% |
| Số tài khoản trong chuỗi (trung vị) – hạt giống thật / lành tính | 190 / 26 | 45 / 20 |

- Precision ~50% là cận dưới: nhãn red team của LANL chỉ đánh dấu một phần sự kiện; mọi tài khoản
  đăng nhập từ C17693 đều là cặp (tài khoản, máy) không quen (không ai dùng máy này ≥ 8 ngày).
- Máy tấn công phụ C19932 (chỉ 1 tài khoản bị chiếm) không tìm được qua mở rộng – cần ≥ 3 tài khoản
  chung; nới ngưỡng trên val kéo theo hàng trăm máy riêng của nạn nhân.
- Incident tài khoản U66, U737 (test) tự lần ra máy bàn đạp C17693.
- Ngưỡng độ tin cậy 0,8: đề xuất chặn ở hạt giống máy tấn công val 5/5,
  test 5/5; hạt giống lành tính val 58/193,
  test 37/181. Val chỉ có 1 máy tấn công nên mọi ngưỡng 0,8–0,95
  đều 5/5 – chọn 0,8 (ưu tiên không bỏ sót; ở test 0,9 sẽ sót 1, 0,95 sót cả 5). Mức incident:
  incident lành tính có đề xuất chặn giảm 54/77 → 22/77; 4 incident liên quan C17693 vẫn được đề xuất.

CERT – incident insider thật có bước đánh cắp MỚI (USB / email ra ngoài / chép .exe) ở
**59%**, incident lành tính chỉ 9.5%
(39/387 incident là insider).
