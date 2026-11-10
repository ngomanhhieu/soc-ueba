# SOC / UEBA – Hệ thống giám sát & phân tích hành vi người dùng

Phát hiện hành vi bất thường của người dùng (tài khoản bị chiếm, di chuyển ngang, insider threat)
trên 2 bộ dữ liệu SOC chuẩn, theo kiến trúc 5 lớp như một SOC thật:

```
log LANL (xác thực AD) + CERT r4.2 (insider) ──▶ Elastic Stack (Elasticsearch + Kibana, bật bảo mật)
     │
     ├─ Lớp 1  Luật Sigma (+ tương quan Sigma v2), gắn MITRE ATT&CK          soc/rules
     ├─ Lớp 2  Baseline thống kê UEBA (self / peer z-score)                  ml/src/statistical.py
     ├─ Lớp 3  ML không giám sát: ECOD, Isolation Forest, Autoencoder,       ml/src
     │         độ hiếm có tần suất, chống đầu độc baseline
     ├─ Lớp 4  Tương quan + điểm rủi ro theo thực thể → incident             soc/risk
     └─ Lớp 5  SOAR: tái dựng chuỗi tấn công (đồ thị xác thực / dòng thời     soc/graph
               gian nội gián) + playbook đề xuất ứng phó gắn MITRE D3FEND,     soc/playbooks
               con người duyệt
                         │
             Web app SOC (FastAPI): hàng đợi incident, MITRE, bằng chứng,     soc/api
             duyệt hành động, IOC → quay lại Lớp 1 (vòng phản hồi)
```

| Thư mục | Nội dung |
|---|---|
| `ml/` | dữ liệu, feature, mô hình, thử nghiệm, đánh giá – xem `ml/README.md` |
| `soc/` | nền tảng: Elastic, luật Sigma, risk, chuỗi tấn công + playbook, web app – xem `soc/README.md` |
| `schema/` | hợp đồng dữ liệu cảnh báo (`alert.schema.json`) |
| `report/` | báo cáo đồ án |

## Chạy nhanh (Windows, không cần Docker/admin)

```powershell
python -m venv ml\.venv ; ml\.venv\Scripts\activate
pip install -r requirements.txt            # torch CPU: xem ml/README.md
copy .env.example .env                     # giá trị do script tự sinh

# 1. dữ liệu + ML  (chi tiết: ml/README.md)
python ml/src/download_data.py lanl --email <email> --lanl-gb 4.4 ; python ml/src/download_data.py cert
python ml/src/lanl_load_auth.py --start-day 0 --end-day 29 ; python ml/src/features.py
python ml/src/run_pipeline.py ; python ml/src/cert_http_domains.py ; python ml/src/cert_features.py ; python ml/src/cert_pipeline.py

# 2. nền tảng SOC  (chi tiết: soc/README.md)
python soc/elastic/install_elastic.py      # Elasticsearch + Kibana 9.5.5 → F:\soc-ueba-data\elastic
python -m soc.elastic.elastic_ctl setup    # cấu hình bảo mật, bật ES + Kibana
python -m soc.elastic.indices              # index + user quyền tối thiểu
python -m soc.elastic.kibana_setup         # data view Kibana
python -m soc.mitre.build_attack ; python -m soc.mitre.build_d3fend   # MITRE ATT&CK + D3FEND chính thức
python -m soc.rules.run_rules tune ; python -m soc.rules.run_rules run
python -m soc.risk.risk ; python -m soc.graph.edges ; python -m soc.risk.incidents ; python -m soc.elastic.ingest
python -m soc.api.users demo ; python -m soc.start      # ES + Kibana + web → http://127.0.0.1:8000
```

Dữ liệu gốc, mô hình, Elastic, trạng thái chạy nằm ngoài repo (`SOC_DATA_DIR`, mặc định
`F:/soc-ueba-data`). Bí mật nằm trong `.env` (không commit).
