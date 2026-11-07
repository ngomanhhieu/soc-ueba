# Checklist công việc (đồ án 1 người)

## 1. Gom code về repo
- [x] Code ML (`ml/`) lên nhánh `feat/ml-pipeline`
- [x] Adapter log thật ECS → feature (`ml/src/ecs_to_auth.py`, `ml/src/score_real.py`)
- [ ] Cấu hình ELK từ Ubuntu server → `platform/wazuh_elastic/` (chạy `collect_elk_config.sh`)
- [ ] Merge `feat/ml-pipeline` vào `main` qua PR

## 2. Hạ tầng log (`platform/wazuh_elastic/`)
- [x] Elasticsearch + Kibana cài bằng apt trên Ubuntu server
- [x] Winlogbeat (Windows) + Filebeat (Linux), log đã parse vào ES
- [ ] Index template cho `alerts-ueba`
- [ ] `docker-compose.yml` tương đương bản apt (để dựng lại bằng 1 lệnh)

## 3. Data & ML (`ml/`)
- [x] A1 Đọc, lọc subset LANL (CERT: đưa vào hướng phát triển)
- [x] A2 Feature engineering theo user × giờ (32 feature)
- [x] A3 Baseline thống kê (z-score, IQR, peer group)
- [x] A4 Isolation Forest, Autoencoder, LOF; tinh chỉnh theo PR-AUC
- [x] A5 Bộ phân loại người thật / bot
- [x] A6 Đánh giá P/R/F1, ROC-AUC, PR-AUC, ablation
- [x] A7 Mapping MITRE ATT&CK
- [x] A8 Xuất alert đúng schema, đẩy vào ES
- [ ] Chạy trên LANL thật → số liệu báo cáo (`reports/metrics.md`, `roc_pr.png`, `ablation.csv`)
- [ ] Chạy `score_real.py` trên log thật (sau khi có ≥ 3 ngày baseline)

## 4. Demo tấn công trong lab
- [ ] Brute force SSH (hydra), RDP ngoài giờ, lateral movement NTLM (psexec)
- [ ] Ghi `attacks.csv` (user,start,end) → đo P/R/F1 trên log thật

## 5. Rule (`platform/rules/`)
- [ ] 4–6 rule Sigma-style + test case (ngưỡng đồng bộ `ml/src/rules.py`)

## 6. AI Agent (`platform/agent/`)
- [ ] LangChain + Claude API; input alert JSON
- [ ] Tool: lịch sử user trong ES, baseline user/peer, tra MITRE
- [ ] Output `agent_analysis` đúng schema, ghi ngược vào alert

## 7. API + Dashboard (`platform/api/`, `platform/dashboard/`)
- [ ] FastAPI: list/chi tiết alert, gọi agent, duyệt/từ chối hành động (có log)
- [ ] Kibana dashboard: severity, MITRE, top user, timeline

## 8. Đóng gói & báo cáo
- [ ] Script demo end-to-end
- [ ] Báo cáo 7 chương (`report/`), slide, tập bảo vệ
