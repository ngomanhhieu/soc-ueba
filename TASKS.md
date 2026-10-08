# Checklist công việc

## Người A – Data & ML (`ml/`)
- [ ] A1 Tải, làm sạch, chọn subset LANL (rồi CERT)
- [ ] A2 Feature engineering theo user × giờ/ngày
- [ ] A3 Baseline thống kê (z-score, IQR, peer group)
- [ ] A4 Train Isolation Forest, Autoencoder; tinh chỉnh
- [ ] A5 Bộ phân loại người thật / bot
- [ ] A6 Đánh giá: Precision/Recall/F1, ROC-AUC, PR-AUC, ablation
- [ ] A7 Bảng mapping MITRE ATT&CK (`ml/src/mitre_mapping.json`)
- [ ] A8 Xuất `alerts.json` đúng schema, đẩy vào Elasticsearch

## Người B – Platform, Agent, Web (`platform/`)
- [ ] B1 Docker Compose Wazuh/Elastic Stack
- [ ] B2 Pipeline nạp log vào Elasticsearch, index mapping
- [ ] B3 Rule Sigma-style / Wazuh rule
- [ ] B4 AI Agent LangChain + tools + output JSON
- [ ] B5 API FastAPI
- [ ] B6 Dashboard (Kibana hoặc React)
- [ ] B7 Demo end-to-end

## Chung
- [ ] Chốt schema alert (tuần 1)
- [ ] Ghép nối end-to-end (tuần 4)
- [ ] Báo cáo + slide + tập bảo vệ (tuần 5)
