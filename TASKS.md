# Checklist công việc

## Dữ liệu & ML (`ml/`)
- [x] Tải LANL (ngày 0–29, đủ 749 sự kiện red team) và CERT r4.2; kiểm tra chất lượng dữ liệu
- [x] Feature theo user × ngày (LANL: xác thực, mới lạ, cạnh mới, fan-in, độ hiếm tần suất; CERT: logon/USB/file/email/web, độ hiếm domain, cửa sổ 7/30 ngày)
- [x] Baseline thống kê (self + peer z-score)
- [x] ML không giám sát: ECOD, Isolation Forest, Autoencoder; chống đầu độc baseline (cách ly)
- [x] Bộ phân loại người / máy (phân biệt loại tài khoản; KHÔNG phát hiện được tài khoản bị chiếm)
- [x] Đánh giá train/val/test theo thời gian, test chưa từng nhìn; sửa rò nhãn CERT
- [x] MITRE ATT&CK cho cảnh báo ML

## Nền tảng SOC (`soc/`)
- [x] Elastic Stack 9.5.5 bật bảo mật (HTTPS, user quyền tối thiểu, token Kibana)
- [x] Lớp 1: engine + luật Sigma (tương quan v2, IOC placeholder), ngưỡng không nhãn, đánh giá
- [x] Lớp 4: điểm rủi ro theo thực thể (hệ số độ ồn luật), incident, mức độ theo thứ hạng
- [x] Nạp cảnh báo / incident / sự kiện vào Elasticsearch
- [x] ~~Lớp 5: AI agent LLM~~ – đã thử (Qwen3 4B cục bộ đúng 9/20, kém mốc 14/20) → bỏ (đã xoá code + Ollama)
- [x] Lớp 5: tái dựng chuỗi tấn công LANL (đồ thị xác thực) + dòng thời gian nội gián CERT, có chấm điểm
- [x] Lớp 5: playbook SOAR tất định, đề xuất ứng phó gắn MITRE D3FEND (ánh xạ chính thức)
- [x] Web app SOC: dashboard, hàng đợi incident, MITRE, bằng chứng, kết luận, duyệt hành động, IOC, kiểm toán
- [x] Bảo mật web app + kiểm thử (`soc.api.smoke_test` 17/17)
- [x] Demo replay từng ngày cho cả LANL và CERT (workflow B7–B15) + vòng phản hồi IOC (`soc.replay`)
- [x] Độ tin cậy chuỗi tấn công (không nhãn) → giảm đề xuất chặn máy ở incident lành tính 54/77 → 22/77
- [ ] Tập demo end-to-end trên web (duyệt IOC bằng tay) + quay video

## Báo cáo
- [ ] Viết `report/` (chương 1–7) từ kết quả trong `ml/README.md` và `soc/README.md`
- [ ] Slide + tập bảo vệ
