# SOC / UEBA – Hệ thống giám sát & phân tích hành vi người dùng

Đồ án nhóm 2 người. Chi tiết kế hoạch: `docs/Ke_hoach_SOC_UEBA.docx`. Checklist: `TASKS.md`.

## Cấu trúc
| Thư mục | Chủ sở hữu | Nội dung |
|---|---|---|
| `ml/` | Người A (Data & ML) | dataset LANL/CERT, feature, mô hình, đánh giá, xuất alert |
| `platform/` | Người B (Platform, Agent, Web) | Wazuh/Elastic, rule Sigma, AI Agent, API, dashboard |
| `schema/` | Chung | hợp đồng dữ liệu alert (đổi phải báo người kia) |
| `docs/` | Chung | kế hoạch, ghi chú |
| `report/` | Chung | báo cáo, slide |

## Quy tắc Git
- Nhánh: `main` (ổn định), `feat/ml-*` (A), `feat/platform-*` (B).
- Merge vào `main` qua Pull Request, người kia review.
- Không commit dữ liệu thô, model, `.env` (đã có trong `.gitignore`).

## Chạy nhanh
```bash
cp .env.example .env
docker compose up -d      # B: dựng Elastic/Kibana
```
