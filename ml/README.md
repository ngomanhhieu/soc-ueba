# ml/ – Người A (Data & ML)

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```
- `data/raw/`: file tải về (không commit). LANL: `auth.txt.gz`, `redteam.txt.gz`.
- `data/processed/`: parquet đã lọc (không commit).
- `src/`: code tái sử dụng. `notebooks/`: thử nghiệm. `reports/`: biểu đồ, bảng kết quả.

## Thứ tự làm với LANL
1. `src/lanl_explore_redteam.py` – xem red team nằm ở ngày nào
2. `src/lanl_load_auth.py` – đọc auth.txt theo chunk, lọc khoảng ngày
3. `src/features.py` – feature theo user × giờ/ngày
4. `src/statistical.py`, `src/models.py` – baseline và ML
5. `src/evaluate.py` – metric
6. `src/export_alerts.py` – xuất `alerts.json` theo `../schema/alert.schema.json`
