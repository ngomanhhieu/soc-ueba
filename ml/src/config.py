"""Đường dẫn và hằng số dùng chung cho toàn bộ pipeline ML.

Dataset gốc rất nặng nên để ngoài repo, trỏ bằng biến môi trường SOC_DATA_DIR
(mặc định F:/soc-ueba-data). Dữ liệu đã xử lý/feature, model, báo cáo nằm trong ml/.
"""
import os
import sys
from pathlib import Path

# Console Windows mặc định cp1252 → không in được tiếng Việt
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8")

ML_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = ML_DIR.parent

DATA_DIR = Path(os.environ.get("SOC_DATA_DIR", "F:/soc-ueba-data"))
LANL_RAW = DATA_DIR / "lanl"
LANL_AUTH_GZ = LANL_RAW / "auth.txt.gz"
LANL_REDTEAM_GZ = LANL_RAW / "redteam.txt.gz"
LANL_EVENTS_DIR = DATA_DIR / "lanl_events"      # parquet theo ngày (sự kiện thô đã lọc)
LANL_DAILY_DIR = DATA_DIR / "lanl_daily"        # tổng hợp theo ngày (features.py giai đoạn 1)
CERT_RAW = DATA_DIR / "cert"

PROCESSED_DIR = ML_DIR / "data" / "processed"   # feature table (nhỏ)
MODELS_DIR = ML_DIR / "models"
REPORTS_DIR = ML_DIR / "reports"
SCHEMA_PATH = REPO_DIR / "schema" / "alert.schema.json"
MITRE_PATH = ML_DIR / "src" / "mitre_mapping.json"

SECONDS_PER_DAY = 86400

AUTH_COLS = ["time", "src_user", "dst_user", "src_comp", "dst_comp",
             "auth_type", "logon_type", "orientation", "result"]
REDTEAM_COLS = ["time", "user", "src_comp", "dst_comp"]

# Tài khoản dịch vụ/hệ thống (không phải người) – dùng làm nhãn yếu cho bộ phân loại người/máy
SYSTEM_ACCOUNT_PREFIXES = ("SYSTEM@", "LOCAL SERVICE@", "NETWORK SERVICE@", "ANONYMOUS LOGON@")

for _d in (PROCESSED_DIR, MODELS_DIR, REPORTS_DIR):
    _d.mkdir(parents=True, exist_ok=True)
