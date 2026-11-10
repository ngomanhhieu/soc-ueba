"""Cấu hình dùng chung cho package soc: đường dẫn, kết nối Elasticsearch, tên index.

Bí mật (mật khẩu Elastic, tài khoản web) đọc từ biến môi trường hoặc file .env ở gốc repo
(.env KHÔNG commit – xem .env.example).
"""
import os
import sys
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parents[1]
ML_SRC = REPO_DIR / "ml" / "src"
if str(ML_SRC) not in sys.path:
    sys.path.insert(0, str(ML_SRC))


def _load_dotenv(path: Path):
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv(REPO_DIR / ".env")

import config as ml_config  # noqa: E402  (ml/src/config.py – đường dẫn dữ liệu, console UTF-8)

DATA_DIR = ml_config.DATA_DIR
REPORTS_DIR = ml_config.REPORTS_DIR
PROCESSED_DIR = ml_config.PROCESSED_DIR
SCHEMA_PATH = ml_config.SCHEMA_PATH
SOC_REPORTS = REPO_DIR / "soc" / "reports"
SOC_REPORTS.mkdir(parents=True, exist_ok=True)
STATE_DIR = DATA_DIR / "soc_state"          # alert/incident/IOC sinh ra khi chạy (ngoài repo)
STATE_DIR.mkdir(parents=True, exist_ok=True)

# ---- Elastic Stack (cài bằng soc/elastic/install_elastic.py)
ELASTIC_VERSION = os.environ.get("ELASTIC_VERSION", "9.5.5")
ELASTIC_HOME = Path(os.environ.get("ELASTIC_HOME", DATA_DIR / "elastic"))
ES_URL = os.environ.get("ES_URL", "https://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASSWORD = os.environ.get("ELASTIC_PASSWORD", "")
ES_CA = ELASTIC_HOME / f"elasticsearch-{ELASTIC_VERSION}" / "config" / "certs" / "http_ca.crt"
KIBANA_URL = os.environ.get("KIBANA_URL", "http://localhost:5601")

INDEX = {
    "alerts": "soc-alerts",           # cảnh báo từ luật + ML (schema/alert.schema.json)
    "incidents": "soc-incidents",     # incident = gom cảnh báo theo thực thể (risk)
    "events_lanl": "soc-events-lanl",  # sự kiện xác thực (phục vụ điều tra)
    "events_cert": "soc-events-cert",
    "ioc": "soc-ioc",                 # IOC do analyst xác nhận
    "audit": "soc-audit",             # nhật ký kiểm toán (ai làm gì, agent gọi tool gì)
}


def es_client(admin: bool = False):
    """admin=True: superuser `elastic` – chỉ cho bước cài đặt (index, role, user).
    Mặc định: user `soc_pipeline` (ghi soc-*, không quản trị cluster) cho nạp dữ liệu / replay."""
    from elasticsearch import Elasticsearch
    pipeline_pw = os.environ.get("SOC_PIPELINE_ES_PASSWORD", "")
    if not admin and pipeline_pw:
        user, pw = "soc_pipeline", pipeline_pw
    else:
        user, pw = ES_USER, os.environ.get("ELASTIC_PASSWORD", ES_PASSWORD)
    if not pw:
        raise SystemExit("Thiếu mật khẩu Elastic trong .env – chạy python -m soc.elastic.elastic_ctl setup")
    return Elasticsearch(ES_URL, basic_auth=(user, pw), ca_certs=str(ES_CA), request_timeout=60)
