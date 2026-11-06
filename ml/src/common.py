"""Hằng số, đường dẫn và hàm I/O dùng chung cho pipeline ML (Người A)."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pandas as pd

ML_DIR = Path(__file__).resolve().parents[1]
RAW = ML_DIR / "data" / "raw"
PROC = ML_DIR / "data" / "processed"
MODELS = ML_DIR / "models"
REPORTS = ML_DIR / "reports"
SCHEMA = ML_DIR.parent / "schema" / "alert.schema.json"
MITRE = ML_DIR / "src" / "mitre_mapping.json"

for _d in (PROC, MODELS, REPORTS):
    _d.mkdir(parents=True, exist_ok=True)

AUTH_COLS = ["time", "src_user", "dst_user", "src_comp", "dst_comp",
             "auth_type", "logon_type", "auth_orient", "outcome"]
REDTEAM_COLS = ["time", "user", "src_comp", "dst_comp"]

# --- Nhóm feature (dùng cho ablation) -------------------------------------
FEATURE_GROUPS: dict[str, list[str]] = {
    "volume": ["n_events", "n_success", "n_fail", "fail_ratio"],
    "hosts": ["distinct_dst", "distinct_src", "distinct_dst_user",
              "new_src", "new_dst", "self_auth_ratio"],
    "auth_type": ["kerberos_ratio", "ntlm_ratio", "negotiate_ratio"],
    "logon_type": ["network_ratio", "interactive_ratio", "remote_interactive_ratio",
                   "service_ratio", "batch_ratio", "unlock_ratio"],
    "orientation": ["logon_ratio", "logoff_ratio", "tgs_ratio", "tgt_ratio"],
    "time": ["offhours_ratio", "hour_sin", "hour_cos"],
    "bot_like": ["interval_mean", "interval_std", "interval_cv", "peak_per_min",
                 "active_hours_day", "hour_entropy_day"],
}
ALL_FEATURES = [f for g in FEATURE_GROUPS.values() for f in g]
# feature dạng đếm -> log1p trước khi chuẩn hoá
COUNT_FEATURES = ["n_events", "n_success", "n_fail", "distinct_dst", "distinct_src",
                  "distinct_dst_user", "new_src", "new_dst", "interval_mean",
                  "interval_std", "peak_per_min"]
# feature cho bộ phân loại người thật / bot (không dùng logon_type để tránh rò nhãn)
BOT_FEATURES = ["interval_mean", "interval_std", "interval_cv", "peak_per_min",
                "active_hours_day", "hour_entropy_day", "n_events", "hour_sin", "hour_cos"]
KEY_COLS = ["user", "win"]


def save_df(df: pd.DataFrame, name: str) -> Path:
    """Lưu parquet nếu có pyarrow, không thì pickle (để chạy được ở mọi máy)."""
    try:
        import pyarrow  # noqa: F401
        p = PROC / f"{name}.parquet"
        df.to_parquet(p, index=False)
    except ImportError:
        p = PROC / f"{name}.pkl"
        df.to_pickle(p)
    return p


def load_df(name: str) -> pd.DataFrame:
    for ext, fn in ((".parquet", pd.read_parquet), (".pkl", pd.read_pickle)):
        p = PROC / f"{name}{ext}"
        if p.exists():
            return fn(p)
    raise FileNotFoundError(f"Không thấy {PROC / name}.parquet|.pkl – chạy bước trước đó chưa?")


def save_json(obj, path: Path):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def load_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def env(key: str, default: str | None = None) -> str | None:
    """Đọc biến môi trường, fallback sang ../.env."""
    if key in os.environ:
        return os.environ[key]
    envf = ML_DIR.parent / ".env"
    if envf.exists():
        for line in envf.read_text().splitlines():
            if line.strip().startswith(f"{key}="):
                return line.split("=", 1)[1].strip()
    return default
