"""Cấu hình pytest: chạy từ gốc repo, thêm repo + ml/src vào sys.path (như `python -m soc...`)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT, ROOT / "ml" / "src"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
