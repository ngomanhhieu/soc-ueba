"""Chỉ số vận hành SOC.

MTTD (mean time to detect) – đo trên TOÀN giai đoạn test, so với nhãn của dataset (chỉ để đánh
giá): với mỗi kẻ tấn công thật (LANL: tài khoản bị chiếm; CERT: nhân viên nội gián), lấy ngày bắt
đầu hoạt động độc hại trong test, rồi ngày đầu tiên (từ ngày đó trở đi) tài khoản nằm trong một
incident – là thực thể, hoặc trong danh sách tài khoản của incident máy bàn đạp.
Hệ thống xử lý theo ngày → độ trễ tính bằng ngày (0 = phát hiện ngay trong ngày bắt đầu).

MTTA / MTTR (thời gian analyst kết luận / lead duyệt ứng phó) đo theo giờ thật trên web:
soc.api.store.soc_ops().

Chạy:  python -m soc.metrics     → soc/reports/soc_metrics.json
"""
import json

import numpy as np
import pandas as pd

from soc.config import SOC_REPORTS, STATE_DIR
from soc.risk.risk import truth_and_splits


def detection_delays(ds: str) -> pd.DataFrame:
    truth, splits, _ = truth_and_splits(ds)
    test = set(splits["test"])
    start = {}
    for u, d in truth:
        if d in test:
            start[u] = min(start.get(u, d), d)
    incs = json.loads((STATE_DIR / f"incidents_{ds}.json").read_text(encoding="utf-8"))
    conv = (lambda x: x) if ds == "lanl" else pd.Timestamp
    spans = {}           # tài khoản → các khoảng [ngày đầu, ngày cuối] của incident chứa nó
    for i in incs:
        users = {i["entity"]} | set(i.get("users") or [])
        for u in users & start.keys():
            spans.setdefault(u, []).append((conv(i["day_first"]), conv(i["day_last"])))
    rows = []
    for u, s in start.items():
        later = [max(a, s) for a, b in spans.get(u, []) if b >= s]
        det = min(later) if later else None
        delay = None if det is None else (det - s if ds == "lanl" else (det - s).days)
        rows.append({"attacker": u, "start": s, "detected": det, "delay_days": delay})
    return pd.DataFrame(rows)


def summarize(df: pd.DataFrame) -> dict:
    hit = df.dropna(subset=["delay_days"])
    dly = hit["delay_days"].astype(float)
    return {"attackers": int(len(df)), "detected": int(len(hit)),
            "mttd_days": round(float(dly.mean()), 2) if len(hit) else None,
            "median_days": float(dly.median()) if len(hit) else None,
            "same_day": int((dly == 0).sum()), "within_1_day": int((dly <= 1).sum())}


def main():
    out = {}
    for ds in ("lanl", "cert"):
        df = detection_delays(ds)
        out[ds] = summarize(df)
        print(ds, out[ds])
    out["note"] = ("Delay from the first malicious day to the first incident detection, test "
                   "period, measured against dataset labels (daily processing: 0 = same day).")
    (SOC_REPORTS / "soc_metrics.json").write_text(json.dumps(out, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
