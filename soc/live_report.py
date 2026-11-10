"""Báo cáo ngày MỚI (LANL ngày 30–57, tải thêm sau khi đã train/thiết kế xong): không có nhãn red
team nên không đo "bắt đúng bao nhiêu" – đo ĐỘ ỔN ĐỊNH khi hệ thống gặp dữ liệu chưa từng thấy:
  * lưu lượng: cảnh báo luật / ML mỗi ngày so với giai đoạn test (có bùng nổ báo động giả không?)
  * hàng đợi máy bàn đạp: máy nào lên top mỗi ngày, máy tấn công cũ C17693 còn xuất hiện không
  * hoạt động của các máy tấn công đã biết (C17693, C19932, C22409, C18025) trong ngày mới

Chạy:  python -m soc.live_report     → soc/reports/live_days.json
"""
import json

import pandas as pd

from soc.config import PROCESSED_DIR, SOC_REPORTS, STATE_DIR
from soc.graph.edges import load_edges
from soc.risk.risk import host_queue
from soc.rules.run_rules import LANL_LIVE, LANL_SPLITS

KNOWN_ATTACKERS = ["C17693", "C19932", "C22409", "C18025"]   # máy nguồn red team ở ngày 0–29


def main():
    sc = pd.read_parquet(PROCESSED_DIR / "lanl_scores.parquet", columns=["day", "alert_score"])
    ml = sc[sc["alert_score"] >= 0.99].groupby("day").size()
    rules = pd.read_parquet(STATE_DIR / "rule_alerts_lanl.parquet").groupby("day").size()
    hq = host_queue("lanl")
    live_days = [d for d in LANL_LIVE if d in set(sc["day"])]
    rows = []
    for d in list(LANL_SPLITS["test"]) + live_days:
        e = load_edges(d)
        att = e[e["src"].isin(KNOWN_ATTACKERS) & (e["src"] != e["dst"])]
        q = hq[(hq["day"] == d) & ~hq["watch"]].sort_values("surprise", ascending=False)
        rows.append({"day": d, "period": "test" if d < LANL_LIVE.start else "live",
                     "ml_alerts": int(ml.get(d, 0)), "rule_alerts": int(rules.get(d, 0)),
                     "host_queue": q["host"].astype(str).tolist(),
                     "known_attacker_remote_logons": int(att["n"].sum()),
                     "known_attacker_accounts": int(att["user"].nunique()),
                     "c17693_in_host_queue": "C17693" in set(q["host"].astype(str))})
    df = pd.DataFrame(rows)
    summ = {p: {"days": int(len(g)), "ml_alerts_per_day": round(float(g["ml_alerts"].mean()), 1),
                "rule_alerts_per_day": round(float(g["rule_alerts"].mean()), 1),
                "days_c17693_in_host_queue": int(g["c17693_in_host_queue"].sum()),
                "known_attacker_remote_logons": int(g["known_attacker_remote_logons"].sum())}
            for p, g in df.groupby("period")}
    out = {"summary": summ, "days": rows}
    (SOC_REPORTS / "live_days.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps(summ, indent=1))
    print(df[["day", "period", "ml_alerts", "rule_alerts", "known_attacker_remote_logons",
              "c17693_in_host_queue"]].to_string(index=False))


if __name__ == "__main__":
    main()
