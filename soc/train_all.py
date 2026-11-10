"""Train lại TOÀN BỘ mô hình theo cấu hình tốt nhất (chọn trên validation), chạy tuần tự, rồi gom
kết quả cuối vào soc/reports/final_results.json.

  LANL : ml/src/run_pipeline.py  (ECOD + IF di chuyển ngang, cách ly, fan-in, độ hiếm – mức tài khoản)
         ml/src/lanl_hosts.py    (phát hiện máy bàn đạp – mức máy)
  CERT : ml/src/cert_pipeline.py (Isolation Forest + Autoencoder, bagging 3 seed)
  SOC  : soc.risk.risk → soc.graph.edges → soc.risk.incidents (+ playbook SOAR, chuỗi tấn công)
         → đánh giá chuỗi tấn công / dòng thời gian → soc.elastic.ingest

Chạy (từ gốc repo):  python -m soc.train_all [--skip-ingest]
"""
import argparse
import json
import subprocess
import sys
import time

import pandas as pd

from soc.config import REPO_DIR, REPORTS_DIR, SOC_REPORTS, STATE_DIR

ML = REPO_DIR / "ml"
STEPS = [
    ("LANL – mức tài khoản", [sys.executable, "src/run_pipeline.py"], ML),
    ("LANL – mức máy", [sys.executable, "src/lanl_hosts.py"], ML),
    ("CERT – IF + AE", [sys.executable, "src/cert_pipeline.py"], ML),
    ("Rủi ro (luật + ML)", [sys.executable, "-m", "soc.risk.risk"], REPO_DIR),
    ("Đồ thị xác thực LANL", [sys.executable, "-m", "soc.graph.edges"], REPO_DIR),
    ("Incident + playbook", [sys.executable, "-m", "soc.risk.incidents"], REPO_DIR),
    ("Đánh giá chuỗi tấn công", [sys.executable, "-m", "soc.graph.attack_graph"], REPO_DIR),
    ("Đánh giá dòng thời gian", [sys.executable, "-m", "soc.graph.insider_timeline"], REPO_DIR),
    ("Chỉ số SOC (MTTD)", [sys.executable, "-m", "soc.metrics"], REPO_DIR),
]
INGEST = ("Nạp Elasticsearch", [sys.executable, "-m", "soc.elastic.ingest"], REPO_DIR)


def run(name, cmd, cwd):
    t0 = time.time()
    log = SOC_REPORTS / f"train_all_{name.split()[0].lower()}_{len(name)}.log"
    print(f"▶ {name} …", flush=True)
    env = {**__import__("os").environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}
    with open(log, "wb") as f:
        r = subprocess.run(cmd, cwd=cwd, stdout=f, stderr=subprocess.STDOUT, env=env)
    if r.returncode:
        raise SystemExit(f"✗ {name} lỗi (mã {r.returncode}) – xem {log}")
    print(f"  xong sau {time.time() - t0:,.0f}s", flush=True)


def collect() -> dict:
    lanl = json.loads((REPORTS_DIR / "lanl_summary.json").read_text(encoding="utf-8"))
    hosts = json.loads((REPORTS_DIR / "lanl_hosts.json").read_text(encoding="utf-8"))
    cert = json.loads((REPORTS_DIR / "cert_summary.json").read_text(encoding="utf-8"))
    cert_sel = json.loads((REPORTS_DIR / "cert_model_selection.json").read_text(encoding="utf-8"))
    cert_m = json.loads((REPORTS_DIR / "cert_test_metrics.json").read_text(encoding="utf-8"))
    risk = pd.read_csv(SOC_REPORTS / "risk_eval.csv")
    return {
        "lanl_user_level": {s: {k: lanl[s][k] for k in ("roc_auc", "pr_auc", "accounts_caught",
                                                          "accounts_total", "alerts_per_day")}
                            for s in ("val", "test")},
        "lanl_host_level": hosts,
        "cert_selected": cert_sel["selected"], "cert_val_pr_auc": cert_sel["validation_pr_auc"],
        "cert_test": {c: {k: round(v[k], 4) for k in ("roc_auc", "pr_auc", "precision@100")}
                      for c, v in cert_m.items()},
        "cert_user_level": cert["user_level"],
        "risk": risk.to_dict("records"),
        "attack_chain_lanl": {s: {k: v for k, v in g.items() if k != "attacker_seed_detail"}
                              for s, g in json.loads((SOC_REPORTS / "attack_graph_eval.json")
                                                     .read_text(encoding="utf-8")).items()},
        "insider_timeline_cert": json.loads((SOC_REPORTS / "insider_timeline_eval.json")
                                            .read_text(encoding="utf-8")),
        "soc_metrics": json.loads((SOC_REPORTS / "soc_metrics.json").read_text(encoding="utf-8")),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-ingest", action="store_true")
    a = ap.parse_args()
    # thang độ tin cậy chuỗi tấn công dựng từ hàng đợi máy ở train → tính lại khi train lại
    (STATE_DIR / "graph" / "chain_size_train.json").unlink(missing_ok=True)
    for name, cmd, cwd in STEPS + ([] if a.skip_ingest else [INGEST]):
        run(name, cmd, cwd)
    res = collect()
    (SOC_REPORTS / "final_results.json").write_text(json.dumps(res, indent=2, ensure_ascii=False),
                                                     encoding="utf-8")
    print("→ soc/reports/final_results.json")


if __name__ == "__main__":
    main()
