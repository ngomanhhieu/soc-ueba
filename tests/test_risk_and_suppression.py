"""Điểm rủi ro theo thực thể (suy giảm) và gộp cảnh báo lặp lại (alert suppression)."""
import pandas as pd
import pytest

from soc.risk.incidents import suppress
from soc.risk.risk import combine, daily_risk


def test_daily_risk_decays_and_accumulates():
    det = pd.DataFrame({"entity": ["u1", "u1"], "day": [1, 3], "points": [100.0, 10.0]})
    r = daily_risk(det, [1, 2, 3, 4], decay=0.5).set_index("day")["risk"]
    assert r[1] == pytest.approx(100)
    assert r[2] == pytest.approx(50)
    assert r[3] == pytest.approx(35)          # 50 × 0,5 + 10
    assert r[4] == pytest.approx(17.5)


def test_daily_risk_drops_cold_entities():
    det = pd.DataFrame({"entity": ["u1"], "day": [1], "points": [2.0]})
    r = daily_risk(det, [1, 2, 3], decay=0.5)
    assert set(r["day"]) == {1, 2}            # ngày 3: 0,5 không > 0,5 → thực thể "nguội", bỏ khỏi bảng


def test_combine_ml_points_only_above_floor():
    rules = pd.DataFrame({"entity": ["u1"], "day": [1], "points": [20.0], "users": [["u1"]]})
    ml = pd.DataFrame({"entity": ["u2", "u3"], "day": [1, 1], "score": [0.995, 0.98],
                       "users": [["u2"], ["u3"]]})
    det = combine(rules, ml, "both", ml_weight=80, ml_floor=0.99).set_index("entity")["points"]
    assert det["u1"] == 20
    assert det["u2"] == pytest.approx(80 * 0.5, abs=1e-2)   # (0,995 − 0,99) / (1 − 0,99) = 0,5
    assert "u3" not in det                                   # dưới ngưỡng ML → không cộng điểm


def alert(ts, host="C1", sev="medium", n=10, gt=False, ctx=("C2",)):
    return {"alert_id": "x", "timestamp": ts, "rule_id": "r1", "entity": "U1@DOM1", "src_host": host,
            "day": 20, "severity": sev, "anomaly_score": 0.7, "ground_truth": gt,
            "features": {"value": n, "n_events": n, "window_start": ts, "window_end": ts,
                         "context": {"destination.host": list(ctx)}}}


def test_suppress_merges_same_rule_entity_host_day():
    out = suppress("lanl", [alert("2026-09-21T01:00:00Z", n=20),
                            alert("2026-09-21T03:00:00Z", sev="high", n=30, gt=True, ctx=("C3",)),
                            alert("2026-09-21T02:00:00Z")])
    assert len(out) == 1
    f = out[0]["features"]
    assert f["count"] == 3 and f["n_events"] == 60 and f["value"] == 30
    assert f["first_seen"] == "2026-09-21T01:00:00Z" and f["last_seen"] == "2026-09-21T03:00:00Z"
    assert out[0]["severity"] == "high" and out[0]["ground_truth"] is True
    assert f["context"]["destination.host"] == ["C2", "C3"]


def test_suppress_keeps_different_hosts_apart():
    out = suppress("lanl", [alert("2026-09-21T01:00:00Z", host="C1"),
                            alert("2026-09-21T01:00:00Z", host="C9")])
    assert len(out) == 2
    assert len({a["alert_id"] for a in out}) == 2              # ID ổn định, không trùng
