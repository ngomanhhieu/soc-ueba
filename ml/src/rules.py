"""Rule-only baseline (Sigma-style) để so sánh với ML trong A6.

Đây là bản tối giản phía ML để đo "rule-only" và "kết hợp"; rule chính thức
(Sigma/Wazuh) do Người B viết trong platform/rules/. Giữ ngưỡng đồng bộ với B.
"""
from __future__ import annotations

import pandas as pd

# rule_id -> (điều kiện, trọng số, behavior trong mitre_mapping.json)
RULES = {
    "sigma_bruteforce_then_success": (lambda d: (d.n_fail >= 5) & (d.n_success > 0), 0.8, "brute_force"),
    "sigma_many_fails": (lambda d: d.n_fail >= 10, 0.6, "brute_force"),
    "sigma_many_hosts_short_time": (lambda d: d.distinct_dst >= 10, 0.7, "lateral_movement"),
    "sigma_new_dst_burst": (lambda d: d.new_dst >= 3, 0.6, "lateral_movement"),
    "sigma_ntlm_network_logon": (lambda d: (d.ntlm_ratio > 0.5) & (d.network_ratio > 0.5)
                                 & (d.n_events >= 3), 0.5, "alt_auth"),
    "sigma_login_offhours_new_src": (lambda d: (d.offhours_ratio > 0.5) & (d.new_src > 0), 0.5,
                                     "valid_accounts"),
}


def apply_rules(df: pd.DataFrame) -> pd.DataFrame:
    hits = pd.DataFrame({rid: cond(df) for rid, (cond, _, _) in RULES.items()}, index=df.index)
    w = pd.Series({rid: v[1] for rid, v in RULES.items()})
    weighted = hits.astype(float) * w
    out = pd.DataFrame(index=df.index)
    out["rule"] = weighted.max(axis=1)  # điểm rule = trọng số rule mạnh nhất đã kích hoạt
    out["rule_id"] = weighted.idxmax(axis=1).where(out["rule"] > 0)
    out["n_rules"] = hits.sum(axis=1)
    return out
