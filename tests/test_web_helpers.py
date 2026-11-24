"""Câu chữ trên web (tất định), biểu đồ nhỏ, bảo mật đăng nhập."""
import pytest

from soc.api import narrative
from soc.api.security import MAX_FAILS, LoginThrottle, hash_password, verify_password


def test_reason_text_prefixes():
    assert narrative.reason_text("usb_offhours") == "unusual after-hours USB connections"
    assert "rising compared with" in narrative.reason_text("trend_file_n")
    assert "last 30 days" in narrative.reason_text("w30_file_exe")


@pytest.mark.parametrize("m, s", [(None, "—"), (12.4, "12 min"), (90, "1.5 h"), (4320, "3.0 days")])
def test_fmt_minutes(m, s):
    assert narrative.fmt_minutes(m) == s


def test_headline_uses_attack_chain():
    inc = {"dataset": "lanl", "entity": "host:C17693", "entity_type": "host", "n_alerts": 1,
           "attack_chain": {"compromised_accounts": ["a", "b", "c"], "touched_hosts": ["x"] * 9,
                            "timeline": [{"auth": "NTLM"}, {"auth": "NTLM"}]}}
    h = narrative.headline(inc)
    assert "C17693" in h and "3 accounts" in h and "9 other hosts" in h and "Pass-the-Hash" in h


def test_headline_counts_merged_hits():
    inc = {"dataset": "lanl", "entity": "U1@DOM1", "entity_type": "user", "n_alerts": 1,
           "n_hits": 36, "attack_chain": {}}
    assert "36 detections" in narrative.headline(inc)


def test_password_hash_roundtrip_and_salt():
    a, b = hash_password("correct horse"), hash_password("correct horse")
    assert a != b                                   # salt ngẫu nhiên
    assert verify_password("correct horse", a) and not verify_password("wrong", a)


def test_login_throttle_locks_only_that_account():
    t = LoginThrottle()
    for _ in range(MAX_FAILS):
        t.fail("1.2.3.4", "khoa")
    assert t.locked("1.2.3.4", "khoa")
    assert not t.locked("1.2.3.4", "hieu")
    t.reset("1.2.3.4", "khoa")
    assert not t.locked("1.2.3.4", "khoa")


def test_sparkline_and_heat_rows():
    from soc.api.main import heat_rows, mix, sparkline
    s = sparkline([0, 5, 10])
    assert s["n"] == 3 and s["line"].startswith("0.0,")
    assert mix([1, 1, 2]) == [25, 25, 50]
    h = heat_rows({"cols": ["d1", "d2"], "cells": {"Exfiltration": {"d1": 1000}, "Discovery": {"d2": 1}}})
    assert [r["tactic"] for r in h["rows"]] == ["Discovery", "Exfiltration"]   # theo thứ tự ATT&CK
    levels = {r["tactic"]: [c["lvl"] for c in r["cells"]] for r in h["rows"]}
    assert levels["Exfiltration"] == [5, 0] and levels["Discovery"][1] >= 1     # thang log
