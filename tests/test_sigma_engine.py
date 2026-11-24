"""Engine Sigma: nạp luật, luật đơn, luật tương quan (event_count, value_count), placeholder IOC."""
import pandas as pd
import pytest

from soc.rules.run_rules import RULE_DIR
from soc.rules.sigma_engine import RuleSet, load_rules, parse_timespan

BRUTE = "Brute force – many failed logons to one account from one host"
SPRAY = "Password spraying – one host failing logons to many accounts"
IOC = "Activity from a host confirmed as attacker (IOC)"   # luật tương quan trên luật nền IOC


def auth(rows):
    """Sự kiện xác thực LANL tối thiểu (field ECS như soc.rules.datasets.lanl_day)."""
    base = {"user.kind": "human", "auth.type": "Kerberos", "logon.type": "Network",
            "event.action": "LogOn", "event.outcome": "Success", "network.remote": True,
            "destination.host": "C2"}
    return pd.DataFrame([{**base, **r} for r in rows])


def run(df, **kw):
    rs = RuleSet(load_rules(RULE_DIR), thresholds={}, **kw).for_logsource("lanl")
    al = rs.run({"auth": df})
    return set(al["rule_title"]) if len(al) else set()


def test_rule_inventory():
    rules = load_rules(RULE_DIR)
    assert len(rules) == 22
    assert sum(r.is_correlation for r in rules) == 11
    assert all(r.mitre for r in rules if r.is_correlation)      # mọi luật cảnh báo đều gắn ATT&CK


def test_parse_timespan():
    assert parse_timespan("10m") == 600
    assert parse_timespan("1h") == 3600


@pytest.mark.parametrize("n, fires", [(20, True), (19, False)])
def test_brute_force_threshold(n, fires):
    df = auth([{"@timestamp": 1000 + i, "user.name": "U1@DOM1", "source.host": "C1",
                "event.outcome": "Fail"} for i in range(n)])
    assert (BRUTE in run(df)) is fires


def test_brute_force_needs_same_window():
    # 20 lần thất bại nhưng rải trong 2 cửa sổ 10 phút → không đủ ngưỡng ở cửa sổ nào
    df = auth([{"@timestamp": (0 if i < 10 else 600) + i, "user.name": "U1@DOM1",
                "source.host": "C1", "event.outcome": "Fail"} for i in range(20)])
    assert BRUTE not in run(df)


@pytest.mark.parametrize("users, fires", [(5, True), (4, False)])
def test_password_spraying_counts_distinct_accounts(users, fires):
    df = auth([{"@timestamp": 1000 + i, "user.name": f"U{i % users}@DOM1", "source.host": "C9",
                "event.outcome": "Fail"} for i in range(12)])
    assert (SPRAY in run(df)) is fires


def test_machine_accounts_ignored():
    df = auth([{"@timestamp": 1000 + i, "user.name": "C1$@DOM1", "user.kind": "machine",
                "source.host": "C1", "event.outcome": "Fail"} for i in range(30)])
    assert BRUTE not in run(df)


def test_ioc_placeholder_feedback_loop():
    df = auth([{"@timestamp": 50, "user.name": "U66@DOM1", "source.host": "C17693"}])
    assert IOC in run(df, placeholders={"ioc_hosts": ["C17693"]})
    assert IOC not in run(df, placeholders={"ioc_hosts": []})
