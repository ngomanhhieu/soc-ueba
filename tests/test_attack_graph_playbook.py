"""Tái dựng chuỗi tấn công trên đồ thị xác thực + playbook SOAR / D3FEND (đồ thị nhỏ tự dựng)."""
import pandas as pd
import pytest

import soc.graph.attack_graph as ag
from soc.playbooks.soar import action, d3, pb_lanl


def edge(user, src, dst, day, auth="NTLM", t=0):
    return {"user": user, "src": src, "dst": dst, "auth": auth, "t0": day * 86400 + t,
            "t1": day * 86400 + t, "n": 1, "rt": False, "day": day}


@pytest.fixture
def graph(monkeypatch):
    """Máy A: 3 tài khoản lần đầu đăng nhập từ đó (máy bàn đạp). Máy B: u9 dùng hằng ngày (quen)."""
    rows = [edge(u, "A", d, 20, t=i) for i, (u, d) in enumerate(
        [("u1", "D1"), ("u2", "D2"), ("u3", "D3"), ("u1", "D4")])]
    rows += [edge("u9", "B", "D9", day, auth="Kerberos") for day in range(1, 21)]   # 13 ngày trước cửa sổ
    e = pd.DataFrame(rows)
    first = e.groupby(["user", "src"])["day"].transform("min")
    novel = e[e["day"] - first < ag.WINDOW].assign(first_day=first)
    hab = e[["user", "dst", "day"]].drop_duplicates()
    monkeypatch.setattr(ag, "novel_edges", lambda: novel)
    monkeypatch.setattr(ag, "all_edges", lambda: e)
    monkeypatch.setattr(ag, "habitual", lambda: hab)
    monkeypatch.setattr(ag, "confidence", lambda n: (0.95, "high"))
    return e


def test_reconstruct_from_jump_host(graph):
    g = ag.reconstruct("host:A", 20)
    assert g["main_host"] == "A"
    assert g["compromised_accounts"] == ["u1", "u2", "u3"]
    assert g["touched_hosts"] == ["D1", "D2", "D3", "D4"]
    assert set(g["mitre_ids"]) >= {"T1550.002", "T1078"}       # NTLM từ máy lạ → Pass-the-Hash


def test_habitual_pairs_are_not_in_chain(graph):
    g = ag.reconstruct("host:B", 20)
    assert g["compromised_accounts"] == []                      # u9 dùng máy B ≥ 10 ngày → quen


def test_account_seed_leads_to_jump_host(graph):
    g = ag.reconstruct("u2", 20, 20)
    assert g["seed"] == ["A"] and len(g["compromised_accounts"]) == 3


def chain(n_acc, level):
    return {"seed": ["A"], "expansion_rounds": [[]], "attacker_hosts": ["A"], "main_host": "A",
            "compromised_accounts": [f"u{i}" for i in range(n_acc)], "touched_hosts": ["D1"],
            "n_edges": n_acc, "confidence": 0.95, "confidence_level": level, "blast_radius_hosts": 7}


def test_playbook_blocks_only_with_enough_evidence():
    inc = {"entity_type": "host", "entity": "host:A"}
    acts = [a["action"] for a in pb_lanl(inc, chain(3, "high"), set())["recommended_actions"]]
    assert acts == ["block_source_host", "reset_credentials", "monitor_closely"]
    for weak in (chain(2, "high"), chain(5, "low")):           # ít tài khoản / độ tin cậy thấp
        acts = [a["action"] for a in pb_lanl(inc, weak, set())["recommended_actions"]]
        assert acts == ["monitor_account"]


def test_playbook_skips_hosts_already_on_ioc_list():
    inc = {"entity_type": "host", "entity": "host:A"}
    acts = [a["action"] for a in pb_lanl(inc, chain(3, "high"), {"A"})["recommended_actions"]]
    assert "block_source_host" not in acts


def test_d3fend_mapping_is_validated():
    assert action("block_usb", "PC-1", "why")["d3fend"]["id"] == "D3-IOPR"
    with pytest.raises(ValueError):
        d3("T1052.001", "D3-AL")            # Account Locking không thuộc ánh xạ của T1052.001
