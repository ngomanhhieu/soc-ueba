"""Sinh dữ liệu GIẢ đúng định dạng LANL auth.txt / redteam.txt để chạy thử pipeline
khi chưa tải bộ thật (~7GB). KHÔNG dùng kết quả này trong báo cáo.

  python src/make_synthetic_lanl.py            # -> data/raw/synthetic/
"""
from __future__ import annotations

import argparse

import numpy as np
import pandas as pd

from common import AUTH_COLS, RAW


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--humans", type=int, default=200)
    ap.add_argument("--services", type=int, default=20)
    ap.add_argument("--machines", type=int, default=40)
    ap.add_argument("--attacked", type=int, default=10)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    rng = np.random.default_rng(a.seed)
    out = RAW / "synthetic"
    out.mkdir(parents=True, exist_ok=True)
    servers = [f"C{i}" for i in range(1, 60)]
    rows, red = [], []

    def ev(t, u, dst_u, src, dst, at, lt, ori, ok=True):
        rows.append((int(t), u, dst_u, src, dst, at, lt, ori, "Success" if ok else "Fail"))

    for h in range(a.humans):
        u = f"U{h + 1}@DOM1"
        home = f"C{1000 + h}"
        my_srv = list(rng.choice(servers, 4, replace=False))
        start_h, end_h = rng.integers(7, 10), rng.integers(16, 19)
        for d in range(a.days):
            if d % 7 in (5, 6) and rng.random() < 0.85:
                continue
            base = d * 86400
            ev(base + start_h * 3600 + rng.integers(0, 900), u, u, home, home, "Negotiate",
               "Interactive", "LogOn")
            for hr in range(start_h, end_h):
                for _ in range(rng.poisson(8)):
                    t = base + hr * 3600 + rng.integers(0, 3600)
                    dst = rng.choice(my_srv) if rng.random() < 0.97 else rng.choice(servers)
                    ok = rng.random() > 0.01
                    ev(t, u, u, home, dst, "Kerberos" if rng.random() < 0.9 else "NTLM", "Network",
                       "LogOn" if rng.random() < 0.7 else "TGS", ok)
                if rng.random() < 0.1:
                    ev(base + hr * 3600 + rng.integers(0, 3600), u, u, home, home, "Negotiate",
                       "Unlock", "LogOn")

    for s in range(a.services):
        u = f"U{9000 + s}@DOM1"
        src = rng.choice(servers)
        dst = rng.choice(servers)
        period = rng.integers(120, 900)
        for t in np.arange(rng.integers(0, period), a.days * 86400, period):
            ev(t + rng.integers(0, 3), u, u, src, dst, "Kerberos", "Service", "LogOn")

    for m in range(a.machines):
        c = f"C{2000 + m}"
        u = f"{c}$@DOM1"
        period = rng.integers(60, 600)
        for t in np.arange(rng.integers(0, period), a.days * 86400, period):
            ev(t + rng.integers(0, 2), u, u, c, rng.choice(servers[:5]), "Kerberos", "Network", "TGS")

    victims = rng.choice(a.humans, a.attacked, replace=False)
    for v in victims:
        u, home = f"U{v + 1}@DOM1", f"C{1000 + v}"
        for _ in range(rng.integers(1, 4)):
            d = rng.integers(3, a.days)
            hr = rng.choice([1, 2, 3, 21, 22, 23, 10, 14])
            t0 = d * 86400 + hr * 3600
            targets = rng.choice([f"C{i}" for i in range(3000, 3400)], rng.integers(4, 20), replace=False)
            for _ in range(rng.integers(0, 8)):
                ev(t0 + rng.integers(0, 600), u, u, home, rng.choice(targets), "NTLM", "Network", "LogOn", False)
            for tg in targets:
                t = t0 + rng.integers(0, 3600)
                ev(t, u, u, home, tg, "NTLM", "Network", "LogOn")
                red.append((int(t), u, home, tg))

    df = pd.DataFrame(rows, columns=AUTH_COLS).sort_values("time")
    df.to_csv(out / "auth.txt.gz", header=False, index=False, compression="gzip")
    pd.DataFrame(red).sort_values(0).to_csv(out / "redteam.txt.gz", header=False, index=False,
                                            compression="gzip")
    print(f"{len(df):,} sự kiện, {len(red)} sự kiện red team ({a.attacked} user) -> {out}")


if __name__ == "__main__":
    main()
