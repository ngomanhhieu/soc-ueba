"""A1 – Đọc LANL auth.txt(.gz) theo chunk, lọc khoảng ngày, lấy subset user.

auth.txt rất lớn (~1 tỷ dòng, ~7GB nén) nên KHÔNG đọc hết vào RAM:
  * chỉ giữ các dòng trong [start_day, end_day)
  * file đã sắp xếp theo time -> dừng đọc khi vượt end_day
  * giữ TẤT CẢ user bị red team + một tỉ lệ ngẫu nhiên (theo hash, cố định) user khác
  * giữ một tỉ lệ nhỏ tài khoản máy (C...$) để huấn luyện bộ phân loại người/bot

Ví dụ:
  python src/lanl_load_auth.py --start-day 0 --end-day 30 --user-sample 0.05
"""
from __future__ import annotations

import argparse
import time as _t
import zlib

import pandas as pd

from common import AUTH_COLS, RAW, REDTEAM_COLS, save_df


def keep_by_hash(name: str, rate: float) -> bool:
    return (zlib.crc32(name.encode()) % 100_000) < rate * 100_000


def load_redteam(path) -> pd.DataFrame:
    red = pd.read_csv(path, names=REDTEAM_COLS)
    red["day"] = red["time"] // 86400
    return red


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--auth", default=str(RAW / "auth.txt.gz"))
    ap.add_argument("--redteam", default=str(RAW / "redteam.txt.gz"))
    ap.add_argument("--start-day", type=int, default=0)
    ap.add_argument("--end-day", type=int, default=30, help="không bao gồm")
    ap.add_argument("--user-sample", type=float, default=0.05,
                    help="tỉ lệ user thường (không phải red team) được giữ")
    ap.add_argument("--machine-sample", type=float, default=0.002,
                    help="tỉ lệ tài khoản máy C...$ được giữ (cho bộ phân loại bot)")
    ap.add_argument("--chunksize", type=int, default=5_000_000)
    ap.add_argument("--out", default="auth_subset")
    a = ap.parse_args()

    t0_s, t1_s = a.start_day * 86400, a.end_day * 86400
    red = load_redteam(a.redteam)
    red = red[(red.time >= t0_s) & (red.time < t1_s)]
    red_users = set(red["user"])
    print(f"Red team trong khoảng ngày: {len(red)} sự kiện, {len(red_users)} user")

    decide: dict[str, bool] = {}

    def keep_user(u: str) -> bool:
        r = decide.get(u)
        if r is None:
            if u in red_users:
                r = True
            elif u.startswith("ANONYMOUS"):
                r = False
            elif "$@" in u:
                r = keep_by_hash(u, a.machine_sample)
            else:
                r = keep_by_hash(u, a.user_sample)
            decide[u] = r
        return r

    parts, n_read, t_start = [], 0, _t.time()
    reader = pd.read_csv(a.auth, names=AUTH_COLS, chunksize=a.chunksize,
                         dtype={c: "string" for c in AUTH_COLS[1:]})
    for chunk in reader:
        n_read += len(chunk)
        tmin, tmax = chunk.time.iloc[0], chunk.time.iloc[-1]
        if tmax < t0_s:
            print(f"  bỏ qua chunk (ngày {tmax // 86400}) ...", end="\r")
            continue
        chunk = chunk[(chunk.time >= t0_s) & (chunk.time < t1_s)]
        users = chunk["src_user"].unique()
        keep = {u for u in users if keep_user(u)}
        chunk = chunk[chunk["src_user"].isin(keep)]
        parts.append(chunk)
        kept = sum(len(p) for p in parts)
        print(f"  đã đọc {n_read:,} dòng, giữ {kept:,} | ngày {tmax // 86400} | "
              f"{_t.time() - t_start:.0f}s", end="\r")
        if tmin >= t1_s:
            break
    print()

    df = pd.concat(parts, ignore_index=True)
    df = df.rename(columns={"src_user": "user"})
    df["success"] = df.pop("outcome").eq("Success")
    df["is_machine"] = df["user"].str.contains(r"\$@", regex=True)
    df["day"] = (df["time"] // 86400).astype("int32")
    for c in ["user", "dst_user", "src_comp", "dst_comp", "auth_type", "logon_type", "auth_orient"]:
        df[c] = df[c].astype("category")
    df["time"] = df["time"].astype("int64")

    p = save_df(df, a.out)
    save_df(red.reset_index(drop=True), "redteam_subset")
    print(f"Lưu {len(df):,} dòng -> {p}")
    print(f"  user người: {df.loc[~df.is_machine, 'user'].nunique():,} | "
          f"tài khoản máy: {df.loc[df.is_machine, 'user'].nunique():,}")
    print(f"  red team user có log: {len(red_users & set(df['user'].unique()))}/{len(red_users)}")
    print("  thiếu dữ liệu ('?'):", {c: int((df[c] == "?").sum())
                                     for c in ["auth_type", "logon_type"]})


if __name__ == "__main__":
    main()
