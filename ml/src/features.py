"""A2 – Feature engineering theo user × cửa sổ thời gian (mặc định 1 giờ).

Lưu ý: thời gian LANL là số giây tương đối (không có giờ thật). "Giờ trong ngày"
được tính là (time // 3600) % 24 – đủ để học nhịp ngày/đêm tương đối.

  python src/features.py --window 3600 --warmup-days 2
"""
from __future__ import annotations

import argparse

import numpy as np
import pandas as pd

from common import ALL_FEATURES, load_df, save_df

AUTH_FLAGS = {"kerberos": ("auth_type", "Kerberos"), "ntlm": ("auth_type", "NTLM"),
              "negotiate": ("auth_type", "Negotiate")}
LOGON_FLAGS = {"network": "Network", "interactive": "Interactive",
               "remote_interactive": "RemoteInteractive", "service": "Service",
               "batch": "Batch", "unlock": "Unlock"}
ORIENT_FLAGS = {"logon": "LogOn", "logoff": "LogOff", "tgs": "TGS", "tgt": "TGT"}


def _mode_per_group(df: pd.DataFrame, keys: list[str], col: str) -> pd.Series:
    """Giá trị xuất hiện nhiều nhất của col trong mỗi nhóm (nhanh hơn .mode())."""
    c = df.groupby(keys + [col], observed=True).size().rename("n").reset_index()
    c = c.sort_values("n", ascending=False).drop_duplicates(keys)
    return c.set_index(keys)[col].astype(str)


def _new_entity_count(df: pd.DataFrame, col: str) -> pd.Series:
    """Số giá trị col (vd src_comp) lần đầu xuất hiện với user trong cửa sổ đó."""
    first = df.groupby(["user", col], observed=True)["win"].min().rename("first_win").reset_index()
    user_first = df.groupby("user", observed=True)["win"].min().rename("user_first")
    first = first.join(user_first, on="user")
    first = first[first.first_win > first.user_first]  # cửa sổ đầu tiên của user không tính "mới"
    return first.groupby(["user", "first_win"], observed=True).size().rename_axis(["user", "win"])


def build_features(df: pd.DataFrame, window: int = 3600, off_start: int = 8,
                   off_end: int = 18) -> pd.DataFrame:
    df = df.copy()
    df["user"] = df["user"].astype(str)  # khoá nhóm dạng chuỗi -> tránh lệch category giữa các bảng
    df = df.sort_values(["user", "time"], kind="stable").reset_index(drop=True)
    df["win"] = df["time"] // window
    hour = (df["time"] // 3600) % 24
    df["hour"] = hour.astype("int8")
    df["is_off"] = ((hour < off_start) | (hour >= off_end)).astype("int8")
    df["fail"] = (~df["success"]).astype("int8")
    df["self_auth"] = (df["src_comp"].astype(str) == df["dst_comp"].astype(str)).astype("int8")
    for k, (col, val) in AUTH_FLAGS.items():
        df[f"f_{k}"] = (df[col] == val).astype("int8")
    for k, val in LOGON_FLAGS.items():
        df[f"f_{k}"] = (df["logon_type"] == val).astype("int8")
    for k, val in ORIENT_FLAGS.items():
        df[f"f_{k}"] = (df["auth_orient"] == val).astype("int8")

    # khoảng cách giữa 2 sự kiện liên tiếp của cùng user, trong cùng cửa sổ
    dt = df["time"].diff()
    same = (df["user"] == df["user"].shift()) & (df["win"] == df["win"].shift())
    df["dt"] = dt.where(same)

    keys = ["user", "win"]
    g = df.groupby(keys, observed=True)
    flag_cols = [c for c in df.columns if c.startswith("f_")]
    agg = g[["fail", "is_off", "self_auth"] + flag_cols].sum()
    feat = pd.DataFrame(index=agg.index)
    feat["n_events"] = g.size()
    feat["n_fail"] = agg["fail"]
    feat["n_success"] = feat["n_events"] - feat["n_fail"]
    feat["fail_ratio"] = feat["n_fail"] / feat["n_events"]
    feat["offhours_ratio"] = agg["is_off"] / feat["n_events"]
    feat["self_auth_ratio"] = agg["self_auth"] / feat["n_events"]
    for c in flag_cols:
        feat[c[2:] + "_ratio"] = agg[c] / feat["n_events"]

    feat["distinct_dst"] = g["dst_comp"].nunique()
    feat["distinct_src"] = g["src_comp"].nunique()
    feat["distinct_dst_user"] = g["dst_user"].nunique()
    feat["new_src"] = _new_entity_count(df, "src_comp")
    feat["new_dst"] = _new_entity_count(df, "dst_comp")

    # --- bot-like ---
    feat["interval_mean"] = g["dt"].mean()
    feat["interval_std"] = g["dt"].std()
    feat["interval_cv"] = feat["interval_std"] / (feat["interval_mean"] + 1)
    df["minute"] = df["time"] // 60
    feat["peak_per_min"] = df.groupby(keys + ["minute"], observed=True).size().groupby(
        level=[0, 1], observed=True).max()

    # hoạt động trong cả ngày (24/7 không nghỉ -> giống máy)
    hd = df.groupby(["user", "day", "hour"], observed=True).size().rename("n").reset_index()
    tot = hd.groupby(["user", "day"], observed=True)["n"].transform("sum")
    hd["p"] = hd["n"] / tot
    day_stats = hd.groupby(["user", "day"], observed=True).agg(
        active_hours_day=("hour", "nunique"),
        hour_entropy_day=("p", lambda p: float(-(p * np.log2(p)).sum())))
    win_day = g["day"].first().rename("day")
    feat = feat.join(win_day)
    feat = feat.join(day_stats, on=["user", "day"])

    feat["hour"] = g["hour"].first()
    feat["hour_sin"] = np.sin(2 * np.pi * feat["hour"] / 24)
    feat["hour_cos"] = np.cos(2 * np.pi * feat["hour"] / 24)
    feat["is_machine"] = g["is_machine"].first()
    feat["ts"] = g["time"].min()
    feat["src_host"] = _mode_per_group(df, keys, "src_comp")
    feat["dst_host"] = _mode_per_group(df, keys, "dst_comp")
    feat["has_interactive"] = (agg["f_interactive"] + agg["f_remote_interactive"]
                               + agg["f_unlock"]) > 0

    feat = feat.fillna({c: 0 for c in ALL_FEATURES})
    feat = feat.reset_index()
    feat["user"] = feat["user"].astype(str)
    return feat


def add_labels(feat: pd.DataFrame, red: pd.DataFrame, window: int) -> pd.DataFrame:
    red = red.assign(win=red["time"] // window)
    lab = red.groupby(["user", "win"]).size().rename("n_redteam").reset_index()
    feat = feat.merge(lab, on=["user", "win"], how="left")
    feat["n_redteam"] = feat["n_redteam"].fillna(0).astype(int)
    feat["label"] = (feat["n_redteam"] > 0).astype(int)
    return feat


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inp", default="auth_subset")
    ap.add_argument("--window", type=int, default=3600, help="giây; 3600=giờ, 86400=ngày")
    ap.add_argument("--warmup-days", type=int, default=2,
                    help="số ngày đầu chỉ dùng làm lịch sử (cho new_src/new_dst), không xuất")
    ap.add_argument("--off-start", type=int, default=8)
    ap.add_argument("--off-end", type=int, default=18)
    ap.add_argument("--out", default="features")
    a = ap.parse_args()

    df = load_df(a.inp)
    red = load_df("redteam_subset")
    print(f"Đọc {len(df):,} sự kiện, {df['user'].nunique():,} user")
    feat = build_features(df, a.window, a.off_start, a.off_end)
    feat = add_labels(feat, red, a.window)
    d0 = feat["day"].min() + a.warmup_days
    n_red_lost = feat.loc[feat.day < d0, "label"].sum()
    feat = feat[feat.day >= d0].reset_index(drop=True)
    p = save_df(feat, a.out)
    print(f"Lưu {len(feat):,} cửa sổ × {len(ALL_FEATURES)} feature -> {p}")
    print(f"  cửa sổ red team: {feat.label.sum()} (bỏ {n_red_lost} trong warm-up) | "
          f"ngày {feat.day.min()}–{feat.day.max()}")


if __name__ == "__main__":
    main()
