"""A2 – Feature engineering hành vi xác thực theo (user × ngày) cho LANL.

Mỗi dòng = hành vi của 1 tài khoản nguồn (src_user) trong 1 ngày. Các nhóm feature:
  * khối lượng / đa dạng: số sự kiện, số máy nguồn/đích, số tài khoản đích
  * kiểu xác thực: tỉ lệ thất bại, NTLM, Kerberos, logon từ xa, các loại logon
  * so với lịch sử của chính user (UEBA): máy nguồn/đích mới, giờ hoạt động lạ, cạnh mới
  * nhịp thời gian (dùng cho phân loại người/máy): độ đều đặn, mức bùng nổ
Nhãn: is_redteam = user-ngày đó có ít nhất 1 sự kiện red team (chỉ dùng để đánh giá).

Hai giai đoạn (để thử nghiệm nhanh):
  1. day_aggregates – mỗi ngày độc lập (chạy song song): feature trong ngày + bảng cặp
     (user, máy nguồn), (user, máy đích), (user, giờ), cạnh (máy nguồn → máy đích) → lanl_daily/
  2. NoveltyState   – đi tuần tự theo ngày, so với lịch sử → feature "mới lạ". Có thể CÁCH LY
     user-ngày đã bị cảnh báo: hành vi đó không được học vào lịch sử "bình thường" (chống đầu
     độc baseline – xem lanl_online.py).

Chạy:  python src/features.py [--workers 3] [--skip-daily]
Kết quả: data/processed/lanl_user_day_features.parquet
"""
import argparse
import time as _time
from concurrent.futures import ProcessPoolExecutor

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from config import (LANL_DAILY_DIR, LANL_EVENTS_DIR, PROCESSED_DIR, SECONDS_PER_DAY,
                    SYSTEM_ACCOUNT_PREFIXES)

OUT_PATH = PROCESSED_DIR / "lanl_user_day_features.parquet"
SMOOTH_M = 20   # số "sự kiện ảo" khi làm mượt tỉ lệ
CAT_COLS = ["src_user", "dst_user", "src_comp", "dst_comp", "auth_type", "logon_type",
            "orientation", "result"]
LOGON_TYPES = ["Network", "Interactive", "RemoteInteractive", "Batch", "Service", "Unlock",
               "NetworkCleartext", "NewCredentials", "CachedInteractive"]
NOVELTY_COLS = ["n_new_dst_comp", "new_dst_ratio", "n_new_src_comp", "unusual_hour_ratio",
                "n_new_src_events", "new_src_ntlm_events", "new_src_max_fanin",
                "n_new_edge", "n_new_edge_src_new"]

# Các feature số đưa vào mô hình (không gồm định danh/nhãn)
FEATURE_COLS = [
    "n_events", "n_logon", "n_fail", "fail_ratio", "n_src_comp", "n_dst_comp", "n_dst_user",
    "remote_ratio", "ntlm_ratio", "kerberos_ratio", "unknown_auth_ratio",
    *[f"lt_{t.lower()}_ratio" for t in LOGON_TYPES],
    "n_active_hours", "hour_entropy", "first_hour", "last_hour",
    *NOVELTY_COLS, "src_max_fanin",
    "gap_mean", "gap_cv", "max_per_minute",
]
# Đầu vào mô hình: bỏ cột trùng thông tin / gần như hằng (kết quả data_quality.py lanl):
# n_logon ~ n_events (tương quan 0.97), lt_newcredentials_ratio gần như luôn = 0
MODEL_COLS = [c for c in FEATURE_COLS if c not in ("n_logon", "lt_newcredentials_ratio")]
# Feature không phụ thuộc lịch sử – dùng cho bộ phân loại người/máy
RHYTHM_COLS = [
    "n_events", "fail_ratio", "n_src_comp", "n_dst_comp", "remote_ratio", "ntlm_ratio",
    "kerberos_ratio", *[f"lt_{t.lower()}_ratio" for t in LOGON_TYPES],
    "n_active_hours", "hour_entropy", "first_hour", "last_hour", "gap_mean", "gap_cv",
    "max_per_minute",
]
DAILY_KINDS = ("base", "src", "dst", "hour", "edge", "alledge")


def account_type(user: pd.Series) -> pd.Series:
    u = user.astype(str)
    kind = np.where(u.str.contains(r"\$@", regex=True), "machine",
                    np.where(u.str.startswith("U"), "human", "other"))
    kind = np.where(u.str.startswith(SYSTEM_ACCOUNT_PREFIXES), "system", kind)
    return pd.Series(kind, index=user.index)


def load_day(path) -> pd.DataFrame:
    table = pq.read_table(path, read_dictionary=CAT_COLS)
    return table.to_pandas()


def _hash(*cols) -> np.ndarray:
    return pd.util.hash_pandas_object(pd.DataFrame({i: c for i, c in enumerate(cols)}),
                                      index=False).values


def daily_path(day: int, kind: str):
    return LANL_DAILY_DIR / f"day{day:02d}_{kind}.parquet"


# ---------------------------------------------------------------- giai đoạn 1: từng ngày
def day_aggregates(path) -> int:
    day = int(path.stem.replace("auth_day", ""))
    df = load_day(path)
    df = df.sort_values(["src_user", "time"], kind="stable")
    df["hour"] = ((df["time"] % SECONDS_PER_DAY) // 3600).astype("int8")
    g = df.groupby("src_user", observed=True, sort=False)

    f = pd.DataFrame({
        "n_events": g.size(),
        "n_src_comp": g["src_comp"].nunique(),
        "n_dst_comp": g["dst_comp"].nunique(),
        "n_dst_user": g["dst_user"].nunique(),
        "first_hour": g["hour"].min(),
        "last_hour": g["hour"].max(),
        "n_redteam": g["is_redteam"].sum(),
    })
    remote = df["src_comp"].astype(str).values != df["dst_comp"].astype(str).values
    ntlm = (df["auth_type"] == "NTLM").values
    flags = pd.DataFrame({
        "src_user": df["src_user"],
        "logon_ratio": (df["orientation"] == "LogOn").values,
        "fail_ratio": (df["result"] == "Fail").values,
        "remote_ratio": remote,
        "ntlm_ratio": ntlm,
        "kerberos_ratio": (df["auth_type"] == "Kerberos").values,
        "unknown_auth_ratio": (df["auth_type"] == "?").values,
        **{f"lt_{t.lower()}_ratio": (df["logon_type"] == t).values for t in LOGON_TYPES},
    })
    f = f.join(flags.groupby("src_user", observed=True).mean())
    f["n_logon"] = (f.pop("logon_ratio") * f["n_events"]).round()
    f["n_fail"] = (f["fail_ratio"] * f["n_events"]).round()
    # Làm mượt tỉ lệ (Bayesian / additive smoothing): tài khoản chỉ có 1–2 sự kiện sẽ có tỉ lệ
    # 0% hoặc 100% chỉ do mẫu nhỏ → báo động giả. Kéo về trung bình chung với SMOOTH_M sự kiện ảo.
    ratio_cols = [c for c in flags.columns if c != "src_user" and c != "logon_ratio"]
    n = f["n_events"]
    for c in ratio_cols:
        prior = (f[c] * n).sum() / n.sum()
        f[c] = (f[c] * n + prior * SMOOTH_M) / (n + SMOOTH_M)

    # Phân bố giờ trong ngày
    hc = df.groupby(["src_user", "hour"], observed=True).size().rename("c").reset_index()
    hc["p"] = hc["c"] / hc.groupby("src_user", observed=True)["c"].transform("sum")
    hc["plogp"] = -hc["p"] * np.log2(hc["p"])
    f["n_active_hours"] = hc.groupby("src_user", observed=True).size()
    f["hour_entropy"] = hc.groupby("src_user", observed=True)["plogp"].sum()

    # Nhịp thời gian: khoảng cách giữa 2 sự kiện liên tiếp, đỉnh sự kiện/phút
    gaps = df["time"].diff().where(df["src_user"].eq(df["src_user"].shift()))
    gstat = gaps.groupby(df["src_user"], observed=True).agg(["mean", "std"])
    f["gap_mean"] = gstat["mean"].fillna(SECONDS_PER_DAY)
    f["gap_cv"] = (gstat["std"] / gstat["mean"]).replace([np.inf], np.nan).fillna(0)
    per_min = df.groupby(["src_user", df["time"] // 60], observed=True).size()
    f["max_per_minute"] = per_min.groupby(level=0, observed=True).max()
    f.index = f.index.astype(str)

    # Bảng cặp cho tài khoản NGƯỜI (novelty chỉ dùng cho phát hiện trên tài khoản người).
    # Fan-in = số tài khoản người khác nhau dùng máy nguồn đó trong ngày (máy cá nhân: 1–2).
    is_human = df["src_user"].astype(str).str.startswith("U").values
    hu = pd.DataFrame({"src_user": df["src_user"].astype(str).values[is_human],
                       "src_comp": df["src_comp"].astype(str).values[is_human],
                       "dst_comp": df["dst_comp"].astype(str).values[is_human],
                       "hour": df["hour"].values[is_human],
                       "ntlm": ntlm[is_human], "remote": remote[is_human]})
    fanin = hu.groupby("src_comp")["src_user"].nunique().rename("fanin")
    src = hu.groupby(["src_user", "src_comp"]).agg(c=("hour", "size"), ntlm=("ntlm", "sum")) \
        .reset_index().merge(fanin, left_on="src_comp", right_index=True)
    # Fan-in lớn nhất trong các máy nguồn (đăng nhập từ xa) user dùng hôm nay – KHÔNG phụ thuộc
    # lịch sử nên không bị "đầu độc" khi kẻ tấn công dùng lại máy cũ
    rsrc = hu[hu["remote"]].groupby(["src_user", "src_comp"]).size().reset_index() \
        .merge(fanin, left_on="src_comp", right_index=True)
    f["src_max_fanin"] = rsrc.groupby("src_user")["fanin"].max().reindex(f.index).fillna(0)
    dst = hu.groupby(["src_user", "dst_comp"]).size().rename("c").reset_index()
    hour = hu.groupby(["src_user", "hour"]).size().rename("c").reset_index()
    edge = hu.loc[hu["remote"], ["src_user", "src_comp", "dst_comp"]].drop_duplicates()
    alle = pd.DataFrame({"h": np.unique(_hash(df["src_comp"].astype(str).values[remote],
                                              df["dst_comp"].astype(str).values[remote]))})

    LANL_DAILY_DIR.mkdir(parents=True, exist_ok=True)
    out = {"base": f.reset_index().rename(columns={"index": "src_user"}), "src": src,
           "dst": dst, "hour": hour, "edge": edge, "alledge": alle}
    for kind, d in out.items():
        d.to_parquet(daily_path(day, kind), index=False)
    print(f"  ngày {day:02d}: {len(df):>11,} sự kiện → {len(f):>6,} user "
          f"({int(f['n_redteam'].gt(0).sum())} user-ngày red team)", flush=True)
    return day


# ---------------------------------------------------------------- giai đoạn 2: tuần tự
class NoveltyState:
    """Lịch sử "đã từng thấy" của mạng, cập nhật từng ngày. Lưu dạng hash uint64 đã sắp xếp."""

    def __init__(self):
        self.seen = {k: np.array([], dtype=np.uint64) for k in ("src", "dst", "hour", "edge")}

    def features(self, day: int) -> tuple[pd.DataFrame, dict]:
        """Feature mới lạ cho ngày `day` (so với lịch sử TRƯỚC ngày đó) + dữ liệu để commit."""
        src, dst = pd.read_parquet(daily_path(day, "src")), pd.read_parquet(daily_path(day, "dst"))
        hour, edge = pd.read_parquet(daily_path(day, "hour")), pd.read_parquet(daily_path(day, "edge"))
        alle = pd.read_parquet(daily_path(day, "alledge"))["h"].values
        src["h"] = _hash(src["src_user"].values, src["src_comp"].values)
        dst["h"] = _hash(dst["src_user"].values, dst["dst_comp"].values)
        hour["h"] = _hash(hour["src_user"].values, hour["hour"].values)
        edge["h"] = _hash(edge["src_comp"].values, edge["dst_comp"].values)
        src["new"] = ~np.isin(src["h"].values, self.seen["src"])
        dst["new"] = ~np.isin(dst["h"].values, self.seen["dst"])
        hour["new"] = ~np.isin(hour["h"].values, self.seen["hour"])
        edge["new"] = ~np.isin(edge["h"].values, self.seen["edge"])

        out = pd.DataFrame(index=pd.Index(src["src_user"].unique(), name="src_user"))
        nd = dst.groupby("src_user").agg(n=("new", "sum"), tot=("new", "size"))
        out["n_new_dst_comp"] = nd["n"]
        out["new_dst_ratio"] = nd["n"] / nd["tot"].clip(lower=1)
        ns = src[src["new"]]
        out["n_new_src_comp"] = ns.groupby("src_user").size()
        out["unusual_hour_ratio"] = (hour["c"] * hour["new"]).groupby(hour["src_user"]).sum() \
            / hour.groupby("src_user")["c"].sum()
        out["n_new_src_events"] = ns.groupby("src_user")["c"].sum()
        out["new_src_ntlm_events"] = ns.groupby("src_user")["ntlm"].sum()
        # mẫu Pass-the-Hash (T1550.002): đăng nhập NTLM từ máy lạ, máy đó dùng nhiều tài khoản
        out["new_src_max_fanin"] = ns[ns["ntlm"] > 0].groupby("src_user")["fanin"].max()
        # cạnh mới toàn cục (máy nguồn → máy đích chưa ai dùng) – di chuyển ngang (TA0008)
        ne = edge[edge["new"]].merge(src.loc[src["new"], ["src_user", "src_comp"]]
                                     .assign(src_new=True), on=["src_user", "src_comp"],
                                     how="left")
        out["n_new_edge"] = ne.groupby("src_user")["h"].nunique()
        out["n_new_edge_src_new"] = ne.groupby("src_user")["src_new"].sum()
        out = out.fillna(0)
        return out, {"src": src, "dst": dst, "hour": hour, "edge": edge, "alledge": alle}

    def commit(self, pending: dict, quarantine: set | None = None):
        """Học hành vi hôm nay vào lịch sử, TRỪ các user trong `quarantine` (đã bị cảnh báo)."""
        for k in ("src", "dst", "hour"):
            d = pending[k]
            if quarantine:
                d = d[~d["src_user"].isin(quarantine)]
            self.seen[k] = np.union1d(self.seen[k], d["h"].values)
        if quarantine:
            # cạnh do user bị cách ly tạo ra không được coi là "bình thường"
            bad = pending["edge"].loc[pending["edge"]["src_user"].isin(quarantine), "h"].values
            good = pending["alledge"][~np.isin(pending["alledge"], bad)]
        else:
            good = pending["alledge"]
        self.seen["edge"] = np.union1d(self.seen["edge"], good)


def available_days() -> list[int]:
    return sorted(int(p.stem.replace("auth_day", ""))
                  for p in LANL_EVENTS_DIR.glob("auth_day*.parquet"))


def load_base(day: int) -> pd.DataFrame:
    return pd.read_parquet(daily_path(day, "base"))


def assemble(day: int, base: pd.DataFrame, nov: pd.DataFrame, history_days: int) -> pd.DataFrame:
    f = base.merge(nov, left_on="src_user", right_index=True, how="left")
    f[NOVELTY_COLS] = f[NOVELTY_COLS].fillna(0)
    f.insert(1, "day", day)
    f["history_days"] = history_days
    return f


def finalize(parts: list[pd.DataFrame]) -> pd.DataFrame:
    feats = pd.concat(parts, ignore_index=True)
    feats["account_type"] = account_type(feats["src_user"])
    feats["is_redteam"] = feats["n_redteam"] > 0
    feats[FEATURE_COLS] = feats[FEATURE_COLS].astype("float32")
    return feats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--skip-daily", action="store_true",
                    help="dùng lại lanl_daily/ đã có, chỉ tính lại novelty")
    args = ap.parse_args()
    days = available_days()
    if not days:
        raise SystemExit(f"Chưa có parquet trong {LANL_EVENTS_DIR}. Chạy lanl_load_auth.py trước.")
    t0 = _time.time()
    if not args.skip_daily:
        todo = [LANL_EVENTS_DIR / f"auth_day{d:02d}.parquet" for d in days
                if not all(daily_path(d, k).exists() for k in DAILY_KINDS)]
        with ProcessPoolExecutor(args.workers) as ex:
            list(ex.map(day_aggregates, todo))
        print(f"Giai đoạn 1 xong ({_time.time() - t0:,.0f}s)")

    state, parts = NoveltyState(), []
    for i, day in enumerate(days):
        nov, pending = state.features(day)
        parts.append(assemble(day, load_base(day), nov, i))
        state.commit(pending)
    feats = finalize(parts)
    feats.to_parquet(OUT_PATH, index=False)
    print(f"Đã lưu {len(feats):,} dòng × {len(FEATURE_COLS)} feature → {OUT_PATH} "
          f"({_time.time() - t0:,.0f}s)")
    print(feats.groupby("account_type")["is_redteam"].agg(["size", "sum"]))


if __name__ == "__main__":
    main()
