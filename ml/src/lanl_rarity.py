"""Độ hiếm có TẦN SUẤT + SUY GIẢM THEO THỜI GIAN cho LANL (thay cờ "mới / đã thấy").

Vì sao: feature "mới so với lịch sử" là cờ có/không – kẻ tấn công dùng máy C17693 một lần ở
ngày 8 thì từ đó về sau máy này "đã thấy" mãi mãi (baseline bị đầu độc). Ở đây lịch sử là số
đếm suy giảm (bán rã HALF_LIFE ngày): cặp chỉ xuất hiện 1–2 lần cách đây vài tuần vẫn hiếm hơn
nhiều so với máy user dùng hằng ngày.

Với mỗi user-ngày (chỉ tài khoản người), lấy GIÁ TRỊ LỚN NHẤT trong ngày (không lấy trung bình –
tránh bị pha loãng bởi hàng nghìn sự kiện bình thường):
  rare_src_max   – độ hiếm của máy nguồn với chính user:   -log((H_u(src) + a) / (H_u + 1))
  rare_dst_max   – độ hiếm của máy đích với chính user:    -log((H_u(dst) + a) / (H_u + 1))
  rare_edge_max  – độ hiếm của cạnh nguồn→đích trong toàn mạng: -log((H(edge) + a) / (D + a))
                   (H(edge) = số ngày cạnh xuất hiện, suy giảm; D = tổng trọng số các ngày)
  rare_combo_max – max trên các cạnh của (độ hiếm nguồn với user + độ hiếm cạnh): cùng lúc máy
                   lạ với user VÀ đường đi lạ trong mạng
Dùng dữ liệu tổng hợp theo ngày của features.py (lanl_daily/), chạy tuần tự, hỗ trợ cách ly.
"""
import numpy as np
import pandas as pd

from features import _hash, daily_path

HALF_LIFE = 7.0
DECAY = 0.5 ** (1 / HALF_LIFE)
ALPHA = 0.1
RARITY_COLS = ["rare_src_max", "rare_dst_max", "rare_edge_max", "rare_combo_max"]


def _add(acc: pd.Series, keys: np.ndarray, vals: np.ndarray) -> pd.Series:
    new = pd.Series(vals, index=keys).groupby(level=0).sum()
    return acc.add(new, fill_value=0.0)


class RarityState:
    def __init__(self):
        self.h_src = pd.Series(dtype="float64")     # hash(user, src) → đếm suy giảm
        self.h_dst = pd.Series(dtype="float64")     # hash(user, dst)
        self.h_user = pd.Series(dtype="float64")    # user → tổng đếm suy giảm
        self.h_edge = pd.Series(dtype="float64")    # hash(src, dst) → số ngày xuất hiện, suy giảm
        self.d_eff = 0.0                            # tổng trọng số các ngày lịch sử

    def features(self, day: int) -> tuple[pd.DataFrame, dict]:
        src = pd.read_parquet(daily_path(day, "src"), columns=["src_user", "src_comp", "c"])
        dst = pd.read_parquet(daily_path(day, "dst"))
        edge = pd.read_parquet(daily_path(day, "edge"))
        alle = pd.read_parquet(daily_path(day, "alledge"))["h"].values
        src["k"] = _hash(src["src_user"].values, src["src_comp"].values)
        dst["k"] = _hash(dst["src_user"].values, dst["dst_comp"].values)
        edge["k"] = _hash(edge["src_comp"].values, edge["dst_comp"].values)
        edge["ks"] = _hash(edge["src_user"].values, edge["src_comp"].values)

        hu = self.h_user.reindex(src["src_user"].values).fillna(0).values
        src["r"] = -np.log((self.h_src.reindex(src["k"].values).fillna(0).values + ALPHA)
                           / (hu + 1))
        hu = self.h_user.reindex(dst["src_user"].values).fillna(0).values
        dst["r"] = -np.log((self.h_dst.reindex(dst["k"].values).fillna(0).values + ALPHA)
                           / (hu + 1))
        edge["re"] = -np.log((self.h_edge.reindex(edge["k"].values).fillna(0).values + ALPHA)
                             / (self.d_eff + ALPHA))
        edge = edge.merge(src[["k", "r"]].rename(columns={"k": "ks", "r": "rs"}), on="ks",
                          how="left")
        edge["combo"] = edge["re"] + edge["rs"].fillna(0)

        out = pd.DataFrame({
            "rare_src_max": src.groupby("src_user")["r"].max(),
            "rare_dst_max": dst.groupby("src_user")["r"].max(),
            "rare_edge_max": edge.groupby("src_user")["re"].max(),
            "rare_combo_max": edge.groupby("src_user")["combo"].max(),
        }).fillna(0.0)
        return out, {"src": src, "dst": dst, "edge": edge, "alledge": alle}

    def commit(self, pending: dict, quarantine: set | None = None):
        """Suy giảm lịch sử 1 ngày rồi học hành vi hôm nay, TRỪ user bị cách ly."""
        for name in ("h_src", "h_dst", "h_user", "h_edge"):
            setattr(self, name, getattr(self, name) * DECAY)
        self.d_eff = self.d_eff * DECAY + 1.0
        src, dst = pending["src"], pending["dst"]
        if quarantine:
            src = src[~src["src_user"].isin(quarantine)]
            dst = dst[~dst["src_user"].isin(quarantine)]
            bad = pending["edge"].loc[pending["edge"]["src_user"].isin(quarantine), "k"].values
            alle = pending["alledge"][~np.isin(pending["alledge"], bad)]
        else:
            alle = pending["alledge"]
        self.h_src = _add(self.h_src, src["k"].values, src["c"].values.astype(float))
        self.h_dst = _add(self.h_dst, dst["k"].values, dst["c"].values.astype(float))
        self.h_user = _add(self.h_user, src["src_user"].values, src["c"].values.astype(float))
        self.h_edge = _add(self.h_edge, alle, np.ones(len(alle)))
