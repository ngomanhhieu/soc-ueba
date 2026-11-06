"""A3 – Baseline thống kê: z-score theo user, IQR theo user, z-score theo peer group.

Peer group: LANL không có phòng ban nên gom user có hồ sơ hành vi giống nhau
bằng KMeans trên trung bình feature giai đoạn train (với CERT có thể thay bằng
department/role trong LDAP).

Chỉ xét lệch DƯƠNG (tăng bất thường) để giảm cảnh báo giả do user ít hoạt động.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

from common import COUNT_FEATURES

STAT_FEATURES = ["n_events", "n_fail", "fail_ratio", "distinct_dst", "distinct_src",
                 "distinct_dst_user", "new_src", "new_dst", "ntlm_ratio",
                 "offhours_ratio", "peak_per_min", "remote_interactive_ratio"]


def _transform(df: pd.DataFrame, cols) -> pd.DataFrame:
    x = df[cols].astype(float).copy()
    for c in cols:
        if c in COUNT_FEATURES:
            x[c] = np.log1p(x[c])
    return x


class StatBaseline:
    def __init__(self, features=STAT_FEATURES, min_windows=10, n_peers=8,
                 std_floor=0.25, iqr_floor=0.25, seed=42):
        self.features, self.min_windows, self.n_peers = features, min_windows, n_peers
        self.std_floor, self.iqr_floor, self.seed = std_floor, iqr_floor, seed

    def fit(self, train: pd.DataFrame):
        x = _transform(train, self.features)
        x["user"] = train["user"].values
        g = x.groupby("user")
        self.u_mean, self.u_std = g.mean(), g.std().fillna(0).clip(lower=self.std_floor)
        self.u_q1, self.u_q3 = g.quantile(0.25), g.quantile(0.75)
        self.u_iqr = (self.u_q3 - self.u_q1).clip(lower=self.iqr_floor)
        self.u_n = g.size()
        self.global_mean = x[self.features].mean()
        self.global_std = x[self.features].std().clip(lower=self.std_floor)

        # peer group
        prof = self.u_mean.fillna(0)
        k = int(min(self.n_peers, max(1, len(prof) // 5)))
        self.scaler = StandardScaler().fit(prof)
        self.km = KMeans(k, n_init=10, random_state=self.seed).fit(self.scaler.transform(prof))
        self.peer_of = pd.Series(self.km.labels_, index=prof.index)
        xp = x.join(self.peer_of.rename("peer"), on="user")
        gp = xp.groupby("peer")[self.features]
        self.p_mean, self.p_std = gp.mean(), gp.std().fillna(0).clip(lower=self.std_floor)
        return self

    def _peer(self, df):
        peer = df["user"].map(self.peer_of)
        miss = peer.isna()
        if miss.any():  # user mới -> gán peer gần nhất theo chính hồ sơ cửa sổ hiện tại
            xm = _transform(df.loc[miss], self.features).fillna(0)
            peer.loc[miss] = self.km.predict(self.scaler.transform(xm))
        return peer.astype(int)

    def score(self, df: pd.DataFrame) -> pd.DataFrame:
        x = _transform(df, self.features)
        users = df["user"]
        enough = users.map(self.u_n).fillna(0) >= self.min_windows
        mean = self.u_mean.reindex(users).set_index(df.index)
        std = self.u_std.reindex(users).set_index(df.index)
        q3 = self.u_q3.reindex(users).set_index(df.index)
        iqr = self.u_iqr.reindex(users).set_index(df.index)
        peer = self._peer(df)
        pm = self.p_mean.reindex(peer).set_index(df.index)
        ps = self.p_std.reindex(peer).set_index(df.index)

        z_peer = ((x - pm) / ps).clip(lower=0)
        z_user = ((x - mean) / std).clip(lower=0)
        iqr_s = ((x - q3) / iqr).clip(lower=0)
        # user ít lịch sử -> dùng peer thay cho baseline cá nhân
        z_user = z_user.where(enough, other=z_peer, axis=0).fillna(z_peer)
        iqr_s = iqr_s.where(enough, other=z_peer, axis=0).fillna(z_peer)

        out = pd.DataFrame(index=df.index)
        out["zscore"] = z_user.max(axis=1)
        out["iqr"] = iqr_s.max(axis=1)
        out["peer_z"] = z_peer.max(axis=1)
        out["stat"] = (z_user + z_peer).max(axis=1) / 2  # điểm thống kê tổng hợp
        out["top_feature"] = (z_user + z_peer).idxmax(axis=1)
        out["top_z"] = z_user.max(axis=1)
        out["peer"] = peer.values
        return out
