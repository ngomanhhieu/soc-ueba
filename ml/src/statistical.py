"""A3 – Baseline thống kê (không cần ML), là mốc so sánh cho Isolation Forest/Autoencoder.

Hai góc nhìn, đúng như UEBA thực tế:
  * self-baseline: so user hôm nay với chính user đó các ngày trước (z-score mở rộng dần)
  * peer-baseline: so user với các user cùng nhóm trong cùng ngày (robust z: median/IQR)
stat_score = trung bình 3 độ lệch dương lớn nhất, ép về [0, 1].
Dùng chung cho LANL (mặc định) và CERT (truyền cols/user_col/peer_col khác).
"""
import numpy as np
import pandas as pd

STAT_COLS = ["n_events", "n_src_comp", "n_dst_comp", "n_dst_user", "fail_ratio",
             "remote_ratio", "ntlm_ratio", "n_new_dst_comp", "new_dst_ratio",
             "n_new_src_comp", "unusual_hour_ratio", "max_per_minute",
             "n_new_src_events", "new_src_ntlm_events", "new_src_max_fanin"]
MIN_HISTORY = 3   # cần ít nhất 3 ngày lịch sử mới tin self-baseline
EPS = 1e-6


def self_zscores(feats, cols, user_col="src_user", day_col="day") -> pd.DataFrame:
    df = feats.sort_values([user_col, day_col])
    x = df[cols].astype("float64")
    g_sum = x.groupby(df[user_col]).cumsum() - x            # tổng các ngày TRƯỚC
    g_sq = (x ** 2).groupby(df[user_col]).cumsum() - x ** 2
    n_hist = df.groupby(user_col).cumcount()
    n = n_hist.replace(0, np.nan).values[:, None]
    mean = g_sum / n
    std = np.sqrt(((g_sq / n) - mean ** 2).clip(lower=0))
    z = (x - mean) / (std.fillna(0) + x.abs().mean() * 0.1 + EPS)
    z[n_hist < MIN_HISTORY] = 0.0
    return z.add_prefix("zself_").reindex(feats.index)


def peer_zscores(feats, cols, day_col="day", peer_col="account_type") -> pd.DataFrame:
    x = feats[cols].astype("float64")
    g = x.groupby([feats[day_col], feats[peer_col]])
    med = g.transform("median")
    iqr = g.transform(lambda s: s.quantile(0.75) - s.quantile(0.25))
    z = (x - med) / (iqr + x.abs().mean() * 0.1 + EPS)
    return z.add_prefix("zpeer_")


def statistical_scores(feats, cols=STAT_COLS, user_col="src_user", day_col="day",
                       peer_col="account_type") -> pd.DataFrame:
    """Trả về các cột z-score + stat_score + top_reasons (feature lệch nhiều nhất)."""
    zs = self_zscores(feats, cols, user_col, day_col)
    zp = peer_zscores(feats, cols, day_col, peer_col)
    # lấy độ lệch lớn hơn giữa self và peer cho từng feature, chỉ quan tâm chiều tăng
    combined = np.nan_to_num(np.maximum(zs.values, zp.values)).clip(min=0)
    top3 = np.sort(combined, axis=1)[:, -3:].mean(axis=1)
    out = pd.concat([zs, zp], axis=1)
    out["stat_raw"] = top3
    out["stat_score"] = 1 - np.exp(-top3 / 5)          # đơn điệu, ép về [0, 1)
    order = np.argsort(-combined, axis=1)[:, :3]
    out["top_reasons"] = [[cols[j] for j in row if combined[i, j] > 0]
                          for i, row in enumerate(order)]
    return out
