"""Kiểm tra chất lượng dữ liệu + EDA TRƯỚC khi train (dùng cho chương "Dữ liệu" của báo cáo).

Dữ liệu thô (CERT, các file nhỏ): số dòng, id trùng, giá trị rỗng, ngày lỗi/ngoài khoảng.
Bảng feature (CERT/LANL): thiếu dữ liệu, cột hằng (vô dụng), cặp cột tương quan rất cao,
tỉ lệ ngoại lai (IQR), phân bố nhãn theo thời gian, so sánh bình thường vs độc hại.

Chạy:  python src/data_quality.py cert   |   python src/data_quality.py lanl
Kết quả: reports/<ds>_data_quality.json + reports/<ds>_eda_*.png
"""
import json
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from config import CERT_RAW, PROCESSED_DIR, REPORTS_DIR

CERT_RAW_FILES = {"logon": ["id", "date", "user", "pc", "activity"],
                  "device": ["id", "date", "user", "pc", "activity"],
                  "file": ["id", "date", "user", "pc", "filename"],
                  "email": ["id", "date", "user", "pc", "to", "from", "size", "attachments"]}


def raw_checks_cert() -> dict:
    out = {}
    for name, cols in CERT_RAW_FILES.items():
        df = pd.read_csv(CERT_RAW / "r4.2" / f"{name}.csv", usecols=cols, dtype=str)
        dt = pd.to_datetime(df["date"], format="%m/%d/%Y %H:%M:%S", errors="coerce")
        out[name] = {
            "rows": int(len(df)),
            "duplicate_ids": int(df["id"].duplicated().sum()),
            "duplicate_rows_excl_id": int(df.drop(columns="id").duplicated().sum()),
            "nulls": {c: int(v) for c, v in df.isna().sum().items() if v},
            "bad_dates": int(dt.isna().sum()),
            "date_min": str(dt.min()), "date_max": str(dt.max()),
            "users": int(df["user"].nunique()),
            "values_activity": df["activity"].value_counts().to_dict() if "activity" in df else None,
        }
        print(f"  {name:7s}: {out[name]['rows']:>9,} dòng, id trùng={out[name]['duplicate_ids']}, "
              f"dòng trùng={out[name]['duplicate_rows_excl_id']}, ngày lỗi={out[name]['bad_dates']}")
    return out


def feature_checks(feats: pd.DataFrame, cols, label, ds) -> dict:
    X = feats[cols].astype("float64")
    q1, q3 = X.quantile(0.25), X.quantile(0.75)
    iqr = q3 - q1
    outlier_rate = ((X > q3 + 3 * iqr) | (X < q1 - 3 * iqr)).mean()
    corr = X.corr().abs()
    pairs = [(a, b, round(float(corr.loc[a, b]), 3)) for i, a in enumerate(cols)
             for b in cols[i + 1:] if corr.loc[a, b] > 0.95]
    y = feats[label].astype(bool)
    compare = pd.DataFrame({"normal_mean": X[~y].mean(), "malicious_mean": X[y].mean()})
    compare["ratio"] = compare["malicious_mean"] / (compare["normal_mean"] + 1e-9)
    report = {
        "rows": int(len(feats)), "positives": int(y.sum()), "positive_rate": float(y.mean()),
        "missing": {c: int(v) for c, v in X.isna().sum().items() if v},
        "constant_cols": [c for c in cols if X[c].nunique() <= 1],
        "near_constant_cols": [c for c in cols if (X[c] == X[c].mode().iat[0]).mean() > 0.999],
        "high_corr_pairs_gt_0.95": pairs,
        "outlier_rate_3iqr": outlier_rate.round(4).to_dict(),
        "malicious_vs_normal": compare.round(3).sort_values("ratio", ascending=False).to_dict("index"),
    }
    _plots(feats, X, y, compare, ds)
    print(f"  {len(feats):,} dòng, {int(y.sum())} dương tính ({y.mean():.4%}); "
          f"cột hằng: {report['constant_cols']}; cặp tương quan >0.95: {len(pairs)}")
    print("  Feature khác biệt nhất (độc hại / bình thường):")
    print(compare.sort_values("ratio", ascending=False).head(8).round(2).to_string())
    return report


def _plots(feats, X, y, compare, ds):
    top = compare.sort_values("ratio", ascending=False).index[:8].tolist()
    fig, axes = plt.subplots(2, 4, figsize=(16, 7))
    for ax, c in zip(axes.flat, top):
        ax.boxplot([np.log1p(X.loc[~y, c].clip(lower=0)), np.log1p(X.loc[y, c].clip(lower=0))],
                   showfliers=False)
        ax.set_xticks([1, 2], ["bình thường", "độc hại"])
        ax.set_title(f"log1p({c})", fontsize=9)
    fig.suptitle(f"{ds.upper()}: feature khác biệt nhất giữa bình thường và độc hại")
    fig.tight_layout()
    fig.savefig(REPORTS_DIR / f"{ds}_eda_feature_compare.png", dpi=120)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10, 3.5))
    per_day = feats.groupby("day")[y.name].sum()
    ax.bar(per_day.index, per_day.values, width=1.0)
    ax.set(title=f"{ds.upper()}: số user-ngày độc hại theo ngày", xlabel="ngày", ylabel="số user-ngày")
    fig.tight_layout()
    fig.savefig(REPORTS_DIR / f"{ds}_eda_labels_over_time.png", dpi=120)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(11, 9))
    im = ax.imshow(X.corr().values, cmap="coolwarm", vmin=-1, vmax=1)
    ax.set_xticks(range(len(X.columns)), X.columns, rotation=90, fontsize=7)
    ax.set_yticks(range(len(X.columns)), X.columns, fontsize=7)
    fig.colorbar(im)
    ax.set_title(f"{ds.upper()}: ma trận tương quan feature")
    fig.tight_layout()
    fig.savefig(REPORTS_DIR / f"{ds}_eda_correlation.png", dpi=120)
    plt.close(fig)


def main():
    ds = sys.argv[1] if len(sys.argv) > 1 else "cert"
    report = {}
    if ds == "cert":
        from cert_features import FEATURE_COLS, OUT_PATH
        print("[1] Dữ liệu thô CERT")
        report["raw"] = raw_checks_cert()
        feats, label = pd.read_parquet(OUT_PATH), "is_malicious"
        report["insiders_per_scenario"] = feats[feats[label]].groupby("scenario")["user"] \
            .nunique().to_dict()
    else:
        from features import FEATURE_COLS, OUT_PATH
        feats, label = pd.read_parquet(OUT_PATH), "is_redteam"
        report["account_types"] = feats["account_type"].value_counts().to_dict()
        feats = feats[feats["account_type"] == "human"]
    print("[2] Bảng feature")
    report["features"] = feature_checks(feats, FEATURE_COLS, label, ds)
    out = REPORTS_DIR / f"{ds}_data_quality.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    print("Đã lưu:", out)


if __name__ == "__main__":
    main()
