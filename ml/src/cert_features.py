"""A1 + A2 cho CERT Insider Threat r4.2: đọc các file log, tạo feature theo (user × ngày).

CERT là bộ dữ liệu về insider threat / vi phạm chính sách (1000 nhân viên, 17 tháng):
  logon.csv  – đăng nhập/đăng xuất máy        device.csv – cắm/rút USB
  file.csv   – sao chép file ra thiết bị       email.csv  – email gửi đi
  http.csv   – lịch sử duyệt web (~14GB, đọc theo luồng, bỏ cột nội dung)
Nhãn: answers/ – các sự kiện độc hại của từng insider → user-ngày có sự kiện = malicious.

Chuẩn bị: giải nén r4.2.tar.bz2 và answers.tar.bz2 vào <SOC_DATA_DIR>/cert/
Chạy:  python src/cert_http_domains.py   (một lần, rút gọn http.csv theo domain)
       python src/cert_features.py
Kết quả: data/processed/cert_user_day_features.parquet
"""
import time as _time

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pv

from config import CERT_RAW, PROCESSED_DIR

R42 = CERT_RAW / "r4.2"
ANSWERS = CERT_RAW / "answers"
OUT_PATH = PROCESSED_DIR / "cert_user_day_features.parquet"
WORK_START, WORK_END = 8, 18          # giờ hành chính
COMPANY_DOMAIN = "dtaa.com"
HTTP_DOMAINS_PATH = CERT_RAW / "http_user_day_domain.parquet"   # cert_http_domains.py
# Nhóm URL theo DANH MỤC, giống web proxy/URL filter của SOC (không lấy từ answers/ – bản cũ
# lấy wikileaks và các trang keylogger từ chính sự kiện insider → rò nhãn vào feature):
#   http_job        – danh mục "tìm việc": mọi trang tuyển dụng có trong dữ liệu, chọn theo tên
#   http_competitor – đối thủ của công ty quốc phòng DTAA (thông tin nghiệp vụ, biết trước)
# Trang hiếm (wikileaks, bán keylogger...) KHÔNG liệt kê – để feature độ hiếm domain tự bắt.
URL_GROUPS = {
    "http_job": {"monster.com", "simplyhired.com", "job-hunt.org", "jobhuntersbible.com",
                 "careerbuilder.com", "indeed.com", "taleo.net"},
    "http_competitor": {"lockheedmartin.com", "boeing.com", "raytheon.com", "harris.com",
                        "northropgrumman.com"},
}
RARE_FRAC = 0.01    # domain "hiếm" = < 1% nhân viên từng vào (tính từ các ngày TRƯỚC)
DOMAIN_COLS = ["http_rare_max", "http_n_rare", "http_n_new_domain"]

FEATURE_COLS = [
    "logon_n", "logoff_n", "logon_offhours", "logon_weekend", "logon_pcs", "first_logon_hour",
    "last_activity_hour", "usb_n", "usb_offhours", "file_n", "file_offhours", "file_exe",
    "file_zip", "file_doc", "email_n", "email_ext_rcpt", "email_attach", "email_size_mean",
    "email_offhours", "http_n", "http_offhours", *URL_GROUPS, *DOMAIN_COLS,
]
# Đầu vào mô hình: bỏ 1 cột trong mỗi cặp tương quan > 0.95 (kết quả data_quality.py):
# logoff_n~logon_pcs (0.99), file_doc~file_n (0.996), email_n~http_n (0.97).
# Giữ http_leak/http_keylogger dù gần như luôn = 0: đó chính là tín hiệu hiếm cần bắt.
REDUNDANT_COLS = ["logoff_n", "file_doc", "email_n"]
MODEL_COLS = [c for c in FEATURE_COLS if c not in REDUNDANT_COLS]
# Hành vi cộng dồn theo cửa sổ thời gian (add_windows)
WIN_BASE = ["usb_n", "usb_offhours", "file_n", "file_exe", "file_zip", "http_job",
            "http_competitor", "http_n_rare", "logon_offhours", "email_ext_rcpt", "email_attach"]
WINDOWS = (7, 30)


def add_windows(feats: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Tổng trượt theo THỜI GIAN (7D/30D, gồm cả hôm nay) cho từng user – chỉ dùng quá khứ.
    Nhắm kịch bản lấy dữ liệu dần dần nhiều tuần: từng ngày trông bình thường, cộng dồn mới lạ."""
    df = feats.sort_values(["user", "date"])
    new = []
    for w in WINDOWS:
        r = (df.set_index("date").groupby("user")[WIN_BASE]
             .rolling(f"{w}D").sum().reset_index(level=0, drop=True))
        r.columns = [f"w{w}_{c}" for c in WIN_BASE]
        r.index = df.index
        df = df.join(r)
        new += list(r.columns)
    return df.reindex(feats.index), new


def add_trends(feats: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Xu hướng của chính user: 30 ngày gần nhất cao hơn bao nhiêu so với mức của 60 ngày trước
    đó (quy về 30 ngày):  trend = w30 − (w90 − w30) / 2.  Nhắm hành vi TĂNG DẦN qua nhiều tuần
    (kịch bản 2 – nhân viên sắp nghỉ lấy dữ liệu từ từ). Cần add_windows trước (có w30)."""
    df = feats.sort_values(["user", "date"])
    r = (df.set_index("date").groupby("user")[WIN_BASE].rolling("90D").sum()
         .reset_index(level=0, drop=True))
    r.index = df.index
    out = pd.DataFrame(index=df.index)
    for c in WIN_BASE:
        out[f"trend_{c}"] = df[f"w30_{c}"] - (r[c] - df[f"w30_{c}"]) / 2
    return feats.join(out.reindex(feats.index)), list(out.columns)


def _read(name, cols, block=64 << 20):
    path = R42 / f"{name}.csv"
    return pv.open_csv(path, read_options=pv.ReadOptions(block_size=block),
                       convert_options=pv.ConvertOptions(include_columns=cols,
                                                         column_types={c: pa.string() for c in cols}))


def _time_parts(batch):
    ts = pc.strptime(batch.column("date"), format="%m/%d/%Y %H:%M:%S", unit="s")
    hour = pc.hour(ts).to_numpy(zero_copy_only=False)
    return pd.DataFrame({
        "user": batch.column("user").to_numpy(zero_copy_only=False),
        "date": pc.floor_temporal(ts, unit="day").to_numpy(zero_copy_only=False),
        "hour": hour,
        "offhours": (hour < WORK_START) | (hour >= WORK_END),
        "weekend": pc.day_of_week(ts).to_numpy(zero_copy_only=False) >= 5,
    })


def _accumulate(name, cols, make_flags, t0):
    parts, n = [], 0
    for batch in _read(name, cols):
        base = _time_parts(batch)
        flags = make_flags(batch, base)
        parts.append(flags.groupby(["user", "date"]).agg(
            {c: ("min" if c.endswith("_min") else "max" if c.endswith("_max") else "sum")
             for c in flags.columns if c not in ("user", "date")}))
        n += batch.num_rows
    agg = pd.concat(parts).groupby(level=[0, 1]).agg(
        {c: ("min" if c.endswith("_min") else "max" if c.endswith("_max") else "sum")
         for c in parts[0].columns})
    print(f"  {name:7s}: {n:>12,} dòng → {len(agg):>8,} user-ngày ({_time.time() - t0:,.0f}s)",
          flush=True)
    return agg


def logon_features(t0):
    pcs = []

    def flags(b, base):
        act = b.column("activity").to_numpy(zero_copy_only=False)
        is_on = act == "Logon"
        pcs.append(pd.DataFrame({"user": base["user"], "date": base["date"],
                                 "pc": b.column("pc").to_numpy(zero_copy_only=False)})
                   .drop_duplicates())
        return base[["user", "date"]].assign(
            logon_n=is_on, logoff_n=~is_on, logon_offhours=is_on & base["offhours"],
            logon_weekend=is_on & base["weekend"],
            first_logon_hour_min=np.where(is_on, base["hour"], 99),
            last_activity_hour_max=base["hour"])

    agg = _accumulate("logon", ["date", "user", "pc", "activity"], flags, t0)
    agg["logon_pcs"] = pd.concat(pcs).drop_duplicates().groupby(["user", "date"]).size()
    return agg.rename(columns={"first_logon_hour_min": "first_logon_hour",
                               "last_activity_hour_max": "last_activity_hour"})


def device_features(t0):
    def flags(b, base):
        con = b.column("activity").to_numpy(zero_copy_only=False) == "Connect"
        return base[["user", "date"]].assign(usb_n=con, usb_offhours=con & base["offhours"])
    return _accumulate("device", ["date", "user", "activity"], flags, t0)


def file_features(t0):
    def flags(b, base):
        fn = pd.Series(b.column("filename").to_numpy(zero_copy_only=False)).str.lower()
        return base[["user", "date"]].assign(
            file_n=1, file_offhours=base["offhours"], file_exe=fn.str.endswith(".exe").values,
            file_zip=fn.str.endswith(".zip").values,
            file_doc=fn.str.contains(r"\.(?:doc|pdf|txt)$", regex=True).values)
    return _accumulate("file", ["date", "user", "filename"], flags, t0)


def email_features(t0):
    def flags(b, base):
        rcpt = pd.Series([";".join(filter(None, x)) for x in zip(
            *(b.column(c).fill_null("").to_pylist() for c in ("to", "cc", "bcc")))])
        n_ext = rcpt.str.split(";").apply(
            lambda xs: sum(1 for x in xs if x and not x.endswith(COMPANY_DOMAIN)))
        size = pd.to_numeric(pd.Series(b.column("size").to_numpy(zero_copy_only=False)),
                             errors="coerce").fillna(0)
        att = pd.to_numeric(pd.Series(b.column("attachments").to_numpy(zero_copy_only=False)),
                            errors="coerce").fillna(0)
        return base[["user", "date"]].assign(
            email_n=1, email_ext_rcpt=n_ext.values, email_attach=att.values,
            email_size_sum=size.values, email_offhours=base["offhours"])
    agg = _accumulate("email", ["date", "user", "to", "cc", "bcc", "size", "attachments"],
                      flags, t0)
    agg["email_size_mean"] = agg.pop("email_size_sum") / agg["email_n"].clip(lower=1)
    return agg


def http_features(t0):
    def flags(b, base):
        host = pd.Series(b.column("url").to_numpy(zero_copy_only=False)).str.lower() \
            .str.extract(r"^[a-z]+://(?:www\.)?([^/:]+)", expand=False)
        out = base[["user", "date"]].assign(http_n=1, http_offhours=base["offhours"])
        for col, domains in URL_GROUPS.items():
            out[col] = host.isin(domains).values
        return out
    return _accumulate("http", ["date", "user", "url"], flags, t0)


def domain_features(t0) -> pd.DataFrame:
    """Độ hiếm domain, tính NHÂN QUẢ (chỉ dùng các ngày trước) và không cần nhãn:
      http_rare_max     – -log(tỉ lệ nhân viên đã từng vào) của domain hiếm nhất trong ngày
      http_n_rare       – số domain trong ngày mà < RARE_FRAC nhân viên từng vào
      http_n_new_domain – số domain lần đầu tiên chính user này vào
    """
    d = pd.read_parquet(HTTP_DOMAINS_PATH)
    d["user"], d["domain"] = d["user"].astype(str), d["domain"].astype(str)
    n_users = d["user"].nunique()
    first = d.groupby(["domain", "user"])["date"].min().rename("first").reset_index()
    pop = np.zeros(len(d))
    for dom, idx in d.groupby("domain").indices.items():
        ref = np.sort(first.loc[first["domain"] == dom, "first"].values)
        pop[idx] = np.searchsorted(ref, d["date"].values[idx], side="left")  # user vào TRƯỚC
    d["rarity"] = -np.log((pop + 1) / (n_users + 1))
    d["rare"] = pop < RARE_FRAC * n_users
    d = d.merge(first, on=["domain", "user"])
    d["new"] = d["date"] == d["first"]
    agg = d.groupby(["user", "date"]).agg(http_rare_max=("rarity", "max"),
                                          http_n_rare=("rare", "sum"),
                                          http_n_new_domain=("new", "sum"))
    print(f"  domain : {len(d):>12,} (user, ngày, domain) → {len(agg):>8,} user-ngày "
          f"({_time.time() - t0:,.0f}s)", flush=True)
    return agg


def load_labels() -> pd.DataFrame:
    """Đọc answers/r4.2-*/<insider>.csv: mỗi dòng là 1 sự kiện độc hại 'type,id,date,user,...'.

    Chỉ giữ sự kiện của chính insider (theo answers/insiders.csv) trong khoảng [start, end].
    Lý do: kịch bản 3 có dòng mang tên tài khoản của sếp bị mạo danh (FAW0032, FBA0348) – đó là
    nạn nhân, không phải insider; các paper về CERT cũng gắn nhãn theo insider.
    """
    ins = pd.read_csv(ANSWERS / "insiders.csv")
    ins = ins[ins["dataset"].astype(str) == "4.2"]
    ins["start"] = pd.to_datetime(ins["start"], format="%m/%d/%Y %H:%M:%S").dt.floor("D")
    ins["end"] = pd.to_datetime(ins["end"], format="%m/%d/%Y %H:%M:%S").dt.floor("D")
    rows = []
    for f in ANSWERS.glob("r4.2-*/*.csv"):
        scenario = int(f.parent.name.split("-")[-1])
        for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            parts = line.split(",")
            if len(parts) >= 4:
                rows.append({"user": parts[3].strip('"'), "ts": parts[2].strip('"'),
                             "scenario": scenario})
    lab = pd.DataFrame(rows)
    lab["date"] = pd.to_datetime(lab["ts"], format="%m/%d/%Y %H:%M:%S").dt.floor("D")
    lab = lab.merge(ins[["user", "start", "end"]], on="user")
    lab = lab[(lab["date"] >= lab["start"]) & (lab["date"] <= lab["end"])]
    return lab.groupby(["user", "date"]).agg(n_malicious=("ts", "size"),
                                              scenario=("scenario", "first"))


def load_roles() -> pd.Series:
    """Vai trò nhân viên (LDAP) – dùng làm peer group cho baseline thống kê."""
    files = sorted((R42 / "LDAP").glob("*.csv"))
    ldap = pd.concat(pd.read_csv(f) for f in files)
    return ldap.drop_duplicates("user_id", keep="last").set_index("user_id")["role"]


def main():
    t0 = _time.time()
    feats = pd.concat([logon_features(t0), device_features(t0), file_features(t0),
                       email_features(t0), http_features(t0), domain_features(t0)], axis=1)
    feats = feats.reset_index().rename(columns={"level_0": "user", "level_1": "date"})
    for c in FEATURE_COLS:
        if c not in feats:
            feats[c] = 0
    # Ngày không có Logon (chỉ có Logoff) → không có giờ logon đầu tiên. Không điền 0 (sẽ thành
    # "đăng nhập lúc nửa đêm" = báo động giả) mà điền giờ logon thường lệ (median) của chính user.
    flh = feats["first_logon_hour"].replace(99, np.nan)
    feats["first_logon_hour"] = flh.fillna(flh.groupby(feats["user"]).transform("median")) \
        .fillna(flh.median())
    feats[FEATURE_COLS] = feats[FEATURE_COLS].fillna(0).astype("float32")
    feats["day"] = (feats["date"] - feats["date"].min()).dt.days

    labels = load_labels()
    feats = feats.merge(labels, left_on=["user", "date"], right_index=True, how="left")
    feats["is_malicious"] = feats["n_malicious"].fillna(0) > 0
    feats["role"] = feats["user"].map(load_roles()).fillna("unknown")
    feats.to_parquet(OUT_PATH, index=False)
    print(f"Đã lưu {len(feats):,} user-ngày, {feats['is_malicious'].sum()} user-ngày độc hại "
          f"({feats.loc[feats['is_malicious'], 'user'].nunique()} insider) → {OUT_PATH}")


if __name__ == "__main__":
    main()
