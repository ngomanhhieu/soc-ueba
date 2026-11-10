"""Chuẩn hoá sự kiện LANL/CERT về field kiểu ECS cho engine luật (và để nạp vào Elasticsearch).

Làm giàu (enrichment) giống pipeline ingest của SIEM – chỉ dùng thông tin có sẵn lúc sự kiện tới:
  LANL: user.kind (từ tên tài khoản), network.remote (nguồn ≠ đích)
  CERT: event.offhours / event.weekend, file.extension, email.external_recipients,
        url.org_popularity (tỉ lệ nhân viên đã từng vào domain, tính từ các ngày TRƯỚC),
        url.category (danh mục URL như web proxy: job / competitor)
Cột nhãn (is_redteam / is_malicious) chỉ để ĐÁNH GIÁ – luật không được dùng.
"""
import numpy as np
import pandas as pd
import pyarrow.compute as pc
import pyarrow.csv as pv
import pyarrow as pa

import soc.config  # noqa: F401  (thêm ml/src vào sys.path)
from cert_features import COMPANY_DOMAIN, HTTP_DOMAINS_PATH, R42, URL_GROUPS, WORK_END, WORK_START
from config import LANL_EVENTS_DIR, SECONDS_PER_DAY
from features import account_type, load_day

LANL_RENAME = {"time": "@timestamp", "src_user": "user.name", "dst_user": "user.target.name",
               "src_comp": "source.host", "dst_comp": "destination.host",
               "auth_type": "auth.type", "logon_type": "logon.type",
               "orientation": "event.action", "result": "event.outcome"}


def lanl_day(day: int) -> pd.DataFrame:
    df = load_day(LANL_EVENTS_DIR / f"auth_day{day:02d}.parquet").rename(columns=LANL_RENAME)
    users = df["user.name"]
    kinds = account_type(pd.Series(users.cat.categories))
    df["user.kind"] = pd.Categorical.from_codes(
        pd.Categorical(kinds, categories=["human", "machine", "system", "other"]).codes[
            users.cat.codes.values], categories=["human", "machine", "system", "other"])
    df["network.remote"] = df["source.host"].astype(str).values \
        != df["destination.host"].astype(str).values
    df["event.dataset"] = "lanl.auth"
    return df


# ---------------------------------------------------------------- CERT
def _read_csv(name: str, cols: list[str]) -> pa.Table:
    return pv.read_csv(R42 / f"{name}.csv", convert_options=pv.ConvertOptions(
        include_columns=cols, column_types={c: pa.string() for c in cols}))


def _time_cols(t: pa.Table) -> pd.DataFrame:
    ts = pc.strptime(t.column("date"), format="%m/%d/%Y %H:%M:%S", unit="s")
    hour = pc.hour(ts).to_numpy(zero_copy_only=False)
    return pd.DataFrame({
        "@timestamp": pc.cast(ts, pa.int64()).to_numpy(zero_copy_only=False),
        "user.name": pd.Categorical(t.column("user").to_numpy(zero_copy_only=False)),
        "event.offhours": (hour < WORK_START) | (hour >= WORK_END),
        "event.weekend": pc.day_of_week(ts).to_numpy(zero_copy_only=False) >= 5,
    })


def cert_events() -> dict[str, pd.DataFrame]:
    """Trả về service → DataFrame: logon, device, file, email, http (http gộp theo ngày)."""
    out = {}
    t = _read_csv("logon", ["date", "user", "pc", "activity"])
    out["logon"] = _time_cols(t).assign(**{
        "host.name": pd.Categorical(t.column("pc").to_numpy(zero_copy_only=False)),
        "event.action": pd.Categorical(t.column("activity").to_numpy(zero_copy_only=False))})
    t = _read_csv("device", ["date", "user", "pc", "activity"])
    out["device"] = _time_cols(t).assign(**{
        "host.name": pd.Categorical(t.column("pc").to_numpy(zero_copy_only=False)),
        "event.action": pd.Categorical(t.column("activity").to_numpy(zero_copy_only=False))})
    t = _read_csv("file", ["date", "user", "pc", "filename"])
    fn = pd.Series(t.column("filename").to_numpy(zero_copy_only=False)).str.lower()
    out["file"] = _time_cols(t).assign(**{
        "host.name": pd.Categorical(t.column("pc").to_numpy(zero_copy_only=False)),
        "file.name": fn.values,
        "file.extension": pd.Categorical(fn.str.extract(r"\.(\w+)$", expand=False).values)})
    t = _read_csv("email", ["date", "user", "pc", "to", "cc", "bcc", "size", "attachments"])
    rcpt = [";".join(filter(None, x)) for x in zip(
        *(t.column(c).fill_null("").to_pylist() for c in ("to", "cc", "bcc")))]
    ext = [sum(1 for a in r.split(";") if a and not a.endswith(COMPANY_DOMAIN)) for r in rcpt]
    out["email"] = _time_cols(t).assign(**{
        "host.name": pd.Categorical(t.column("pc").to_numpy(zero_copy_only=False)),
        "email.external_recipients": np.array(ext, dtype="int16"),
        "email.attachments": pd.to_numeric(pd.Series(
            t.column("attachments").to_numpy(zero_copy_only=False)), errors="coerce")
        .fillna(0).astype("int16").values,
        "email.size": pd.to_numeric(pd.Series(t.column("size").to_numpy(zero_copy_only=False)),
                                    errors="coerce").fillna(0).values})
    out["http"] = cert_http_daily()
    return out


def cert_http_daily() -> pd.DataFrame:
    """Truy cập web gộp (user, ngày, domain) + độ phổ biến domain tính nhân quả + danh mục."""
    d = pd.read_parquet(HTTP_DOMAINS_PATH)
    d["user"], d["domain"] = d["user"].astype(str), d["domain"].astype(str)
    n_users = d["user"].nunique()
    first = d.groupby(["domain", "user"])["date"].min().rename("first").reset_index()
    pop = np.zeros(len(d))
    for dom, idx in d.groupby("domain").indices.items():
        ref = np.sort(first.loc[first["domain"] == dom, "first"].values)
        pop[idx] = np.searchsorted(ref, d["date"].values[idx], side="left")
    cat = np.full(len(d), "other", dtype=object)
    for name, doms in URL_GROUPS.items():
        cat[d["domain"].isin(doms).values] = name.replace("http_", "")
    return pd.DataFrame({
        "@timestamp": d["date"].values.astype("datetime64[s]").astype("int64"),
        "user.name": pd.Categorical(d["user"]),
        "url.domain": pd.Categorical(d["domain"]),
        "url.org_popularity": pop / n_users,
        "url.category": pd.Categorical(cat),
        "http.visits": d["visits"].values,
    })


def cert_day(ts: pd.Series) -> pd.Series:
    return pd.to_datetime(ts, unit="s").dt.floor("D")


def lanl_day_of(ts) -> np.ndarray:
    return np.asarray(ts) // SECONDS_PER_DAY
