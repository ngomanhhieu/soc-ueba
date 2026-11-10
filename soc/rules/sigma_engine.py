"""Engine luật Sigma tối giản chạy trên pandas DataFrame (Lớp 1 – rule-based detection).

Hỗ trợ đúng phần chuẩn Sigma mà dự án dùng:
  * luật cơ sở: detection gồm các selection (dict = AND giữa field, list giá trị = OR,
    list các dict = OR), condition với and / or / not / ngoặc / "1 of x*" / "all of x*" / "them"
  * modifier: contains, startswith, endswith, re, gt, gte, lt, lte, all, expand (placeholder
    %ten% – dùng cho danh sách IOC nạp lúc chạy)
  * luật tương quan Sigma v2 (correlation): event_count, value_count, temporal, có group-by,
    timespan, condition (gt/gte/lt/lte, field). Cửa sổ thời gian dạng tumbling (cắt theo bội
    số timespan) – giống "bucket" của SIEM, đơn giản và giải thích được.

Sự kiện là DataFrame với cột theo tên field ECS (vd. "user.name", "source.host") và cột
"@timestamp" = số giây (int). Mỗi bộ dữ liệu có loader riêng (datasets.py).
"""
import re
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

LEVEL_SCORE = {"informational": 0.3, "low": 0.5, "medium": 0.7, "high": 0.85, "critical": 0.95}
CONTEXT_MAX = 50
_SPAN = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_timespan(s: str) -> int:
    m = re.fullmatch(r"(\d+)([smhd])", str(s).strip())
    if not m:
        raise ValueError(f"timespan không hợp lệ: {s}")
    return int(m.group(1)) * _SPAN[m.group(2)]


@dataclass
class Rule:
    raw: dict
    path: Path

    @property
    def id(self): return self.raw.get("id", self.name)
    @property
    def name(self): return self.raw.get("name") or self.raw.get("title")
    @property
    def title(self): return self.raw.get("title", self.name)
    @property
    def level(self): return self.raw.get("level", "medium")
    @property
    def tags(self): return self.raw.get("tags", [])
    @property
    def logsource(self): return self.raw.get("logsource", {})
    @property
    def is_correlation(self): return "correlation" in self.raw

    @property
    def mitre(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags
                if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]


def load_rules(folder: Path) -> list[Rule]:
    rules = []
    for p in sorted(Path(folder).glob("*.yml")):
        for doc in yaml.safe_load_all(p.read_text(encoding="utf-8")):
            if doc:
                rules.append(Rule(doc, p))
    return rules


# ---------------------------------------------------------------- luật cơ sở
def _match_values(col: pd.Series, values, mods: list[str], placeholders: dict) -> pd.Series:
    if not isinstance(values, list):
        values = [values]
    if "expand" in mods:
        exp = []
        for v in values:
            m = re.fullmatch(r"%(\w+)%", str(v))
            exp += list(placeholders.get(m.group(1), [])) if m else [v]
        values = exp
        mods = [m for m in mods if m != "expand"]
    if not values:
        return pd.Series(False, index=col.index)
    if any(v is None for v in values):
        none_hit = col.isna()
        values = [v for v in values if v is not None]
        if not values:
            return none_hit
    else:
        none_hit = pd.Series(False, index=col.index)

    num = {"gt": np.greater, "gte": np.greater_equal, "lt": np.less, "lte": np.less_equal}
    hits = []
    for v in values:
        if any(m in num for m in mods):
            op = next(num[m] for m in mods if m in num)
            hits.append(pd.Series(op(pd.to_numeric(col, errors="coerce"), float(v)),
                                  index=col.index).fillna(False))
        elif "re" in mods:
            hits.append(col.astype(str).str.contains(str(v), regex=True, na=False))
        elif "contains" in mods:
            hits.append(col.astype(str).str.lower().str.contains(str(v).lower(), regex=False,
                                                                 na=False))
        elif "startswith" in mods:
            hits.append(col.astype(str).str.lower().str.startswith(str(v).lower(), na=False))
        elif "endswith" in mods:
            hits.append(col.astype(str).str.lower().str.endswith(str(v).lower(), na=False))
        elif isinstance(v, bool):
            hits.append(col.astype(bool) == v)
        elif isinstance(v, (int, float)):
            hits.append(pd.to_numeric(col, errors="coerce") == v)
        elif isinstance(col.dtype, pd.CategoricalDtype) and len(values) > 1 and "all" not in mods:
            return col.isin(values) | none_hit          # nhanh cho cột category
        else:
            hits.append(col.astype(str).str.lower() == str(v).lower())
    out = hits[0]
    for h in hits[1:]:
        out = (out & h) if "all" in mods else (out | h)
    return out | none_hit


def _selection(df: pd.DataFrame, sel, placeholders) -> pd.Series:
    if isinstance(sel, list):                       # list các map → OR
        out = pd.Series(False, index=df.index)
        for s in sel:
            out |= _selection(df, s, placeholders)
        return out
    out = pd.Series(True, index=df.index)
    for key, values in sel.items():
        fld, *mods = key.split("|")
        if fld not in df.columns:
            raise KeyError(f"field '{fld}' không có trong dữ liệu")
        out &= _match_values(df[fld], values, mods, placeholders)
    return out


def _tokenize(cond: str) -> list[str]:
    return re.findall(r"\(|\)|1 of [\w*]+|all of [\w*]+|\w+\*?|\S+", cond)


def eval_condition(cond: str, sels: dict[str, pd.Series], index) -> pd.Series:
    """Parser đệ quy cho: or < and < not < (…) | tên | 1 of x* | all of x* | them."""
    toks = _tokenize(cond)
    pos = 0

    def group(pattern, how):
        names = [n for n in sels if re.fullmatch(pattern.replace("*", ".*"), n)] \
            if pattern != "them" else list(sels)
        parts = [sels[n] for n in names]
        if not parts:
            raise KeyError(f"không có selection khớp '{pattern}'")
        out = parts[0]
        for p in parts[1:]:
            out = (out | p) if how == "any" else (out & p)
        return out

    def atom():
        nonlocal pos
        t = toks[pos]
        pos += 1
        if t == "(":
            v = expr_or()
            pos += 1                                    # ')'
            return v
        if t == "not":
            return ~atom()
        if t.startswith("1 of "):
            return group(t[5:], "any")
        if t.startswith("all of "):
            return group(t[7:], "all")
        return sels[t]

    def expr_and():
        nonlocal pos
        v = atom()
        while pos < len(toks) and toks[pos] == "and":
            pos += 1
            v = v & atom()
        return v

    def expr_or():
        nonlocal pos
        v = expr_and()
        while pos < len(toks) and toks[pos] == "or":
            pos += 1
            v = v | expr_and()
        return v

    return expr_or()


def match_base(rule: Rule, df: pd.DataFrame, placeholders: dict | None = None) -> pd.Series:
    det = dict(rule.raw["detection"])
    cond = det.pop("condition")
    sels = {k: _selection(df, v, placeholders or {}) for k, v in det.items()}
    return eval_condition(cond, sels, df.index)


# ---------------------------------------------------------------- tương quan
def _cmp(v, cond: dict):
    ok = np.ones(len(v), dtype=bool)
    for op, f in (("gt", np.greater), ("gte", np.greater_equal), ("lt", np.less),
                  ("lte", np.less_equal), ("eq", np.equal)):
        if op in cond:
            ok &= f(v, cond[op])
    return ok


def correlate(rule: Rule, matches: dict[str, pd.DataFrame], cond_override: dict | None = None,
              label_col: str | None = None) -> pd.DataFrame:
    """matches: tên luật cơ sở → DataFrame các sự kiện khớp. Trả về 1 dòng / (nhóm, cửa sổ).
    cond_override: thay ngưỡng (dùng khi dò ngưỡng); label_col: cột nhãn để ĐẾM (chỉ đánh giá)."""
    c = rule.raw["correlation"]
    span = parse_timespan(c["timespan"])
    by = c.get("group-by", [])
    cond = dict(c.get("condition", {"gte": 1}))
    if cond_override:
        cond.update(cond_override)
    kind = c["type"]
    parts = [matches[r].assign(_rule=r) for r in c["rules"] if r in matches and len(matches[r])]
    if not parts:
        return pd.DataFrame()
    ev = pd.concat(parts, ignore_index=True)
    ev["_win"] = ev["@timestamp"] // span
    keys = by + ["_win"]
    g = ev.groupby(keys, observed=True, sort=False)
    agg = g.agg(first=("@timestamp", "min"), last=("@timestamp", "max"), n_events=("_rule", "size"))
    if label_col and label_col in ev.columns:
        agg["n_label"] = g[label_col].sum()
    if kind == "event_count":
        agg["value"] = agg["n_events"]
    elif kind == "value_count":
        agg["value"] = g[cond["field"]].nunique()
    elif kind == "temporal":                             # mọi luật được tham chiếu đều xuất hiện
        agg["value"] = g["_rule"].nunique()
        if not cond_override:
            cond = {"gte": len(c["rules"])}
    else:
        raise ValueError(f"correlation type chưa hỗ trợ: {kind}")
    hit = agg[_cmp(agg["value"].values, cond)].reset_index()
    if hit.empty:
        return hit
    hit["window_start"] = hit["_win"] * span
    hit["window_end"] = hit["window_start"] + span
    # giữ các giá trị ngữ cảnh (máy đích, tài khoản...) để analyst/agent điều tra
    sample_cols = [f for f in c.get("context", []) if f in ev.columns]
    if sample_cols:
        sub = ev.merge(hit[keys], on=keys)
        for col in sample_cols:   # category → chuỗi, để gom thành list không bị ép kiểu
            sub[col] = sub[col].astype(str)
        ctx = sub.groupby(keys, observed=True, sort=False)[sample_cols] \
            .agg(lambda s: sorted(map(str, set(s)))[:CONTEXT_MAX]) \
            .rename(columns=lambda c: f"ctx.{c}").reset_index()   # không trùng khoá group-by
        hit = hit.merge(ctx, on=keys, how="left")
        if label_col and label_col in sub.columns and "user.name" in sample_cols:
            lab = sub[sub[label_col]].groupby(keys, observed=True)["user.name"] \
                .agg(lambda s: sorted(map(str, set(s)))).rename("label_users").reset_index()
            hit = hit.merge(lab, on=keys, how="left")
    return hit.drop(columns="_win")


@dataclass
class RuleSet:
    rules: list[Rule]
    placeholders: dict = field(default_factory=dict)
    thresholds: dict = field(default_factory=dict)   # rule id → ngưỡng (từ tune_thresholds.py)
    label_col: str | None = None                       # chỉ để đánh giá
    tune: dict | None = None                           # chế độ dò ngưỡng: ghi đè condition

    def for_logsource(self, product: str, service: str | None = None) -> "RuleSet":
        sel = [r for r in self.rules if r.logsource.get("product") == product
               and (service is None or r.logsource.get("service") == service)]
        names = {r.name for r in sel}
        corr = [r for r in self.rules if r.is_correlation
                and set(r.raw["correlation"]["rules"]) & names]
        return RuleSet(sel + [r for r in corr if r not in sel], self.placeholders,
                       self.thresholds, self.label_col, self.tune)

    def run(self, events: dict[str, pd.DataFrame]) -> pd.DataFrame:
        """events: service → DataFrame. Trả về bảng cảnh báo (mỗi dòng 1 lần luật bắn)."""
        base = [r for r in self.rules if not r.is_correlation]
        corr = [r for r in self.rules if r.is_correlation]
        referenced = {n for r in corr for n in r.raw["correlation"]["rules"]}
        matches, out = {}, []
        for r in base:
            df = events.get(r.logsource.get("service"))
            if df is None or df.empty:
                continue
            m = df[match_base(r, df, self.placeholders)]
            matches[r.name] = m
            if self.tune is None and r.name not in referenced and len(m):
                # luật đứng một mình → mỗi sự kiện 1 cảnh báo
                out.append(self._alerts(r, m.assign(n_events=1, window_start=m["@timestamp"],
                                                   window_end=m["@timestamp"])))
        for r in corr:
            override = self.tune if self.tune is not None else (
                {"gte": self.thresholds[r.id]} if r.id in self.thresholds else None)
            hit = correlate(r, matches, override, self.label_col)
            if len(hit):
                out.append(self._alerts(r, hit))
        return pd.concat(out, ignore_index=True) if out else pd.DataFrame()

    @staticmethod
    def _alerts(r: Rule, hit: pd.DataFrame) -> pd.DataFrame:
        hit = hit.copy()
        hit.insert(0, "rule_id", r.id)
        hit.insert(1, "rule_title", r.title)
        hit.insert(2, "level", r.level)
        hit.insert(3, "mitre", [r.mitre] * len(hit))
        hit.insert(4, "rule_score", LEVEL_SCORE.get(r.level, 0.7))
        return hit
