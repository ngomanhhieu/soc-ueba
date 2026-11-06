"""A5 – Bộ phân loại người thật / không phải người (bot, tài khoản máy, service).

LANL không có nhãn người/bot nên dùng nhãn yếu (weak supervision):
  * bot (0)  : tài khoản máy C...$@DOM
  * người (1): tài khoản U... từng có logon Interactive/RemoteInteractive/Unlock
               trong giai đoạn train (dấu hiệu có người ngồi máy)
  * còn lại  : không gán nhãn (thường là service account) -> chỉ dự đoán
Model CHỈ dùng nhóm feature bot-like (nhịp sự kiện, đỉnh/phút, 24/7, entropy giờ)
— không dùng logon_type để tránh rò nhãn. Đánh giá bằng GroupKFold theo user.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupKFold

from common import BOT_FEATURES


def weak_labels(train: pd.DataFrame) -> pd.Series:
    human_users = set(train.loc[~train.is_machine & train.has_interactive, "user"])
    lab = pd.Series(np.nan, index=train.index)
    lab[train.is_machine] = 0
    lab[train.user.isin(human_users)] = 1
    return lab


class HumanBotClassifier:
    def __init__(self, seed=42):
        self.seed = seed
        self.features = BOT_FEATURES

    def _rf(self):
        return RandomForestClassifier(n_estimators=300, min_samples_leaf=5, n_jobs=-1,
                                      class_weight="balanced", random_state=self.seed)

    def fit(self, train: pd.DataFrame):
        y = weak_labels(train)
        m = y.notna()
        X, y, groups = train.loc[m, self.features].to_numpy(), y[m].astype(int).to_numpy(), train.loc[m, "user"]
        self.report = {"n_train": int(m.sum()), "n_human": int(y.sum()), "n_bot": int((y == 0).sum())}
        if len(np.unique(y)) < 2:
            print("  [human_bot] thiếu một lớp nhãn (cần cả tài khoản máy và user) -> is_human_prob = None")
            self.m = None
            return self
        n_groups = groups.nunique()
        if n_groups >= 4:
            aucs = []
            for tr, te in GroupKFold(n_splits=min(5, n_groups)).split(X, y, groups):
                if len(np.unique(y[te])) < 2:
                    continue
                p = self._rf().fit(X[tr], y[tr]).predict_proba(X[te])[:, 1]
                aucs.append(roc_auc_score(y[te], p))
            self.report["cv_roc_auc_by_user"] = float(np.mean(aucs)) if aucs else None
        self.m = self._rf().fit(X, y)
        self.report["importance"] = dict(sorted(zip(self.features, [round(float(v), 3) for v in self.m.feature_importances_]),
                                                key=lambda t: -t[1]))
        return self

    def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
        if self.m is None:
            return np.full(len(df), np.nan)
        return self.m.predict_proba(df[self.features].to_numpy())[:, 1]
