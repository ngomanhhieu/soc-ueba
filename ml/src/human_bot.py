"""A5 – Phân loại "có phải người dùng hay không" (người thật vs máy/dịch vụ).

LANL không có nhãn người/máy trực tiếp, nhưng tên tài khoản cho nhãn yếu:
  U123@DOM1  → tài khoản người      C625$@DOM1 / SYSTEM@... → tài khoản máy/dịch vụ
Mô hình chỉ học từ NHỊP HÀNH VI (giờ hoạt động, độ đều đặn, mức bùng nổ, kiểu logon),
không nhìn tên tài khoản. Khi áp lên tài khoản người, is_human_prob thấp nghĩa là
"tài khoản người nhưng hành xử như máy" (script, công cụ tự động, tài khoản bị chiếm).
Chia train/test theo user (GroupShuffleSplit) để không lộ thông tin giữa hai tập.
"""
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

from config import MODELS_DIR
from features import RHYTHM_COLS
from models import to_matrix

MODEL_PATH = MODELS_DIR / "lanl_human_bot.joblib"


def train_human_bot(feats: pd.DataFrame, max_rows: int = 400_000) -> tuple[pd.Series, dict]:
    labeled = feats[feats["account_type"].isin(["human", "machine", "system"])]
    labeled = labeled[labeled["n_events"] >= 5]          # quá ít sự kiện thì không có "nhịp"
    if len(labeled) > max_rows:
        labeled = labeled.sample(max_rows, random_state=42)
    y = (labeled["account_type"] == "human").astype(int).values
    X = to_matrix(labeled, RHYTHM_COLS)

    tr, te = next(GroupShuffleSplit(test_size=0.25, random_state=42)
                  .split(X, y, groups=labeled["src_user"].values))
    clf = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08,
                                         class_weight="balanced", random_state=42)
    clf.fit(X[tr], y[tr])
    prob = clf.predict_proba(X[te])[:, 1]
    metrics = {
        "rows_train": int(len(tr)), "rows_test": int(len(te)),
        "accuracy": float(accuracy_score(y[te], prob > 0.5)),
        "roc_auc": float(roc_auc_score(y[te], prob)),
        "report": classification_report(y[te], prob > 0.5, target_names=["machine", "human"],
                                        output_dict=True),
    }
    print(f"    người/máy: accuracy={metrics['accuracy']:.3f}  ROC-AUC={metrics['roc_auc']:.3f}")
    joblib.dump({"model": clf, "cols": RHYTHM_COLS}, MODEL_PATH)

    is_human_prob = pd.Series(clf.predict_proba(to_matrix(feats, RHYTHM_COLS))[:, 1],
                              index=feats.index, name="is_human_prob")
    return is_human_prob, metrics


def predict_human_prob(feats: pd.DataFrame) -> np.ndarray:
    blob = joblib.load(MODEL_PATH)
    return blob["model"].predict_proba(to_matrix(feats, blob["cols"]))[:, 1]
