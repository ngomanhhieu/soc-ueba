"""A4 – Mô hình phát hiện bất thường không giám sát: Isolation Forest và Autoencoder.

Huấn luyện trên dữ liệu "gần như bình thường" (giai đoạn train), chấm điểm mọi user-ngày.
Điểm được chuẩn hoá thành percentile so với phân bố điểm của tập train:
0.99 nghĩa là bất thường hơn 99% user-ngày lúc train → dễ đặt ngưỡng, dễ giải thích.
"""
import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from torch import nn

from config import MODELS_DIR

COUNT_PREFIXES = ("n_", "max_per_minute", "gap_mean", "first_hour", "last_hour")
SEED = 42


def to_matrix(feats: pd.DataFrame, cols, log_cols=None) -> np.ndarray:
    """Cột đếm (phân bố lệch nặng) được log1p; mặc định nhận diện theo tiền tố tên LANL."""
    X = feats[cols].astype("float64").copy()
    for c in cols:
        if (c in log_cols) if log_cols is not None else c.startswith(COUNT_PREFIXES):
            X[c] = np.log1p(X[c].clip(lower=0))
    return X.fillna(0).values


def percentile_score(train_scores: np.ndarray, scores: np.ndarray) -> np.ndarray:
    ref = np.sort(train_scores)
    return np.searchsorted(ref, scores, side="right") / len(ref)


class AutoEncoder(nn.Module):
    def __init__(self, d: int):
        super().__init__()
        self.enc = nn.Sequential(nn.Linear(d, 32), nn.ReLU(), nn.Linear(32, 8), nn.ReLU())
        self.dec = nn.Sequential(nn.Linear(8, 32), nn.ReLU(), nn.Linear(32, d))

    def forward(self, x):
        return self.dec(self.enc(x))


class AnomalyModels:
    def __init__(self, cols, log_cols=None, seed: int = SEED):
        self.cols = list(cols)
        self.log_cols = None if log_cols is None else list(log_cols)
        self.seed = seed
        self.scaler = StandardScaler()
        self.iforest = IsolationForest(n_estimators=300, max_samples=4096, random_state=seed,
                                       n_jobs=-1)
        self.ae = None
        self.train_ref = {}

    # ---------- train ----------
    def fit(self, train: pd.DataFrame, ae_epochs: int = 30):
        X = self.scaler.fit_transform(to_matrix(train, self.cols, self.log_cols))
        self.iforest.fit(X)
        self._fit_ae(X, ae_epochs)
        self.train_ref = {"iforest": self._raw_iforest(X), "ae": self._raw_ae(X)}
        return self

    def _fit_ae(self, X, epochs):
        torch.manual_seed(self.seed)
        self.ae = AutoEncoder(X.shape[1])
        opt = torch.optim.Adam(self.ae.parameters(), lr=1e-3, weight_decay=1e-5)
        all_data = torch.tensor(X, dtype=torch.float32)
        # 10% giữ lại làm validation để theo dõi overfit (không dùng để cập nhật trọng số)
        idx = torch.randperm(len(all_data))
        n_val = max(1, len(all_data) // 10)
        val, data = all_data[idx[:n_val]], all_data[idx[n_val:]]
        self.history = []
        for ep in range(epochs):
            self.ae.train()
            perm = torch.randperm(len(data))
            total = 0.0
            for i in range(0, len(data), 1024):
                xb = data[perm[i:i + 1024]]
                loss = nn.functional.mse_loss(self.ae(xb), xb)
                opt.zero_grad()
                loss.backward()
                opt.step()
                total += loss.item() * len(xb)
            self.ae.eval()
            with torch.no_grad():
                val_loss = nn.functional.mse_loss(self.ae(val), val).item()
            self.history.append({"epoch": ep, "train_loss": total / len(data), "val_loss": val_loss})
            if ep % 10 == 0 or ep == epochs - 1:
                print(f"    AE epoch {ep:02d}: train_loss={total / len(data):.4f}  "
                      f"val_loss={val_loss:.4f}")

    # ---------- score ----------
    def _raw_iforest(self, X):
        return -self.iforest.score_samples(X)

    def _raw_ae(self, X):
        self.ae.eval()
        with torch.no_grad():
            x = torch.tensor(X, dtype=torch.float32)
            return ((self.ae(x) - x) ** 2).mean(dim=1).numpy()

    def score(self, feats: pd.DataFrame) -> pd.DataFrame:
        X = self.scaler.transform(to_matrix(feats, self.cols, self.log_cols))
        out = pd.DataFrame(index=feats.index)
        out["iforest_score"] = percentile_score(self.train_ref["iforest"], self._raw_iforest(X))
        out["ae_score"] = percentile_score(self.train_ref["ae"], self._raw_ae(X))
        return out

    # ---------- lưu / nạp ----------
    def save(self, name: str = "lanl"):
        joblib.dump({"cols": self.cols, "log_cols": self.log_cols, "scaler": self.scaler,
                     "iforest": self.iforest, "train_ref": self.train_ref,
                     "ae_loss_history": getattr(self, "history", [])},
                    MODELS_DIR / f"{name}_anomaly.joblib")
        torch.save(self.ae.state_dict(), MODELS_DIR / f"{name}_autoencoder.pt")

    @classmethod
    def load(cls, name: str = "lanl"):
        blob = joblib.load(MODELS_DIR / f"{name}_anomaly.joblib")
        m = cls(blob["cols"], blob.get("log_cols"))
        m.scaler, m.iforest, m.train_ref = blob["scaler"], blob["iforest"], blob["train_ref"]
        m.history = blob.get("ae_loss_history", [])
        m.ae = AutoEncoder(len(m.cols))
        m.ae.load_state_dict(torch.load(MODELS_DIR / f"{name}_autoencoder.pt"))
        return m
