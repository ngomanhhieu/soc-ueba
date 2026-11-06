"""A4 – Mô hình phát hiện bất thường không giám sát: Isolation Forest (chính),
Autoencoder (PyTorch; tự fallback sang sklearn MLP nếu chưa cài torch), LOF.

Mọi model trả về điểm "càng cao càng bất thường".
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

from common import COUNT_FEATURES


class Prep:
    """log1p cho feature đếm + StandardScaler (fit trên train)."""

    def __init__(self, features):
        self.features = list(features)

    def _x(self, df):
        x = df[self.features].astype(float).to_numpy(copy=True)
        for i, c in enumerate(self.features):
            if c in COUNT_FEATURES:
                x[:, i] = np.log1p(np.clip(x[:, i], 0, None))
        return np.nan_to_num(x)

    def fit(self, df):
        self.sc = StandardScaler().fit(self._x(df))
        return self

    def transform(self, df):
        return np.clip(self.sc.transform(self._x(df)), -10, 10)


class IFModel:
    def __init__(self, n_estimators=300, max_samples=256, max_features=1.0,
                 contamination="auto", seed=42):
        self.m = IsolationForest(n_estimators=n_estimators, max_samples=max_samples,
                                 max_features=max_features, contamination=contamination,
                                 random_state=seed, n_jobs=-1)

    def fit(self, X):
        self.m.fit(X)
        return self

    def score(self, X):
        return -self.m.score_samples(X)


class LOFModel:
    def __init__(self, n_neighbors=20, max_train=50_000, seed=42):
        self.k, self.max_train, self.seed = n_neighbors, max_train, seed

    def fit(self, X):
        if len(X) > self.max_train:
            X = X[np.random.default_rng(self.seed).choice(len(X), self.max_train, replace=False)]
        self.m = LocalOutlierFactor(n_neighbors=self.k, novelty=True, n_jobs=-1).fit(X)
        return self

    def score(self, X):
        return -self.m.score_samples(X)


class AEModel:
    """Autoencoder d -> 32 -> 16 -> bottleneck -> 16 -> 32 -> d; điểm = lỗi tái tạo MSE."""

    def __init__(self, bottleneck=4, epochs=30, batch=1024, lr=1e-3, seed=42):
        self.b, self.epochs, self.batch, self.lr, self.seed = bottleneck, epochs, batch, lr, seed
        try:
            import torch  # noqa: F401
            self.backend = "torch"
        except ImportError:
            self.backend = "sklearn"

    def fit(self, X, verbose=False):
        if self.backend == "sklearn":
            import warnings

            from sklearn.exceptions import ConvergenceWarning
            from sklearn.neural_network import MLPRegressor
            warnings.filterwarnings("ignore", category=ConvergenceWarning)
            self.m = MLPRegressor(hidden_layer_sizes=(32, 16, self.b, 16, 32), max_iter=self.epochs * 4,
                                  batch_size=min(self.batch, len(X)), learning_rate_init=self.lr,
                                  early_stopping=True, random_state=self.seed).fit(X, X)
            return self
        import torch
        from torch import nn
        torch.manual_seed(self.seed)
        d = X.shape[1]
        self.m = nn.Sequential(nn.Linear(d, 32), nn.ReLU(), nn.Linear(32, 16), nn.ReLU(),
                               nn.Linear(16, self.b), nn.ReLU(),
                               nn.Linear(self.b, 16), nn.ReLU(), nn.Linear(16, 32), nn.ReLU(),
                               nn.Linear(32, d))
        opt = torch.optim.Adam(self.m.parameters(), lr=self.lr)
        Xt = torch.tensor(X, dtype=torch.float32)
        n_val = max(1, int(0.1 * len(Xt)))
        perm = torch.randperm(len(Xt))
        Xv, Xtr = Xt[perm[:n_val]], Xt[perm[n_val:]]
        best, best_state, patience = np.inf, None, 0
        for ep in range(self.epochs):
            self.m.train()
            order = torch.randperm(len(Xtr))
            for i in range(0, len(Xtr), self.batch):
                xb = Xtr[order[i:i + self.batch]]
                opt.zero_grad()
                loss = ((self.m(xb) - xb) ** 2).mean()
                loss.backward()
                opt.step()
            self.m.eval()
            with torch.no_grad():
                vl = ((self.m(Xv) - Xv) ** 2).mean().item()
            if verbose:
                print(f"    AE epoch {ep + 1}: val_mse={vl:.4f}")
            if vl < best - 1e-4:
                best, patience = vl, 0
                best_state = {k: v.clone() for k, v in self.m.state_dict().items()}
            else:
                patience += 1
                if patience >= 5:
                    break
        if best_state:
            self.m.load_state_dict(best_state)
        return self

    def score(self, X):
        if self.backend == "sklearn":
            return ((self.m.predict(X) - X) ** 2).mean(axis=1)
        import torch
        self.m.eval()
        with torch.no_grad():
            Xt = torch.tensor(X, dtype=torch.float32)
            out = [((self.m(Xt[i:i + 65536]) - Xt[i:i + 65536]) ** 2).mean(1)
                   for i in range(0, len(Xt), 65536)]
        return torch.cat(out).numpy()

    def __getstate__(self):  # để joblib lưu được model torch
        s = self.__dict__.copy()
        if self.backend == "torch":
            import io

            import torch
            buf = io.BytesIO()
            torch.save(self.m, buf)
            s["m"] = buf.getvalue()
        return s

    def __setstate__(self, s):
        self.__dict__.update(s)
        if s.get("backend") == "torch" and isinstance(s["m"], bytes):
            import io

            import torch
            self.m = torch.load(io.BytesIO(s["m"]), weights_only=False)


class ECDF:
    """Chuẩn hoá điểm về [0,1] theo phân phối điểm trên train (percentile rank)."""

    def fit(self, s):
        self.ref = np.sort(np.asarray(s, dtype=float))
        return self

    def __call__(self, s):
        return np.searchsorted(self.ref, np.asarray(s, dtype=float), side="right") / len(self.ref)


def to_frame(scores: dict[str, np.ndarray], index) -> pd.DataFrame:
    return pd.DataFrame(scores, index=index)
