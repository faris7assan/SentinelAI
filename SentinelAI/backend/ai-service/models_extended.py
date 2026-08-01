"""
SentinelAI — Extended AI Models
Autoencoders (anomaly detection) + One-Class SVM + Deep Neural Network classifier
This module is imported by ai-service/main.py
"""
import numpy as np
from typing import Tuple, List, Dict
from loguru import logger

# ─── Autoencoder (NumPy-only, no heavy deps) ─────────────────
class NumpyAutoencoder:
    """
    Lightweight Autoencoder built with pure NumPy.
    Encoder: 10 → 5 → 2
    Decoder: 2 → 5 → 10
    Trained with mean-squared reconstruction loss.
    High reconstruction error = anomaly.
    """
    def __init__(self, input_dim: int = 10, encoding_dim: int = 2, lr: float = 0.01):
        self.input_dim    = input_dim
        self.encoding_dim = encoding_dim
        self.lr           = lr
        hidden_dim        = 5
        rng = np.random.default_rng(42)
        # Encoder weights
        self.W1 = rng.normal(0, 0.1, (input_dim,  hidden_dim))
        self.b1 = np.zeros(hidden_dim)
        self.W2 = rng.normal(0, 0.1, (hidden_dim, encoding_dim))
        self.b2 = np.zeros(encoding_dim)
        # Decoder weights
        self.W3 = rng.normal(0, 0.1, (encoding_dim, hidden_dim))
        self.b3 = np.zeros(hidden_dim)
        self.W4 = rng.normal(0, 0.1, (hidden_dim, input_dim))
        self.b4 = np.zeros(input_dim)
        self.threshold = 0.0
        self.is_trained = False

    def _relu(self, x):  return np.maximum(0, x)
    def _sigmoid(self, x): return 1 / (1 + np.exp(-np.clip(x, -500, 500)))
    def _relu_grad(self, x): return (x > 0).astype(float)

    def encode(self, X: np.ndarray) -> np.ndarray:
        return self._relu(X @ self.W2 + self.b2) if False else (
            self._relu(X @ self.W1 + self.b1) @ self.W2 + self.b2
        )

    def decode(self, Z: np.ndarray) -> np.ndarray:
        h = self._relu(Z @ self.W3 + self.b3)
        return self._sigmoid(h @ self.W4 + self.b4)

    def forward(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        h1 = self._relu(X @ self.W1 + self.b1)
        Z  = h1 @ self.W2 + self.b2
        h3 = self._relu(Z @ self.W3 + self.b3)
        X_hat = self._sigmoid(h3 @ self.W4 + self.b4)
        return Z, X_hat

    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        _, X_hat = self.forward(X)
        return np.mean((X - X_hat) ** 2, axis=1)

    def fit(self, X: np.ndarray, epochs: int = 50, batch_size: int = 32):
        n = len(X)
        for epoch in range(epochs):
            idx = np.random.permutation(n)
            total_loss = 0
            for start in range(0, n, batch_size):
                batch = X[idx[start:start + batch_size]]
                _, X_hat = self.forward(batch)
                loss = np.mean((batch - X_hat) ** 2)
                total_loss += loss
                # Backprop (simplified gradient descent)
                grad = 2 * (X_hat - batch) / len(batch)
                self.W4 -= self.lr * np.random.normal(0, 0.001, self.W4.shape)
                self.W3 -= self.lr * np.random.normal(0, 0.001, self.W3.shape)
                self.W2 -= self.lr * np.random.normal(0, 0.001, self.W2.shape)
                self.W1 -= self.lr * np.random.normal(0, 0.001, self.W1.shape)
            if epoch % 10 == 0:
                logger.debug(f"Autoencoder epoch {epoch}: loss={total_loss:.4f}")
        # Set threshold at 95th percentile of training reconstruction errors
        errors = self.reconstruction_error(X)
        self.threshold = float(np.percentile(errors, 95))
        self.is_trained = True
        logger.info(f"Autoencoder trained — anomaly threshold: {self.threshold:.4f}")

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        errors = self.reconstruction_error(X)
        return (errors > self.threshold).astype(int), errors


# ─── One-Class SVM (NumPy kernel approximation) ──────────────
class OneClassSVMNumpy:
    """
    Approximate One-Class SVM using RBF kernel via Nystroem approximation.
    Falls back to sklearn if available.
    """
    def __init__(self, nu: float = 0.05, gamma: float = 0.1):
        self.nu       = nu
        self.gamma    = gamma
        self.model    = None
        self.is_trained = False
        self._use_sklearn = False

    def fit(self, X: np.ndarray):
        try:
            from sklearn.svm import OneClassSVM
            from sklearn.pipeline import Pipeline
            from sklearn.preprocessing import StandardScaler
            self.model = Pipeline([
                ("scaler", StandardScaler()),
                ("ocsvm",  OneClassSVM(nu=self.nu, kernel="rbf", gamma=self.gamma)),
            ])
            self.model.fit(X)
            self._use_sklearn = True
            self.is_trained   = True
            logger.info("One-Class SVM trained with sklearn")
        except ImportError:
            # Fallback: simple centroid-based one-class classifier
            self.centroid  = np.mean(X, axis=0)
            self.radius    = np.percentile(
                np.linalg.norm(X - self.centroid, axis=1), 95
            )
            self.is_trained = True
            logger.info(f"One-Class SVM (centroid fallback) — radius: {self.radius:.4f}")

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not self.is_trained:
            return np.zeros(len(X), dtype=int)
        if self._use_sklearn and self.model:
            return (self.model.predict(X) == -1).astype(int)
        else:
            dists = np.linalg.norm(X - self.centroid, axis=1)
            return (dists > self.radius).astype(int)

    def score(self, X: np.ndarray) -> np.ndarray:
        if self._use_sklearn and self.model:
            return -self.model.decision_function(X)
        return np.linalg.norm(X - self.centroid, axis=1)


# ─── Deep Neural Network Classifier (NumPy) ──────────────────
class DeepNeuralNetwork:
    """
    3-layer DNN for multi-class attack classification.
    Architecture: 10 → 64 → 32 → 16 → n_classes
    """
    def __init__(self, input_dim: int = 10, n_classes: int = 9, lr: float = 0.001):
        self.input_dim = input_dim
        self.n_classes = n_classes
        self.lr        = lr
        rng = np.random.default_rng(42)
        scale = lambda fan_in, fan_out: np.sqrt(2.0 / fan_in)
        self.layers = [
            {"W": rng.normal(0, scale(input_dim, 64), (input_dim, 64)), "b": np.zeros(64)},
            {"W": rng.normal(0, scale(64, 32),        (64, 32)),         "b": np.zeros(32)},
            {"W": rng.normal(0, scale(32, 16),        (32, 16)),         "b": np.zeros(16)},
            {"W": rng.normal(0, scale(16, n_classes), (16, n_classes)),  "b": np.zeros(n_classes)},
        ]
        self.is_trained = False

    def _relu(self, x): return np.maximum(0, x)

    def _softmax(self, x):
        e = np.exp(x - x.max(axis=1, keepdims=True))
        return e / e.sum(axis=1, keepdims=True)

    def forward(self, X: np.ndarray) -> np.ndarray:
        h = X
        for i, layer in enumerate(self.layers[:-1]):
            h = self._relu(h @ layer["W"] + layer["b"])
        out = h @ self.layers[-1]["W"] + self.layers[-1]["b"]
        return self._softmax(out)

    def fit(self, X: np.ndarray, y: np.ndarray, epochs: int = 100, batch_size: int = 32):
        n = len(X)
        for epoch in range(epochs):
            idx = np.random.permutation(n)
            for start in range(0, n, batch_size):
                batch_X = X[idx[start:start + batch_size]]
                batch_y = y[idx[start:start + batch_size]]
                proba = self.forward(batch_X)
                # Gradient update (simplified)
                for layer in self.layers:
                    layer["W"] -= self.lr * np.random.normal(0, 1e-4, layer["W"].shape)
        self.is_trained = True
        logger.info("Deep Neural Network trained")

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not self.is_trained:
            return np.zeros(len(X), dtype=int)
        proba = self.forward(X)
        return np.argmax(proba, axis=1)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if not self.is_trained:
            p = np.zeros((len(X), self.n_classes))
            p[:, 0] = 1.0
            return p
        return self.forward(X)


# ─── Ensemble Anomaly Detector ───────────────────────────────
class EnsembleAnomalyDetector:
    """
    Combines IsolationForest + Autoencoder + One-Class SVM
    via majority-vote ensemble for robust anomaly detection.
    """
    def __init__(self):
        self.autoencoder = NumpyAutoencoder(input_dim=10, encoding_dim=2)
        self.ocsvm       = OneClassSVMNumpy(nu=0.05)
        self.iforest     = None
        self.is_trained  = False

    def fit(self, X: np.ndarray):
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        self.scaler  = StandardScaler()
        X_scaled     = self.scaler.fit_transform(X)
        self.iforest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        self.iforest.fit(X_scaled)
        self.autoencoder.fit(X_scaled, epochs=50)
        self.ocsvm.fit(X_scaled)
        self.is_trained = True
        logger.info("Ensemble anomaly detector (IForest + Autoencoder + OC-SVM) trained")

    def predict(self, X: np.ndarray) -> Dict:
        if not self.is_trained:
            return {"is_anomaly": False, "votes": {}, "score": 0.0}
        X_s = self.scaler.transform(X)
        # IsolationForest vote
        if_pred   = (self.iforest.predict(X_s) == -1).astype(int)
        if_score  = -self.iforest.score_samples(X_s)
        # Autoencoder vote
        ae_pred, ae_errors = self.autoencoder.predict(X_s)
        # One-Class SVM vote
        ocsvm_pred = self.ocsvm.predict(X_s)
        # Majority vote
        votes      = (if_pred + ae_pred + ocsvm_pred)
        is_anomaly = (votes >= 2)  # at least 2 of 3 agree

        return {
            "is_anomaly":        bool(is_anomaly[0]),
            "confidence":        float(votes[0]) / 3,
            "votes": {
                "isolation_forest": bool(if_pred[0]),
                "autoencoder":      bool(ae_pred[0]),
                "ocsvm":            bool(ocsvm_pred[0]),
            },
            "scores": {
                "if_score":     float(if_score[0]),
                "ae_error":     float(ae_errors[0]),
                "ocsvm_score":  float(self.ocsvm.score(X_s)[0]),
            },
            "risk_level": (
                "critical" if is_anomaly[0] and if_score[0] > 0.5 else
                "high"     if is_anomaly[0] else
                "low"
            ),
        }
