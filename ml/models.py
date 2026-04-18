"""
ml/models.py
NIGHTWATCH Ensemble Inference

Loads the three trained models and runs weighted soft voting:
  RF (30%) + XGBoost (35%) + LightGBM (35%)

Usage:
    from ml.models import get_ensemble
    ensemble = get_ensemble()
    result   = ensemble.predict(features_dict)
"""

import os
import json
import numpy as np
import joblib
from typing import Dict, Any, Optional

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_models")

# Soft voting weights — XGBoost and LightGBM weighted slightly higher
# because gradient boosting generally outperforms RF on tabular data
WEIGHTS = {
    "RandomForest": 0.30,
    "XGBoost":      0.35,
    "LightGBM":     0.35,
}

# Decision threshold — probability >= this → predict attack
ATTACK_THRESHOLD = 0.50


class NightWatchEnsemble:
    """
    Loads and wraps all three trained models.
    Exposes a single predict() method for the engine to call.
    """

    def __init__(self):
        self.rf            = None
        self.xgb           = None
        self.lgbm          = None
        self.scaler        = None
        self.feature_names = None
        self.loaded        = False

    def load(self) -> bool:
        """
        Load models from disk.
        Returns True if successful, False if models not trained yet.
        """
        required = ["rf.joblib", "xgb.joblib", "lgbm.joblib",
                    "scaler.joblib", "feature_names.json"]

        for fname in required:
            if not os.path.exists(os.path.join(MODELS_DIR, fname)):
                return False   # models not trained yet — graceful fallback

        try:
            self.rf            = joblib.load(os.path.join(MODELS_DIR, "rf.joblib"))
            self.xgb           = joblib.load(os.path.join(MODELS_DIR, "xgb.joblib"))
            self.lgbm          = joblib.load(os.path.join(MODELS_DIR, "lgbm.joblib"))
            self.scaler        = joblib.load(os.path.join(MODELS_DIR, "scaler.joblib"))

            with open(os.path.join(MODELS_DIR, "feature_names.json")) as f:
                self.feature_names = json.load(f)

            self.loaded = True
            return True

        except Exception as e:
            print(f"[Ensemble] Warning: could not load models: {e}")
            return False

    def _features_to_vector(self, features: Dict[str, float]) -> np.ndarray:
        """
        Convert feature dict → numpy array in the correct column order.
        Missing features default to 0.0.
        """
        vec = np.array(
            [features.get(name, 0.0) for name in self.feature_names],
            dtype=np.float64
        )
        # Apply the same scaling used during training
        return self.scaler.transform(vec.reshape(1, -1))

    def predict(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Run the weighted soft voting ensemble.

        Args:
            features: dict from feature_extractor.extract()

        Returns:
            {
                "attack_probability": float,   # 0.0–1.0 (weighted average)
                "label": "attack" | "benign",
                "model_probabilities": {
                    "RandomForest": float,
                    "XGBoost": float,
                    "LightGBM": float,
                },
                "votes": {
                    "RandomForest": "attack" | "benign",
                    "XGBoost": "attack" | "benign",
                    "LightGBM": "attack" | "benign",
                },
                "agreement": "unanimous" | "majority" | "split",
            }
        """
        if not self.loaded:
            raise RuntimeError("Models not loaded. Call load() first.")

        X = self._features_to_vector(features)

        # Get attack probability from each model (index 1 = attack class)
        probs = {
            "RandomForest": float(self.rf.predict_proba(X)[0][1]),
            "XGBoost":      float(self.xgb.predict_proba(X)[0][1]),
            "LightGBM":     float(self.lgbm.predict_proba(X)[0][1]),
        }

        # Weighted soft vote
        attack_prob = sum(probs[name] * WEIGHTS[name] for name in probs)

        # Individual votes
        votes = {name: ("attack" if prob >= 0.5 else "benign") for name, prob in probs.items()}

        # Agreement level
        attack_votes = sum(1 for v in votes.values() if v == "attack")
        if attack_votes == 3:
            agreement = "unanimous_attack"
        elif attack_votes == 0:
            agreement = "unanimous_benign"
        elif attack_votes == 2:
            agreement = "majority_attack"
        else:
            agreement = "majority_benign"

        label = "attack" if attack_prob >= ATTACK_THRESHOLD else "benign"

        return {
            "attack_probability":  round(attack_prob, 4),
            "label":               label,
            "model_probabilities": {k: round(v, 4) for k, v in probs.items()},
            "votes":               votes,
            "agreement":           agreement,
        }


# ── Singleton pattern ─────────────────────────────────────────────────
# We load models once at startup and reuse the instance.
# This avoids reloading 3 models from disk on every request.

_ensemble_instance: Optional[NightWatchEnsemble] = None

def get_ensemble() -> NightWatchEnsemble:
    global _ensemble_instance
    if _ensemble_instance is None:
        _ensemble_instance = NightWatchEnsemble()
        _ensemble_instance.load()
    return _ensemble_instance
