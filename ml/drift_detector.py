"""
ml/drift_detector.py
NIGHTWATCH Model Drift Detector

What is concept drift?
  Your model is trained on today's attack patterns.
  Attackers evolve. In 6 months, new payload types emerge.
  The model starts seeing inputs unlike anything it trained on
  → its confidence drops → its accuracy silently degrades.

This module:
  1. Loads the baseline confidence distribution from training
  2. Tracks live prediction confidences in a rolling window
  3. Alerts when the rolling mean drifts significantly from baseline

How to use:
  After each ML prediction, call:
    drift_detector.record(attack_probability)

  Periodically call:
    drift_detector.check()  → returns alert if drift detected
"""

import os
import json
import math
from collections import deque
from typing import Dict, Any, Optional

MODELS_DIR    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_models")
REPORT_PATH   = os.path.join(MODELS_DIR, "training_report.json")

# Rolling window size — how many recent predictions to track
WINDOW_SIZE   = 500

# Alert threshold — how many standard deviations from baseline = drift
DRIFT_Z_SCORE = 2.5


class DriftDetector:
    """
    Monitors prediction confidence over a rolling window.
    Compares against the baseline established during training.
    """

    def __init__(self):
        self.window          = deque(maxlen=WINDOW_SIZE)
        self.baseline_mean   = None
        self.baseline_std    = None
        self.total_recorded  = 0
        self.alerts_fired    = 0
        self._loaded         = False

    def load_baseline(self) -> bool:
        """Load baseline confidence stats from training report."""
        if not os.path.exists(REPORT_PATH):
            return False
        try:
            with open(REPORT_PATH) as f:
                report = json.load(f)
            self.baseline_mean = report.get("baseline_prob_mean")
            self.baseline_std  = report.get("baseline_prob_std") or 0.1
            self._loaded = True
            return True
        except Exception:
            return False

    def record(self, attack_probability: float) -> None:
        """Record a new prediction probability into the rolling window."""
        self.window.append(attack_probability)
        self.total_recorded += 1

    def check(self) -> Dict[str, Any]:
        """
        Check the current window for drift.

        Returns a status dict. If drift is detected, 'alert' will be True
        and 'message' will explain the situation.
        """
        if not self._loaded:
            self.load_baseline()

        if len(self.window) < 50:
            return {
                "alert":   False,
                "status":  "insufficient_data",
                "message": f"Need 50+ samples in window (have {len(self.window)}). Keep running.",
                "window_mean": None,
            }

        window_mean = sum(self.window) / len(self.window)
        window_std  = math.sqrt(
            sum((x - window_mean) ** 2 for x in self.window) / len(self.window)
        )

        if self.baseline_mean is None:
            return {
                "alert":       False,
                "status":      "no_baseline",
                "message":     "No training baseline found. Run trainer.py first.",
                "window_mean": round(window_mean, 4),
            }

        # Z-score: how many standard deviations is the current mean from baseline?
        std = max(self.baseline_std, 0.01)   # avoid division by zero
        z_score = abs(window_mean - self.baseline_mean) / std

        drift_detected = z_score >= DRIFT_Z_SCORE

        if drift_detected:
            self.alerts_fired += 1

        return {
            "alert":          drift_detected,
            "status":         "drift_detected" if drift_detected else "stable",
            "window_mean":    round(window_mean, 4),
            "baseline_mean":  round(self.baseline_mean, 4),
            "z_score":        round(z_score, 4),
            "message": (
                f"⚠ DRIFT DETECTED: window mean={window_mean:.3f}, "
                f"baseline={self.baseline_mean:.3f}, z={z_score:.2f}. "
                f"Consider retraining on new data."
            ) if drift_detected else (
                f"Model stable. Window mean={window_mean:.3f} "
                f"(baseline={self.baseline_mean:.3f}, z={z_score:.2f})"
            ),
            "window_size":    len(self.window),
            "total_recorded": self.total_recorded,
            "alerts_fired":   self.alerts_fired,
        }

    def status_summary(self) -> str:
        """Return a one-line human-readable status."""
        result = self.check()
        return result["message"]


# ── Singleton ─────────────────────────────────────────────────────────
_detector: Optional[DriftDetector] = None

def get_detector() -> DriftDetector:
    global _detector
    if _detector is None:
        _detector = DriftDetector()
        _detector.load_baseline()
    return _detector
