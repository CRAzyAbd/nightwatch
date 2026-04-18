"""
ml/trainer.py
NIGHTWATCH Ensemble Trainer

Trains three models on data/dataset.csv:
  1. Random Forest      (sklearn)
  2. XGBoost            (gradient boosting, tree-based)
  3. LightGBM           (fast gradient boosting, Microsoft)

Then saves:
  ml/saved_models/rf.joblib
  ml/saved_models/xgb.joblib
  ml/saved_models/lgbm.joblib
  ml/saved_models/scaler.joblib     (StandardScaler for feature normalization)
  ml/saved_models/feature_names.json
  ml/saved_models/training_report.json

Run this script every time you get new training data.
"""

import os
import sys
import json
import warnings
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")   # non-interactive backend (no GUI needed)
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, f1_score, precision_score, recall_score
)
from sklearn.preprocessing import StandardScaler

import xgboost as xgb
import lightgbm as lgb

warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ─────────────────────────────────────────────────────────────────────
#  PATHS
# ─────────────────────────────────────────────────────────────────────

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH   = os.path.join(BASE_DIR, "data", "dataset.csv")
MODELS_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_models")
REPORTS_DIR = os.path.join(BASE_DIR, "data")


def _ensure_dirs():
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────
#  DATA LOADING
# ─────────────────────────────────────────────────────────────────────

def load_data():
    """
    Load dataset.csv, drop non-feature columns, split X/y.
    """
    print(f"\n[Trainer] Loading dataset: {DATA_PATH}")
    df = pd.read_csv(DATA_PATH)

    print(f"  Total rows    : {len(df)}")
    print(f"  Attack rows   : {df['label'].sum()}")
    print(f"  Benign rows   : {(df['label'] == 0).sum()}")
    print(f"  Columns       : {len(df.columns)}")

    # Drop columns that aren't ML features
    drop_cols = ["label", "attack_type"]
    feature_cols = [c for c in df.columns if c not in drop_cols]

    X = df[feature_cols].values
    y = df["label"].values

    return X, y, feature_cols


# ─────────────────────────────────────────────────────────────────────
#  MODEL DEFINITIONS
# ─────────────────────────────────────────────────────────────────────

def build_models():
    """
    Define all three models with tuned hyperparameters.

    Why these hyperparameters?
      - n_estimators=200: more trees = more stable predictions
      - max_depth limits overfitting (memorizing training data)
      - class_weight='balanced': handles class imbalance automatically
      - random_state=42: reproducible results
    """
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,              # use all CPU cores
        random_state=42,
    )

    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        verbosity=0,
    )

    lgbm_model = lgb.LGBMClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        num_leaves=31,
        subsample=0.8,
        colsample_bytree=0.8,
        class_weight="balanced",
        random_state=42,
        verbose=-1,
        feature_name="auto",
    )

    return {
        "RandomForest": rf,
        "XGBoost":      xgb_model,
        "LightGBM":     lgbm_model,
    }


# ─────────────────────────────────────────────────────────────────────
#  TRAINING + EVALUATION
# ─────────────────────────────────────────────────────────────────────

def train_and_evaluate(X_train, X_test, y_train, y_test, models: dict) -> dict:
    """
    Train each model, evaluate on test set, cross-validate.
    Returns a dict of results.
    """
    results = {}
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    for name, model in models.items():
        print(f"\n  ── Training {name} ──────────────────")

        # Train
        model.fit(X_train, y_train)

        # Predict
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1]

        # Metrics
        f1        = f1_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall    = recall_score(y_test, y_pred)
        roc_auc   = roc_auc_score(y_test, y_prob)

        # Cross-validation F1 score (5 folds)
        cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="f1", n_jobs=-1)

        print(f"  F1 Score  : {f1:.4f}")
        print(f"  Precision : {precision:.4f}  (of blocked requests, how many were real attacks)")
        print(f"  Recall    : {recall:.4f}  (of all attacks, how many did we catch)")
        print(f"  ROC-AUC   : {roc_auc:.4f}")
        print(f"  CV F1     : {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

        results[name] = {
            "model":      model,
            "f1":         f1,
            "precision":  precision,
            "recall":     recall,
            "roc_auc":    roc_auc,
            "cv_f1_mean": cv_scores.mean(),
            "cv_f1_std":  cv_scores.std(),
            "y_pred":     y_pred,
            "y_prob":     y_prob,
        }

    return results


# ─────────────────────────────────────────────────────────────────────
#  CONFUSION MATRIX PLOT
# ─────────────────────────────────────────────────────────────────────

def plot_confusion_matrices(results: dict, y_test):
    """Save confusion matrix plots for all three models."""
    fig, axes = plt.subplots(1, 3, figsize=(15, 4))
    fig.suptitle("NIGHTWATCH — Confusion Matrices (Phase 2)", fontsize=14, fontweight="bold")

    for ax, (name, res) in zip(axes, results.items()):
        cm = confusion_matrix(y_test, res["y_pred"])
        sns.heatmap(
            cm, annot=True, fmt="d", cmap="Blues", ax=ax,
            xticklabels=["Benign", "Attack"],
            yticklabels=["Benign", "Attack"],
        )
        ax.set_title(f"{name}\nF1={res['f1']:.3f}  AUC={res['roc_auc']:.3f}")
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")

    plt.tight_layout()
    out_path = os.path.join(REPORTS_DIR, "confusion_matrices.png")
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"\n[Trainer] Confusion matrices saved → {out_path}")


# ─────────────────────────────────────────────────────────────────────
#  SAVE MODELS
# ─────────────────────────────────────────────────────────────────────

def save_models(results: dict, scaler: StandardScaler, feature_names: list):
    """Save trained models and supporting artifacts."""
    print("\n[Trainer] Saving models...")

    # Save each model
    joblib.dump(results["RandomForest"]["model"], os.path.join(MODELS_DIR, "rf.joblib"))
    joblib.dump(results["XGBoost"]["model"],      os.path.join(MODELS_DIR, "xgb.joblib"))
    joblib.dump(results["LightGBM"]["model"],     os.path.join(MODELS_DIR, "lgbm.joblib"))

    # Save scaler (used to normalize features at inference time)
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.joblib"))

    # Save feature names (critical — must match what the engine sends at inference)
    with open(os.path.join(MODELS_DIR, "feature_names.json"), "w") as f:
        json.dump(feature_names, f, indent=2)

    # Save training report (for drift detection baseline in Phase 2)
    report = {
        "feature_names": feature_names,
        "models": {
            name: {
                "f1":         round(res["f1"], 4),
                "precision":  round(res["precision"], 4),
                "recall":     round(res["recall"], 4),
                "roc_auc":    round(res["roc_auc"], 4),
                "cv_f1_mean": round(res["cv_f1_mean"], 4),
                "cv_f1_std":  round(res["cv_f1_std"], 4),
            }
            for name, res in results.items()
        },
        # Baseline confidence distribution (for drift detection)
        "baseline_prob_mean": float(np.mean([
            np.mean(res["y_prob"]) for res in results.values()
        ])),
        "baseline_prob_std": float(np.std([
            np.std(res["y_prob"]) for res in results.values()
        ])),
    }

    with open(os.path.join(MODELS_DIR, "training_report.json"), "w") as f:
        json.dump(report, f, indent=2)

    print(f"  rf.joblib           → saved")
    print(f"  xgb.joblib          → saved")
    print(f"  lgbm.joblib         → saved")
    print(f"  scaler.joblib       → saved")
    print(f"  feature_names.json  → saved")
    print(f"  training_report.json → saved")


# ─────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────

def main():
    _ensure_dirs()

    print("=" * 60)
    print("  NIGHTWATCH — Phase 2 Ensemble Trainer")
    print("=" * 60)

    # ── Load data ─────────────────────────────────────────────────
    X, y, feature_names = load_data()

    # ── Scale features ────────────────────────────────────────────
    # StandardScaler: makes each feature have mean=0, std=1
    # This helps XGBoost and LightGBM converge faster.
    # RF doesn't need scaling but it doesn't hurt.
    scaler  = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ── Train/test split (80% train, 20% test) ────────────────────
    # stratify=y ensures both splits have the same attack/benign ratio
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )
    print(f"\n[Trainer] Train: {len(X_train)} samples | Test: {len(X_test)} samples")

    # ── Build + train models ──────────────────────────────────────
    models  = build_models()
    results = train_and_evaluate(X_train, X_test, y_train, y_test, models)

    # ── Summary ───────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  {'Model':<15} {'F1':>8} {'Precision':>10} {'Recall':>8} {'AUC':>8}")
    print(f"  {'-'*15} {'-'*8} {'-'*10} {'-'*8} {'-'*8}")
    for name, res in results.items():
        print(
            f"  {name:<15} {res['f1']:>8.4f} {res['precision']:>10.4f} "
            f"{res['recall']:>8.4f} {res['roc_auc']:>8.4f}"
        )

    # ── Ensemble voting explanation ───────────────────────────────
    print("\n  Ensemble voting (soft, weighted):")
    print("    RF 0.30 + XGBoost 0.35 + LightGBM 0.35")
    print("    Attack probability = weighted average of model probabilities")
    print("    Block threshold: probability >= 0.5")

    # ── Plots ─────────────────────────────────────────────────────
    plot_confusion_matrices(results, y_test)

    # ── Save ──────────────────────────────────────────────────────
    save_models(results, scaler, feature_names)

    print("\n[Trainer] ✅ Phase 2 training complete.")
    print(f"[Trainer] Models saved in: {MODELS_DIR}")


if __name__ == "__main__":
    main()
