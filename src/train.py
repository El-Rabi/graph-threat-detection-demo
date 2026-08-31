"""Train and evaluate an interpretable session-level threat detector."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split


def train_and_evaluate(features: pd.DataFrame, results_dir: Path, seed: int = 42) -> dict[str, float]:
    X = features.drop(columns=["session_id", "label"])
    y = (features["label"] == "attack").astype(int)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=seed, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=250,
        min_samples_leaf=3,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    cv = cross_validate(
        model,
        X_train,
        y_train,
        cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=seed),
        scoring={"roc_auc": "roc_auc", "f1": "f1"},
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    prediction = model.predict(X_test)
    probability = model.predict_proba(X_test)[:, 1]
    metrics = {
        "test_accuracy": float(accuracy_score(y_test, prediction)),
        "test_precision": float(precision_score(y_test, prediction, zero_division=0)),
        "test_recall": float(recall_score(y_test, prediction, zero_division=0)),
        "test_f1": float(f1_score(y_test, prediction, zero_division=0)),
        "test_roc_auc": float(roc_auc_score(y_test, probability)),
        "cv_roc_auc_mean": float(np.mean(cv["test_roc_auc"])),
        "cv_f1_mean": float(np.mean(cv["test_f1"])),
        "test_sessions": int(len(y_test)),
        "test_attack_rate": float(y_test.mean()),
    }

    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    importance = pd.DataFrame(
        {"feature": X.columns, "importance": model.feature_importances_}
    ).sort_values("importance", ascending=False)
    importance.to_csv(results_dir / "feature_importance.csv", index=False)

    fig, ax = plt.subplots(figsize=(6, 5))
    ConfusionMatrixDisplay.from_predictions(
        y_test, prediction, display_labels=["benign", "attack"], cmap="Blues", colorbar=False, ax=ax
    )
    ax.set_title("Synthetic session confusion matrix")
    fig.tight_layout()
    fig.savefig(results_dir / "confusion_matrix.png", dpi=160)
    plt.close(fig)

    false_positive_rate, true_positive_rate, _ = roc_curve(y_test, probability)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(false_positive_rate, true_positive_rate, label=f"ROC-AUC = {metrics['test_roc_auc']:.3f}")
    ax.plot([0, 1], [0, 1], linestyle="--", color="grey")
    ax.set(xlabel="False-positive rate", ylabel="True-positive rate", title="Threat detection ROC curve")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(results_dir / "roc_curve.png", dpi=160)
    plt.close(fig)

    top = importance.head(10).sort_values("importance")
    fig, ax = plt.subplots(figsize=(8, 5.5))
    ax.barh(top["feature"], top["importance"], color="#6A4C93")
    ax.set(xlabel="Random Forest importance", title="Top session-level features")
    fig.tight_layout()
    fig.savefig(results_dir / "feature_importance.png", dpi=160)
    plt.close(fig)
    return metrics
