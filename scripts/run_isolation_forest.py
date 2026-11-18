#!/usr/bin/env python3
"""Run Isolation Forest ablation study (Static vs Runtime vs Hybrid).

Uses Stratified K-Fold Out-of-Fold (OOF) evaluation to prevent data leakage,
compares Feature-Level Concatenation and Late Score-Level Fusion,
and reports ROC-AUC, PR-AUC, Precision, Recall, F1, FPR, and MCC (mean ± std).
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import random
import statistics
import tempfile
from pathlib import Path
from typing import Any

try:
    from sklearn.ensemble import IsolationForest as SklearnIsolationForest
    from sklearn.metrics import average_precision_score, roc_auc_score

    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_RESULTS_DIR = ROOT_DIR / "results"


class BuiltinITreeNode:
    def __init__(self, left=None, right=None, split_feature=None, split_value=None, size=1):
        self.left = left
        self.right = right
        self.split_feature = split_feature
        self.split_value = split_value
        self.size = size


def c_factor(n: int) -> float:
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)


def build_itree(
    X: list[list[float]],
    depth: int,
    max_depth: int,
    rng: random.Random,
    feature_indices: list[int],
) -> BuiltinITreeNode:
    n = len(X)
    if depth >= max_depth or n <= 1:
        return BuiltinITreeNode(size=n)

    valid_features = []
    for f in feature_indices:
        vals = [row[f] for row in X]
        if min(vals) < max(vals):
            valid_features.append(f)

    if not valid_features:
        return BuiltinITreeNode(size=n)

    q = rng.choice(valid_features)
    vals = [row[q] for row in X]
    p = rng.uniform(min(vals), max(vals))

    left = [row for row in X if row[q] < p]
    right = [row for row in X if row[q] >= p]

    return BuiltinITreeNode(
        left=build_itree(left, depth + 1, max_depth, rng, feature_indices),
        right=build_itree(right, depth + 1, max_depth, rng, feature_indices),
        split_feature=q,
        split_value=p,
        size=n,
    )


def compute_path_length(x: list[float], node: BuiltinITreeNode, depth: int) -> float:
    if node.left is None or node.right is None:
        return depth + c_factor(node.size)
    if x[node.split_feature] < node.split_value:
        return compute_path_length(x, node.left, depth + 1)
    return compute_path_length(x, node.right, depth + 1)


class BuiltinIsolationForest:
    """Pure-Python Isolation Forest implementing Liu et al. (2008) subsampling."""

    def __init__(
        self,
        n_estimators: int = 300,
        max_samples: int = 256,
        max_features: float = 0.8,
        contamination: float | None = None,
        random_state: int = 42,
    ):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.max_features = max_features
        self.contamination = contamination
        self.random_state = random_state
        self.trees: list[BuiltinITreeNode] = []
        self.c_n = 1.0
        self.offset_ = 0.0

    def fit(self, X: list[list[float]]):
        rng = random.Random(self.random_state)
        n = len(X)
        n_features = len(X[0]) if n > 0 else 0
        subsample_size = min(self.max_samples, n)
        feat_sub_size = max(1, min(n_features, int(round(n_features * self.max_features))))

        self.c_n = c_factor(subsample_size)
        max_depth = math.ceil(math.log2(max(subsample_size, 2)))

        self.trees = []
        for _ in range(self.n_estimators):
            sample_subset = rng.sample(X, subsample_size) if subsample_size < n else list(X)
            feat_subset = (
                rng.sample(range(n_features), feat_sub_size)
                if feat_sub_size < n_features
                else list(range(n_features))
            )
            self.trees.append(build_itree(sample_subset, 0, max_depth, rng, feat_subset))

        raw_train_scores = self.score_samples(X)
        if self.contamination is not None and 0.0 < self.contamination <= 0.5:
            sorted_s = sorted(raw_train_scores)
            idx = max(0, min(len(sorted_s) - 1, int(math.floor(len(sorted_s) * self.contamination))))
            self.offset_ = sorted_s[idx]
        else:
            self.offset_ = -0.5
        return self

    def score_samples(self, X: list[list[float]]) -> list[float]:
        scores = []
        for x in X:
            avg_path = sum(compute_path_length(x, t, 0) for t in self.trees) / len(self.trees)
            raw_anom = 2.0 ** (-(avg_path / self.c_n)) if self.c_n > 0 else 0.5
            scores.append(-raw_anom)
        return scores

    def decision_function(self, X: list[list[float]]) -> list[float]:
        return [s - self.offset_ for s in self.score_samples(X)]

    def predict(self, X: list[list[float]]) -> list[int]:
        return [-1 if d < 0.0 else 1 for d in self.decision_function(X)]


def calculate_roc_auc_pure(y_true: list[int], y_scores: list[float]) -> float | None:
    positives = sum(1 for y in y_true if y == 1)
    negatives = len(y_true) - positives
    if positives == 0 or negatives == 0:
        return None

    paired = sorted(zip(y_scores, y_true), key=lambda p: p[0], reverse=True)
    tp = fp = prev_tp = prev_fp = 0
    auc = 0.0

    for _, label in paired:
        if label == 1:
            tp += 1
        else:
            fp += 1
            auc += (tp + prev_tp) / 2.0 * (fp - prev_fp)
            prev_tp = tp
            prev_fp = fp

    return auc / (positives * negatives)


def calculate_pr_auc_pure(y_true: list[int], y_scores: list[float]) -> float | None:
    positives = sum(1 for y in y_true if y == 1)
    if positives == 0 or positives == len(y_true):
        return None

    paired = sorted(zip(y_scores, y_true), key=lambda p: p[0], reverse=True)
    tp = fp = 0
    ap = 0.0
    for _, label in paired:
        if label == 1:
            tp += 1
            ap += tp / (tp + fp)
        else:
            fp += 1
    return ap / positives


def compute_metrics(
    y_true: list[int],
    preds: list[int],
    decision_scores: list[float],
) -> dict[str, Any]:
    anomaly_strength = [-s for s in decision_scores]

    tp = fp = tn = fn = 0
    for yt, p in zip(y_true, preds):
        yp = 1 if p == -1 else 0
        if yt == 1 and yp == 1:
            tp += 1
        elif yt == 0 and yp == 1:
            fp += 1
        elif yt == 0 and yp == 0:
            tn += 1
        elif yt == 1 and yp == 0:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    mcc_denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / mcc_denom if mcc_denom > 0 else 0.0

    roc_auc = None
    pr_auc = None
    if len(set(y_true)) == 2:
        if HAS_SKLEARN:
            try:
                roc_auc = float(roc_auc_score(y_true, anomaly_strength))
                pr_auc = float(average_precision_score(y_true, anomaly_strength))
            except Exception:
                roc_auc = calculate_roc_auc_pure(y_true, anomaly_strength)
                pr_auc = calculate_pr_auc_pure(y_true, anomaly_strength)
        else:
            roc_auc = calculate_roc_auc_pure(y_true, anomaly_strength)
            pr_auc = calculate_pr_auc_pure(y_true, anomaly_strength)

    return {
        "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
        "pr_auc": round(pr_auc, 4) if pr_auc is not None else None,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "mcc": round(mcc, 4),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def make_stratified_folds(y_true: list[int], n_folds: int, seed: int) -> list[list[int]]:
    rng = random.Random(seed)
    pos_idx = [i for i, y in enumerate(y_true) if y == 1]
    neg_idx = [i for i, y in enumerate(y_true) if y == 0]
    rng.shuffle(pos_idx)
    rng.shuffle(neg_idx)

    folds: list[list[int]] = [[] for _ in range(n_folds)]
    for idx, sample_i in enumerate(pos_idx):
        folds[idx % n_folds].append(sample_i)
    for idx, sample_i in enumerate(neg_idx):
        folds[idx % n_folds].append(sample_i)

    for f in folds:
        f.sort()
    return folds


def build_model(contamination: float, n_estimators: int, max_features: float, seed: int):
    if HAS_SKLEARN:
        return SklearnIsolationForest(
            n_estimators=n_estimators,
            max_samples="auto",
            contamination=contamination,
            max_features=max_features,
            random_state=seed,
            n_jobs=-1,
        )
    return BuiltinIsolationForest(
        n_estimators=n_estimators,
        max_samples=256,
        max_features=max_features,
        contamination=contamination,
        random_state=seed,
    )


def summarize_folds(
    y_true: list[int],
    oof_scores: list[float],
    oof_preds: list[int],
    fold_metrics: list[dict[str, Any]],
    effective_folds: int,
) -> dict[str, Any]:
    oof_overall = compute_metrics(y_true, oof_preds, oof_scores)
    summary_stats: dict[str, Any] = {}
    for metric_key in ("roc_auc", "pr_auc", "precision", "recall", "f1", "fpr", "mcc"):
        vals = [m[metric_key] for m in fold_metrics if m[metric_key] is not None]
        if vals:
            mean_v = statistics.mean(vals)
            std_v = statistics.stdev(vals) if len(vals) > 1 else 0.0
            summary_stats[f"{metric_key}_mean"] = round(mean_v, 4)
            summary_stats[f"{metric_key}_std"] = round(std_v, 4)
        else:
            summary_stats[f"{metric_key}_mean"] = None
            summary_stats[f"{metric_key}_std"] = None

    return {
        "effective_folds": effective_folds,
        "oof_overall": oof_overall,
        "cv_summary": summary_stats,
        "oof_scores": oof_scores,
        "oof_preds": oof_preds,
    }


def evaluate_variant_oof(
    X: list[list[float]],
    y_true: list[int],
    n_folds: int,
    n_estimators: int,
    max_features: float,
    seed: int,
    train_benign_only: bool = False,
    benign_fpr_target: float = 0.05,
) -> dict[str, Any]:
    n = len(X)
    pos_total = sum(y_true)
    neg_total = n - pos_total
    min_class = min(pos_total, neg_total)
    effective_folds = min(n_folds, min_class) if min_class >= 2 else 1

    oof_scores = [0.0] * n
    oof_preds = [1] * n
    fold_metrics: list[dict[str, Any]] = []

    if effective_folds >= 2:
        folds = make_stratified_folds(y_true, effective_folds, seed)
        for fold_id, test_idx in enumerate(folds):
            test_set = set(test_idx)
            train_idx = [i for i in range(n) if i not in test_set]

            if train_benign_only:
                X_train = [X[i] for i in train_idx if y_true[i] == 0]
                contam = min(0.49, max(0.01, benign_fpr_target))
            else:
                X_train = [X[i] for i in train_idx]
                y_train = [y_true[i] for i in train_idx]
                train_mal_ratio = sum(y_train) / max(1, len(y_train))
                contam = min(0.49, max(0.01, train_mal_ratio))

            X_test = [X[i] for i in test_idx]
            y_test = [y_true[i] for i in test_idx]

            model = build_model(contam, n_estimators, max_features, seed + fold_id)
            model.fit(X_train)

            scores_test = [float(s) for s in model.decision_function(X_test)]
            preds_test = [int(p) for p in model.predict(X_test)]

            for idx_pos, orig_i in enumerate(test_idx):
                oof_scores[orig_i] = scores_test[idx_pos]
                oof_preds[orig_i] = preds_test[idx_pos]

            fold_metrics.append(compute_metrics(y_test, preds_test, scores_test))
    else:
        if train_benign_only and neg_total > 0:
            X_train = [X[i] for i in range(n) if y_true[i] == 0]
            contam = min(0.49, max(0.01, benign_fpr_target))
        else:
            X_train = X
            raw_ratio = pos_total / max(1, n)
            contam = min(0.49, max(0.01, raw_ratio if raw_ratio > 0 else 0.1))

        model = build_model(contam, n_estimators, max_features, seed)
        model.fit(X_train)
        oof_scores = [float(s) for s in model.decision_function(X)]
        oof_preds = [int(p) for p in model.predict(X)]
        fold_metrics.append(compute_metrics(y_true, oof_preds, oof_scores))

    return summarize_folds(y_true, oof_scores, oof_preds, fold_metrics, effective_folds)


def evaluate_score_fusion_oof(
    X_static: list[list[float]],
    X_runtime: list[list[float]],
    y_true: list[int],
    n_folds: int,
    n_estimators: int,
    max_features: float,
    seed: int,
    train_benign_only: bool = False,
    benign_fpr_target: float = 0.05,
    static_weight: float = 0.7,
) -> dict[str, Any]:
    """Late score-level fusion of independent Static IF and Runtime IF models (leak-free)."""
    n = len(y_true)
    pos_total = sum(y_true)
    neg_total = n - pos_total
    min_class = min(pos_total, neg_total)
    effective_folds = min(n_folds, min_class) if min_class >= 2 else 1
    runtime_weight = 1.0 - static_weight

    oof_scores = [0.0] * n
    oof_preds = [1] * n
    fold_metrics: list[dict[str, Any]] = []

    folds = (
        make_stratified_folds(y_true, effective_folds, seed)
        if effective_folds >= 2
        else [list(range(n))]
    )

    for fold_id, test_idx in enumerate(folds):
        test_set = set(test_idx)
        train_idx = [i for i in range(n) if i not in test_set] if effective_folds >= 2 else list(range(n))

        if train_benign_only:
            fit_idx = [i for i in train_idx if y_true[i] == 0]
            contam = min(0.49, max(0.01, benign_fpr_target))
        else:
            fit_idx = train_idx
            y_train = [y_true[i] for i in train_idx]
            contam = min(0.49, max(0.01, sum(y_train) / max(1, len(y_train))))

        Xs_fit = [X_static[i] for i in fit_idx]
        Xr_fit = [X_runtime[i] for i in fit_idx]
        Xs_test = [X_static[i] for i in test_idx]
        Xr_test = [X_runtime[i] for i in test_idx]
        y_test = [y_true[i] for i in test_idx]

        model_s = build_model(contam, n_estimators, max_features, seed + fold_id)
        model_r = build_model(contam, n_estimators, max_features, seed + 1000 + fold_id)
        model_s.fit(Xs_fit)
        model_r.fit(Xr_fit)

        s_fit_scores = [float(s) for s in model_s.decision_function(Xs_fit)]
        r_fit_scores = [float(s) for s in model_r.decision_function(Xr_fit)]
        s_test_scores = [float(s) for s in model_s.decision_function(Xs_test)]
        r_test_scores = [float(s) for s in model_r.decision_function(Xr_test)]

        s_mean = statistics.mean(s_fit_scores)
        s_std = statistics.stdev(s_fit_scores) if len(s_fit_scores) > 1 else 1.0
        s_std = s_std if s_std > 1e-9 else 1.0

        r_mean = statistics.mean(r_fit_scores)
        r_std = statistics.stdev(r_fit_scores) if len(r_fit_scores) > 1 else 1.0
        r_std = r_std if r_std > 1e-9 else 1.0

        fit_fused = [
            static_weight * ((s - s_mean) / s_std) + runtime_weight * ((r - r_mean) / r_std)
            for s, r in zip(s_fit_scores, r_fit_scores)
        ]
        sorted_fit = sorted(fit_fused)
        q_idx = max(0, min(len(sorted_fit) - 1, int(math.floor(len(sorted_fit) * contam))))
        threshold = sorted_fit[q_idx]

        test_fused_centered = [
            (static_weight * ((s - s_mean) / s_std) + runtime_weight * ((r - r_mean) / r_std)) - threshold
            for s, r in zip(s_test_scores, r_test_scores)
        ]
        preds_test = [-1 if d < 0.0 else 1 for d in test_fused_centered]

        for idx_pos, orig_i in enumerate(test_idx):
            oof_scores[orig_i] = test_fused_centered[idx_pos]
            oof_preds[orig_i] = preds_test[idx_pos]

        fold_metrics.append(compute_metrics(y_test, preds_test, test_fused_centered))

    return summarize_folds(y_true, oof_scores, oof_preds, fold_metrics, effective_folds)


def compute_feature_attribution(
    X: list[list[float]],
    feature_names: list[str],
    y_true: list[int],
    n_estimators: int,
    max_features: float,
    seed: int,
    train_benign_only: bool = False,
    benign_fpr_target: float = 0.05,
) -> list[dict[str, Any]]:
    n = len(X)
    pos_idx = [i for i, y in enumerate(y_true) if y == 1]
    neg_idx = [i for i, y in enumerate(y_true) if y == 0]

    if train_benign_only and neg_idx:
        X_train = [X[i] for i in neg_idx]
        contam = min(0.49, max(0.01, benign_fpr_target))
    else:
        X_train = X
        raw_ratio = len(pos_idx) / max(1, n)
        contam = min(0.49, max(0.01, raw_ratio if raw_ratio > 0 else 0.1))

    model = build_model(contam, n_estimators, max_features, seed)
    model.fit(X_train)

    target_idx = pos_idx if pos_idx else list(range(n))
    X_target = [X[i] for i in target_idx]
    base_scores = [float(s) for s in model.decision_function(X_target)]

    attribution_rows: list[dict[str, Any]] = []
    for f_idx, fname in enumerate(feature_names):
        X_ablated = [list(row) for row in X_target]
        for row in X_ablated:
            row[f_idx] = 0.0
        ablated_scores = [float(s) for s in model.decision_function(X_ablated)]

        mean_shift = statistics.mean(a - b for a, b in zip(ablated_scores, base_scores))

        mal_rate = (
            sum(1 for i in pos_idx if X[i][f_idx] > 0.0) / len(pos_idx)
            if pos_idx
            else 0.0
        )
        ben_rate = (
            sum(1 for i in neg_idx if X[i][f_idx] > 0.0) / len(neg_idx)
            if neg_idx
            else 0.0
        )
        modality = "runtime_ebpf" if fname.startswith(("rt_", "runtime_")) else "static_sbom"

        attribution_rows.append(
            {
                "feature": fname,
                "modality": modality,
                "anomaly_score_contribution": round(mean_shift, 6),
                "malicious_active_rate": round(mal_rate, 4),
                "benign_active_rate": round(ben_rate, 4),
                "rate_lift": round(mal_rate - ben_rate, 4),
            }
        )

    attribution_rows.sort(key=lambda r: r["anomaly_score_contribution"], reverse=True)
    return attribution_rows


def load_dataset(features_file: Path) -> tuple[list[list[float]], list[str]]:
    with features_file.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        feature_columns = [c.strip() for c in (reader.fieldnames or []) if c is not None]
        X: list[list[float]] = []
        for row in reader:
            X.append([float(row.get(c, 0.0) or 0.0) for c in feature_columns])
    return X, feature_columns


def atomic_write_csv(output_path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8-sig",
        newline="",
        dir=str(output_path.parent),
        prefix=f".{output_path.stem}_",
        suffix=".tmp",
        delete=False,
    ) as tmp_file:
        tmp_path = Path(tmp_file.name)
        writer = csv.DictWriter(tmp_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        tmp_file.flush()
        os.fsync(tmp_file.fileno())

    os.replace(tmp_path, output_path)


def format_mean_std(summary: dict[str, Any], key: str) -> str:
    m = summary.get(f"{key}_mean")
    s = summary.get(f"{key}_std")
    if m is None:
        return "N/A"
    return f"{m:.4f}±{s:.4f}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Isolation Forest ablation study with Out-of-Fold evaluation."
    )
    parser.add_argument(
        "--features",
        type=Path,
        default=None,
        help="Path ke file fitur tunggal (otomatis mengaktifkan mode single jika diisi)",
    )
    parser.add_argument(
        "--metadata",
        type=Path,
        default=None,
        help="Path ke file metadata (default: results/features_model_metadata.csv)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_RESULTS_DIR,
        help="Direktori output hasil eksperimen (default: results/)",
    )
    parser.add_argument(
        "--folds",
        type=int,
        default=5,
        help="Jumlah Stratified K-Fold untuk evaluasi Out-of-Fold (default: 5)",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=300,
        help="Jumlah pohon iTree dalam forest (default: 300)",
    )
    parser.add_argument(
        "--max-features",
        type=float,
        default=0.8,
        help="Proporsi subset fitur per pohon untuk mengurangi dilution (default: 0.8)",
    )
    parser.add_argument(
        "--train-benign-only",
        action="store_true",
        help="Latih Isolation Forest hanya pada sampel benign (semi-supervised novelty detection)",
    )
    parser.add_argument(
        "--benign-fpr",
        type=float,
        default=0.05,
        help="Target FPR pada data benign jika memakai --train-benign-only (default: 0.05)",
    )
    parser.add_argument(
        "--static-weight",
        type=float,
        default=0.7,
        help="Bobot skor Static IF pada Hybrid Score Fusion (default: 0.7)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed utama untuk reproduktibilitas (default: 42)",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=25,
        help="Jumlah sampel paling anomali yang ditampilkan di terminal (default: 25)",
    )
    args = parser.parse_args()

    results_dir = args.output_dir.expanduser().resolve()
    metadata_file = (
        args.metadata.expanduser().resolve()
        if args.metadata
        else results_dir / "features_model_metadata.csv"
    )

    if not metadata_file.is_file():
        print(f"[ERROR] File metadata tidak ditemukan: {metadata_file}")
        return

    with metadata_file.open("r", encoding="utf-8-sig", newline="") as f:
        metadata_rows = list(csv.DictReader(f))

    num_samples = len(metadata_rows)
    if num_samples < 4:
        print("[ERROR] Minimal diperlukan 4 sampel untuk menjalankan evaluasi.")
        return

    ground_truth_labels = [m.get("reference_label", "").strip().lower() for m in metadata_rows]
    y_true = [1 if lbl == "malicious" else 0 for lbl in ground_truth_labels]
    mal_count = sum(y_true)
    benign_count = num_samples - mal_count

    engine_name = "scikit-learn" if HAS_SKLEARN else "Built-in pure-Python IsolationForest"
    fit_regime = (
        f"Semi-supervised (benign-only, target FPR={args.benign_fpr})"
        if args.train_benign_only
        else "Unsupervised (natural mixture, leak-free train contamination)"
    )

    print(f"[INFO] Engine              : {engine_name}")
    print(f"[INFO] Total Sampel        : {num_samples} (Malicious: {mal_count}, Benign: {benign_count})")
    print(f"[INFO] Regime Training     : {fit_regime}")
    print(f"[INFO] Hyperparameters     : n_estimators={args.n_estimators}, max_features={args.max_features}, folds={args.folds}, seed={args.seed}")

    if args.features is not None:
        features_path = args.features.expanduser().resolve()
        if not features_path.is_file():
            print(f"[ERROR] File fitur tidak ditemukan: {features_path}")
            return
        X, cols = load_dataset(features_path)
        res = evaluate_variant_oof(
            X,
            y_true,
            n_folds=args.folds,
            n_estimators=args.n_estimators,
            max_features=args.max_features,
            seed=args.seed,
            train_benign_only=args.train_benign_only,
            benign_fpr_target=args.benign_fpr,
        )
        ov = res["oof_overall"]
        print(
            f"\n[OOF EVALUATION - {features_path.name} ({len(cols)} fitur)] "
            f"ROC-AUC: {ov['roc_auc']} | PR-AUC: {ov['pr_auc']} | "
            f"Precision: {ov['precision']} | Recall: {ov['recall']} | "
            f"F1: {ov['f1']} | FPR: {ov['fpr']} | MCC: {ov['mcc']}"
        )
        return

    static_file = results_dir / "features_model_static.csv"
    runtime_file = results_dir / "features_model_runtime.csv"
    combined_file = results_dir / "features_model_combined.csv"

    variants: list[tuple[str, Path]] = []
    if static_file.is_file():
        variants.append(("Static + SBOM", static_file))
    if runtime_file.is_file():
        variants.append(("Runtime eBPF", runtime_file))
    if combined_file.is_file():
        variants.append(("Hybrid (Concat)", combined_file))

    if not variants:
        print(f"[ERROR] Tidak ada dataset model (features_model_*.csv) di {results_dir}")
        return

    print("\n" + "=" * 114)
    print(" EXPERIMENTAL ABLATION STUDY: OUT-OF-FOLD ISOLATION FOREST EVALUATION ")
    print("=" * 114)

    variant_results: dict[str, dict[str, Any]] = {}
    metrics_csv_rows: list[dict[str, Any]] = []

    for label_name, fpath in variants:
        X, cols = load_dataset(fpath)
        if not cols or len(X) != num_samples:
            print(f"[WARNING] Melewati {label_name}: jumlah baris/kolom tidak cocok dengan metadata.")
            continue

        res = evaluate_variant_oof(
            X,
            y_true,
            n_folds=args.folds,
            n_estimators=args.n_estimators,
            max_features=args.max_features,
            seed=args.seed,
            train_benign_only=args.train_benign_only,
            benign_fpr_target=args.benign_fpr,
        )
        res["feature_count"] = len(cols)
        res["feature_names"] = cols
        res["X"] = X
        variant_results[label_name] = res

    if "Static + SBOM" in variant_results and "Runtime eBPF" in variant_results:
        s_res = variant_results["Static + SBOM"]
        r_res = variant_results["Runtime eBPF"]
        fusion_res = evaluate_score_fusion_oof(
            s_res["X"],
            r_res["X"],
            y_true,
            n_folds=args.folds,
            n_estimators=args.n_estimators,
            max_features=args.max_features,
            seed=args.seed,
            train_benign_only=args.train_benign_only,
            benign_fpr_target=args.benign_fpr,
            static_weight=args.static_weight,
        )
        fusion_res["feature_count"] = s_res["feature_count"] + r_res["feature_count"]
        variant_results["Hybrid (Score Fusion)"] = fusion_res

    for label_name, res in variant_results.items():
        ov = res["oof_overall"]
        cv = res["cv_summary"]
        metrics_csv_rows.append(
            {
                "variant": label_name,
                "num_features": res["feature_count"],
                "folds": res["effective_folds"],
                "oof_roc_auc": ov["roc_auc"],
                "oof_pr_auc": ov["pr_auc"],
                "oof_precision": ov["precision"],
                "oof_recall": ov["recall"],
                "oof_f1": ov["f1"],
                "oof_fpr": ov["fpr"],
                "oof_mcc": ov["mcc"],
                "cv_roc_auc_mean": cv["roc_auc_mean"],
                "cv_roc_auc_std": cv["roc_auc_std"],
                "cv_pr_auc_mean": cv["pr_auc_mean"],
                "cv_pr_auc_std": cv["pr_auc_std"],
                "cv_f1_mean": cv["f1_mean"],
                "cv_f1_std": cv["f1_std"],
                "tp": ov["tp"],
                "fp": ov["fp"],
                "tn": ov["tn"],
                "fn": ov["fn"],
            }
        )

    print(
        f"{'MODEL VARIANT':<22} | {'FEAT':<4} | {'OOF ROC-AUC':<11} | {'OOF PR-AUC':<10} | "
        f"{'PREC':<7} | {'REC':<7} | {'F1':<7} | {'FPR':<7} | {'MCC':<7}"
    )
    print("-" * 114)
    for row in metrics_csv_rows:
        print(
            f"{row['variant']:<22} | {row['num_features']:<4} | "
            f"{str(row['oof_roc_auc']):<11} | {str(row['oof_pr_auc']):<10} | "
            f"{row['oof_precision']:<7.4f} | {row['oof_recall']:<7.4f} | "
            f"{row['oof_f1']:<7.4f} | {row['oof_fpr']:<7.4f} | {row['oof_mcc']:<7.4f}"
        )
    print("-" * 114)

    print("\n--- Cross-Validation Stability (Mean ± Std across folds) ---")
    for label_name, res in variant_results.items():
        cv = res["cv_summary"]
        print(
            f"{label_name:<22} | ROC-AUC: {format_mean_std(cv, 'roc_auc'):<13} | "
            f"PR-AUC: {format_mean_std(cv, 'pr_auc'):<13} | F1: {format_mean_std(cv, 'f1'):<13}"
        )

    metrics_output = results_dir / "ablation_metrics_paper.csv"
    if metrics_csv_rows:
        atomic_write_csv(metrics_output, list(metrics_csv_rows[0].keys()), metrics_csv_rows)
        print(f"\n[OK] Metrik evaluasi paper disimpan di     : {metrics_output}")

    static_res = variant_results.get("Static + SBOM")
    runtime_res = variant_results.get("Runtime eBPF")
    hybrid_res = (
        variant_results.get("Hybrid (Score Fusion)")
        or variant_results.get("Hybrid (Concat)")
        or static_res
    )

    comparison_results: list[dict[str, Any]] = []
    for i, meta in enumerate(metadata_rows):
        s_score = round(static_res["oof_scores"][i], 6) if static_res else 0.0
        s_label = ("outlier" if static_res["oof_preds"][i] == -1 else "inlier") if static_res else "n/a"

        r_score = round(runtime_res["oof_scores"][i], 6) if runtime_res else 0.0
        r_label = ("outlier" if runtime_res["oof_preds"][i] == -1 else "inlier") if runtime_res else "n/a"

        h_score = round(hybrid_res["oof_scores"][i], 6) if hybrid_res else 0.0
        h_label = ("outlier" if hybrid_res["oof_preds"][i] == -1 else "inlier") if hybrid_res else "n/a"

        comparison_results.append(
            {
                "id": meta.get("id", ""),
                "name": meta.get("name", "unknown"),
                "ground_truth": meta.get("reference_label", "unknown"),
                "score_static": s_score,
                "label_static": s_label,
                "score_runtime": r_score,
                "label_runtime": r_label,
                "score_hybrid": h_score,
                "label_hybrid": h_label,
            }
        )

    comparison_results.sort(key=lambda r: r["score_hybrid"])

    comp_output = results_dir / "isolation_forest_comparison.csv"
    comp_fields = [
        "id",
        "name",
        "ground_truth",
        "score_static",
        "label_static",
        "score_runtime",
        "label_runtime",
        "score_hybrid",
        "label_hybrid",
    ]
    atomic_write_csv(comp_output, comp_fields, comparison_results)
    print(f"[OK] Hasil perbandingan OOF disimpan di    : {comp_output}")

    concat_res = variant_results.get("Hybrid (Concat)")
    if concat_res is not None:
        attr_rows = compute_feature_attribution(
            concat_res["X"],
            concat_res["feature_names"],
            y_true,
            n_estimators=args.n_estimators,
            max_features=args.max_features,
            seed=args.seed,
            train_benign_only=args.train_benign_only,
            benign_fpr_target=args.benign_fpr,
        )
        attr_output = results_dir / "feature_importance_paper.csv"
        if attr_rows:
            atomic_write_csv(attr_output, list(attr_rows[0].keys()), attr_rows)
            print(f"[OK] Kontribusi fitur paper disimpan di    : {attr_output}")

            print("\n--- Top 10 Fitur Paling Berkontribusi Menangkap Malware ---")
            for ar in attr_rows[:10]:
                print(
                    f"  {ar['feature']:<36} [{ar['modality']:<12}] "
                    f"shift={ar['anomaly_score_contribution']:+.5f} "
                    f"(mal={ar['malicious_active_rate']:.1%} vs ben={ar['benign_active_rate']:.1%})"
                )

    shown = comparison_results[: max(1, args.top_k)]
    print(f"\n--- Top {len(shown)} Sampel Paling Anomali (Out-of-Fold Hybrid Score) ---")
    print("-" * 102)
    print(
        f"{'ID':<5} {'PACKAGE NAME':<28} | {'LABEL':<10} | "
        f"{'STATIC':<9} | {'RUNTIME':<9} | {'HYBRID':<9} | {'VERDICT':<8}"
    )
    print("-" * 102)
    for r in shown:
        print(
            f"{r['id']:<5} {r['name'][:27]:<28} | "
            f"{r['ground_truth']:<10} | "
            f"{r['score_static']:<9.4f} | "
            f"{r['score_runtime']:<9.4f} | "
            f"{r['score_hybrid']:<9.4f} | "
            f"{r['label_hybrid']:<8}"
        )
    print("-" * 102)


if __name__ == "__main__":
    main()
