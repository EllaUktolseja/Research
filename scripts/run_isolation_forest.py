#!/usr/bin/env python3
"""Run Isolation Forest for anomaly detection.
Supports comparative ablation study (Static vs Runtime vs Combined).
Calculates academic evaluation metrics (ROC-AUC, Precision, Recall, F1, FPR, Confusion Matrix)
against ground-truth reference labels (benign vs malicious).
"""

import argparse
import csv
import math
import random
from pathlib import Path
from typing import Any

try:
    from sklearn.ensemble import IsolationForest as SklearnIsolationForest
    from sklearn.metrics import roc_auc_score
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


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


def build_itree(X: list[list[float]], depth: int, max_depth: int, rng: random.Random) -> BuiltinITreeNode:
    n = len(X)
    if depth >= max_depth or n <= 1:
        return BuiltinITreeNode(size=n)

    n_features = len(X[0])
    valid_features = []
    for f in range(n_features):
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
        left=build_itree(left, depth + 1, max_depth, rng),
        right=build_itree(right, depth + 1, max_depth, rng),
        split_feature=q,
        split_value=p,
        size=n,
    )


def compute_path_length(x: list[float], node: BuiltinITreeNode, depth: int) -> float:
    if node.left is None or node.right is None:
        return depth + c_factor(node.size)
    if x[node.split_feature] < node.split_value:
        return compute_path_length(x, node.left, depth + 1)
    else:
        return compute_path_length(x, node.right, depth + 1)


class BuiltinIsolationForest:
    def __init__(self, n_estimators: int = 200, random_state: int = 42, contamination: float | None = None):
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.contamination = contamination
        self.trees: list[BuiltinITreeNode] = []
        self.c_n = 1.0

    def fit(self, X: list[list[float]]):
        rng = random.Random(self.random_state)
        n = len(X)
        self.c_n = c_factor(n)
        max_depth = math.ceil(math.log2(max(n, 2)))

        self.trees = []
        for _ in range(self.n_estimators):
            tree = build_itree(X, 0, max_depth, rng)
            self.trees.append(tree)
        return self

    def decision_function(self, X: list[list[float]]) -> list[float]:
        scores = []
        for x in X:
            avg_path = sum(compute_path_length(x, t, 0) for t in self.trees) / len(self.trees)
            if self.c_n > 0:
                raw_score = 2.0 ** (- (avg_path / self.c_n))
            else:
                raw_score = 0.5
            scores.append(0.5 - raw_score)
        return scores

    def predict(self, X: list[list[float]]) -> list[int]:
        scores = self.decision_function(X)
        if self.contamination and 0.0 < self.contamination < 0.5:
            k = max(1, int(len(scores) * self.contamination))
            threshold = sorted(scores)[k - 1]
        else:
            threshold = sorted(scores)[len(scores) // 4]
        return [-1 if s <= threshold else 1 for s in scores]


def calculate_roc_auc_pure(y_true: list[int], y_scores: list[float]) -> float | None:
    """Pure-Python ROC-AUC computation (y_scores: higher = more positive / anomalous)."""
    positives = sum(1 for y in y_true if y == 1)
    negatives = len(y_true) - positives
    if positives == 0 or negatives == 0:
        return None

    # Sort pairs by score descending
    paired = sorted(zip(y_scores, y_true), key=lambda p: p[0], reverse=True)
    tp = 0
    fp = 0
    prev_tp = 0
    prev_fp = 0
    auc = 0.0

    for score, label in paired:
        if label == 1:
            tp += 1
        else:
            fp += 1
            # Trapezoidal area under curve
            auc += (tp + prev_tp) / 2.0 * (fp - prev_fp)
            prev_tp = tp
            prev_fp = fp

    return round(auc / (positives * negatives), 4)


def evaluate_metrics(y_true_labels: list[str], preds: list[int], raw_scores: list[float]) -> dict[str, Any]:
    """
    Evaluasi performa deteksi terhadap ground truth:
    - Positive Class (1) = Malicious
    - Negative Class (0) = Benign
    Predictions: -1 = Outlier (Malicious), 1 = Inlier (Benign)
    """
    y_true = []
    has_both_classes = False
    labels_set = set(y_true_labels)
    if "malicious" in labels_set and "benign" in labels_set:
        has_both_classes = True

    for l in y_true_labels:
        y_true.append(1 if l == "malicious" else 0)

    # Inverted score: Isolation Forest output negatif = lebih anomali (malicious)
    # Untuk ROC-AUC, kita jadikan score tinggi = anomali
    anomaly_strength = [-s for s in raw_scores]

    tp = fp = tn = fn = 0
    for yt, p in zip(y_true, preds):
        yp = 1 if p == -1 else 0  # -1 outlier (malicious)
        if yt == 1 and yp == 1:
            tp += 1
        elif yt == 0 and yp == 1:
            fp += 1
        elif yt == 0 and yp == 0:
            tn += 1
        elif yt == 1 and yp == 0:
            fn += 1

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0

    roc_auc = None
    if has_both_classes:
        if HAS_SKLEARN:
            try:
                roc_auc = round(float(roc_auc_score(y_true, anomaly_strength)), 4)
            except Exception:
                roc_auc = calculate_roc_auc_pure(y_true, anomaly_strength)
        else:
            roc_auc = calculate_roc_auc_pure(y_true, anomaly_strength)

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "roc_auc": roc_auc if roc_auc is not None else "N/A (need benign & mal)",
    }


def load_dataset(features_file: Path) -> tuple[list[list[float]], list[str]]:
    with features_file.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        feature_columns = list(reader.fieldnames or [])
        X = []
        for row in reader:
            X.append([float(row.get(c, 0.0) or 0.0) for c in feature_columns])
    return X, feature_columns


def fit_and_predict(X: list[list[float]], contamination: float = 0.2, n_estimators: int = 200, random_state: int = 42):
    if HAS_SKLEARN:
        model = SklearnIsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=random_state)
        model.fit(X)
        scores = list(model.decision_function(X))
        predictions = list(model.predict(X))
    else:
        model = BuiltinIsolationForest(n_estimators=n_estimators, random_state=random_state, contamination=contamination)
        model.fit(X)
        scores = model.decision_function(X)
        predictions = model.predict(X)
    return scores, predictions


def main():
    parser = argparse.ArgumentParser(
        description="Run Isolation Forest with Ablation Comparison and Academic Evaluation Metrics."
    )
    parser.add_argument(
        "--features",
        type=Path,
        help="Path ke file numerik tunggal (misal results/features_model.csv)",
    )
    parser.add_argument(
        "--metadata",
        type=Path,
        help="Path ke file metadata (default: results/features_model_metadata.csv)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Path output hasil deteksi (default: results/isolation_forest_results.csv)",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        default=True,
        help="Jalankan komparasi 3 mode (Static only, Runtime only, Combined) (default: True)",
    )
    args = parser.parse_args()

    ROOT = Path(__file__).resolve().parent.parent
    RESULTS_DIR = ROOT / "results"

    METADATA_FILE = (
        args.metadata.resolve()
        if args.metadata
        else RESULTS_DIR / "features_model_metadata.csv"
    )

    if not METADATA_FILE.is_file():
        print(f"[ERROR] File metadata tidak ditemukan: {METADATA_FILE}")
        return

    with METADATA_FILE.open(newline="", encoding="utf-8-sig") as f:
        metadata_rows = list(csv.DictReader(f))

    num_samples = len(metadata_rows)
    if num_samples < 2:
        print("[ERROR] Minimal diperlukan 2 sampel untuk melatih model.")
        return

    # Hitung rasio kontaminasi malware riil jika ada
    ground_truth_labels = [m.get("reference_label", "").lower() for m in metadata_rows]
    mal_count = sum(1 for l in ground_truth_labels if l == "malicious")
    benign_count = sum(1 for l in ground_truth_labels if l == "benign")

    if mal_count > 0 and num_samples > 0:
        contamination_ratio = min(0.45, max(0.05, round(mal_count / num_samples, 2)))
    else:
        contamination_ratio = 0.2

    engine_name = "scikit-learn" if HAS_SKLEARN else "Built-in pure-Python IsolationForest"
    print(f"[INFO] Engine              : {engine_name}")
    print(f"[INFO] Total Sampel        : {num_samples} (Malicious: {mal_count}, Benign: {benign_count})")
    print(f"[INFO] Contamination Ratio : {contamination_ratio}")

    static_file = RESULTS_DIR / "features_model_static.csv"
    runtime_file = RESULTS_DIR / "features_model_runtime.csv"
    combined_file = RESULTS_DIR / "features_model_combined.csv"

    can_compare = static_file.is_file() and runtime_file.is_file() and combined_file.is_file()

    if args.compare and can_compare:
        print("\n" + "=" * 88)
        print(" EXPERIMENTAL ABLATION STUDY: ISOLATION FOREST COMPARISON ")
        print("=" * 88)

        # 1. Static / SBOM Model
        X_static, static_cols = load_dataset(static_file)
        scores_s, preds_s = fit_and_predict(X_static, contamination=contamination_ratio)
        eval_s = evaluate_metrics(ground_truth_labels, preds_s, scores_s)

        # 2. Runtime / eBPF Model
        X_runtime, runtime_cols = load_dataset(runtime_file)
        scores_r, preds_r = fit_and_predict(X_runtime, contamination=contamination_ratio)
        eval_r = evaluate_metrics(ground_truth_labels, preds_r, scores_r)

        # 3. Hybrid / Combined Model
        X_combined, combined_cols = load_dataset(combined_file)
        scores_c, preds_c = fit_and_predict(X_combined, contamination=contamination_ratio)
        eval_c = evaluate_metrics(ground_truth_labels, preds_c, scores_c)

        print(f"[1/3] Model Static / SBOM  : {len(static_cols)} fitur.")
        print(f"[2/3] Model Runtime / eBPF : {len(runtime_cols)} fitur.")
        print(f"[3/3] Model Hybrid Combined: {len(combined_cols)} fitur.")

        # Tampilkan tabel metrik evaluasi ilmiah untuk paper
        print("\n" + "=" * 88)
        print(" EVALUATION METRICS TABLE FOR PAPER (ABLATION COMPARISON) ")
        print("=" * 88)
        print(f"{'MODEL VARIANT':<24} | {'ROC-AUC':<10} | {'PRECISION':<10} | {'RECALL':<10} | {'F1-SCORE':<10} | {'FPR':<8}")
        print("-" * 88)
        print(f"{'Static + SBOM':<24} | {str(eval_s['roc_auc']):<10} | {eval_s['precision']:<10} | {eval_s['recall']:<10} | {eval_s['f1']:<10} | {eval_s['fpr']:<8}")
        print(f"{'Runtime eBPF':<24} | {str(eval_r['roc_auc']):<10} | {eval_r['precision']:<10} | {eval_r['recall']:<10} | {eval_r['f1']:<10} | {eval_r['fpr']:<8}")
        print(f"{'Hybrid (Combined)':<24} | {str(eval_c['roc_auc']):<10} | {eval_c['precision']:<10} | {eval_c['recall']:<10} | {eval_c['f1']:<10} | {eval_c['fpr']:<8}")
        print("-" * 88)

        # Simpan metrik paper ke CSV
        metrics_output = RESULTS_DIR / "ablation_metrics_paper.csv"
        with metrics_output.open("w", newline="", encoding="utf-8-sig") as f:
            fieldnames = ["variant", "roc_auc", "precision", "recall", "f1_score", "fpr", "tp", "fp", "tn", "fn"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow({"variant": "Static+SBOM", "roc_auc": eval_s["roc_auc"], "precision": eval_s["precision"], "recall": eval_s["recall"], "f1_score": eval_s["f1"], "fpr": eval_s["fpr"], "tp": eval_s["tp"], "fp": eval_s["fp"], "tn": eval_s["tn"], "fn": eval_s["fn"]})
            writer.writerow({"variant": "Runtime_eBPF", "roc_auc": eval_r["roc_auc"], "precision": eval_r["precision"], "recall": eval_r["recall"], "f1_score": eval_r["f1"], "fpr": eval_r["fpr"], "tp": eval_r["tp"], "fp": eval_r["fp"], "tn": eval_r["tn"], "fn": eval_r["fn"]})
            writer.writerow({"variant": "Hybrid_Combined", "roc_auc": eval_c["roc_auc"], "precision": eval_c["precision"], "recall": eval_c["recall"], "f1_score": eval_c["f1"], "fpr": eval_c["fpr"], "tp": eval_c["tp"], "fp": eval_c["fp"], "tn": eval_c["tn"], "fn": eval_c["fn"]})

        print(f"[OK] Metrik evaluasi paper disimpan di: {metrics_output}")

        comparison_results = []
        for i, meta in enumerate(metadata_rows):
            comparison_results.append({
                "id": meta.get("id", ""),
                "name": meta.get("name", "unknown"),
                "version": meta.get("version", "unknown"),
                "ground_truth": meta.get("reference_label", "unknown"),
                "score_static": round(float(scores_s[i]), 6),
                "label_static": "outlier" if preds_s[i] == -1 else "inlier",
                "score_runtime": round(float(scores_r[i]), 6),
                "label_runtime": "outlier" if preds_r[i] == -1 else "inlier",
                "score_hybrid": round(float(scores_c[i]), 6),
                "label_hybrid": "outlier" if preds_c[i] == -1 else "inlier",
            })

        comparison_results.sort(key=lambda r: r["score_hybrid"])

        comp_output = RESULTS_DIR / "isolation_forest_comparison.csv"
        with comp_output.open("w", newline="", encoding="utf-8-sig") as f:
            fieldnames = [
                "id", "name", "version", "ground_truth",
                "score_static", "label_static",
                "score_runtime", "label_runtime",
                "score_hybrid", "label_hybrid"
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(comparison_results)

        # Simpan default results
        default_output = args.output.resolve() if args.output else RESULTS_DIR / "isolation_forest_results.csv"
        with default_output.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "id", "name", "version", "ground_truth", "anomaly_score", "model_label", "interpretation"
            ])
            writer.writeheader()
            for r in comparison_results:
                writer.writerow({
                    "id": r["id"],
                    "name": r["name"],
                    "version": r["version"],
                    "ground_truth": r["ground_truth"],
                    "anomaly_score": r["score_hybrid"],
                    "model_label": ("potential_outlier" if r["label_hybrid"] == "outlier" else "inlier"),
                    "interpretation": "exploratory_hybrid_model",
                })

        print(f"[OK] Hasil perbandingan sampel disimpan di : {comp_output}")
        print(f"[OK] Hasil default disimpan di             : {default_output}")

        print("\n" + "-" * 98)
        print(f"{'ID':<4} {'PACKAGE NAME':<26} | {'LABEL':<10} | {'STATIC':<9} | {'RUNTIME':<9} | {'HYBRID':<9} | {'VERDICT':<8}")
        print("-" * 98)
        for r in comparison_results:
            name_cut = r["name"][:25]
            print(
                f"{r['id']:<4} {name_cut:<26} | "
                f"{r['ground_truth']:<10} | "
                f"{r['score_static']:<9.4f} | "
                f"{r['score_runtime']:<9.4f} | "
                f"{r['score_hybrid']:<9.4f} | "
                f"{r['label_hybrid']:<8}"
            )
        print("-" * 98)
        return

    # Fallback / Single mode
    features_path = args.features.resolve() if args.features else (
        combined_file if combined_file.is_file() else RESULTS_DIR / "features_model.csv"
    )
    if not features_path.is_file():
        print(f"[ERROR] File fitur tidak ditemukan: {features_path}")
        return

    X, cols = load_dataset(features_path)
    scores, preds = fit_and_predict(X, contamination=contamination_ratio)
    eval_single = evaluate_metrics(ground_truth_labels, preds, scores)

    print(f"\n[EVALUATION] Precision: {eval_single['precision']}, Recall: {eval_single['recall']}, F1: {eval_single['f1']}, ROC-AUC: {eval_single['roc_auc']}")


if __name__ == "__main__":
    main()
