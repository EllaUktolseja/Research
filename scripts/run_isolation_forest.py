#!/usr/bin/env python3
"""Run Isolation Forest for anomaly detection.
Supports comparative ablation study (Static vs Runtime vs Combined).
Includes automatic fallback to built-in Isolation Forest if scikit-learn is not installed.
"""

import argparse
import csv
import math
import random
from pathlib import Path
from typing import Any

try:
    from sklearn.ensemble import IsolationForest as SklearnIsolationForest
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
    def __init__(self, n_estimators: int = 200, random_state: int = 42):
        self.n_estimators = n_estimators
        self.random_state = random_state
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
        # Return decision score matching scikit-learn convention:
        # higher score = normal (inlier), lower score (negative) = anomalous (outlier)
        scores = []
        for x in X:
            avg_path = sum(compute_path_length(x, t, 0) for t in self.trees) / len(self.trees)
            if self.c_n > 0:
                raw_score = 2.0 ** (- (avg_path / self.c_n))
            else:
                raw_score = 0.5
            # Sklearn decision_function is roughly 0.5 - raw_score
            scores.append(0.5 - raw_score)
        return scores

    def predict(self, X: list[list[float]]) -> list[int]:
        scores = self.decision_function(X)
        # Median threshold for auto contamination
        median_score = sorted(scores)[len(scores) // 4]  # flag bottom ~25% as outliers
        return [-1 if s <= median_score else 1 for s in scores]


def load_dataset(features_file: Path) -> tuple[list[list[float]], list[str]]:
    with features_file.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        feature_columns = list(reader.fieldnames or [])
        X = []
        for row in reader:
            X.append([float(row.get(c, 0.0) or 0.0) for c in feature_columns])
    return X, feature_columns


def fit_and_predict(X: list[list[float]], n_estimators: int = 200, random_state: int = 42):
    if HAS_SKLEARN:
        model = SklearnIsolationForest(n_estimators=n_estimators, contamination="auto", random_state=random_state)
        model.fit(X)
        scores = list(model.decision_function(X))
        predictions = list(model.predict(X))
    else:
        model = BuiltinIsolationForest(n_estimators=n_estimators, random_state=random_state)
        model.fit(X)
        scores = model.decision_function(X)
        predictions = model.predict(X)
    return scores, predictions


def main():
    parser = argparse.ArgumentParser(
        description="Run Isolation Forest with Ablation Comparison (Static vs eBPF vs Hybrid)."
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

    engine_name = "scikit-learn" if HAS_SKLEARN else "Built-in pure-Python IsolationForest"
    print(f"[INFO] Engine: {engine_name}")

    # Mode 1: Komparasi 3 Model (Static vs Runtime vs Combined)
    static_file = RESULTS_DIR / "features_model_static.csv"
    runtime_file = RESULTS_DIR / "features_model_runtime.csv"
    combined_file = RESULTS_DIR / "features_model_combined.csv"

    can_compare = static_file.is_file() and runtime_file.is_file() and combined_file.is_file()

    if args.compare and can_compare:
        print("\n" + "=" * 80)
        print(" EXPERIMENTAL ABLATION STUDY: ISOLATION FOREST COMPARISON ")
        print("=" * 80)

        # 1. Static / SBOM Model
        X_static, static_cols = load_dataset(static_file)
        scores_s, preds_s = fit_and_predict(X_static)
        print(f"[1/3] Model Static / SBOM  : {len(static_cols)} fitur dievaluasi.")

        # 2. Runtime / eBPF Model
        X_runtime, runtime_cols = load_dataset(runtime_file)
        scores_r, preds_r = fit_and_predict(X_runtime)
        print(f"[2/3] Model Runtime / eBPF : {len(runtime_cols)} fitur dievaluasi.")

        # 3. Hybrid / Combined Model
        X_combined, combined_cols = load_dataset(combined_file)
        scores_c, preds_c = fit_and_predict(X_combined)
        print(f"[3/3] Model Hybrid Combined: {len(combined_cols)} fitur dievaluasi.")

        comparison_results = []
        for i, meta in enumerate(metadata_rows):
            comparison_results.append({
                "id": meta.get("id", ""),
                "name": meta.get("name", "unknown"),
                "version": meta.get("version", "unknown"),
                "score_static": round(float(scores_s[i]), 6),
                "label_static": "outlier" if preds_s[i] == -1 else "inlier",
                "score_runtime": round(float(scores_r[i]), 6),
                "label_runtime": "outlier" if preds_r[i] == -1 else "inlier",
                "score_hybrid": round(float(scores_c[i]), 6),
                "label_hybrid": "outlier" if preds_c[i] == -1 else "inlier",
            })

        # Urutkan berdasarkan skor hybrid terendah (paling anomali)
        comparison_results.sort(key=lambda r: r["score_hybrid"])

        comp_output = RESULTS_DIR / "isolation_forest_comparison.csv"
        with comp_output.open("w", newline="", encoding="utf-8-sig") as f:
            fieldnames = [
                "id", "name", "version",
                "score_static", "label_static",
                "score_runtime", "label_runtime",
                "score_hybrid", "label_hybrid"
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(comparison_results)

        # Simpan juga default results.csv (pakai hasil hybrid)
        default_output = args.output.resolve() if args.output else RESULTS_DIR / "isolation_forest_results.csv"
        with default_output.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "id", "name", "version", "anomaly_score", "model_label", "interpretation"
            ])
            writer.writeheader()
            for r in comparison_results:
                writer.writerow({
                    "id": r["id"],
                    "name": r["name"],
                    "version": r["version"],
                    "anomaly_score": r["score_hybrid"],
                    "model_label": ("potential_outlier" if r["label_hybrid"] == "outlier" else "inlier"),
                    "interpretation": "exploratory_hybrid_model",
                })

        print(f"\n[OK] Hasil komparasi tersimpan di: {comp_output}")
        print(f"[OK] Hasil default tersimpan di   : {default_output}")

        # Tampilkan tabel perbandingan di konsol
        print("\n" + "-" * 98)
        print(f"{'ID':<4} {'PACKAGE NAME':<30} | {'STATIC':<10} | {'RUNTIME':<10} | {'HYBRID':<10} | {'VERDICT':<8}")
        print("-" * 98)
        for r in comparison_results:
            name_cut = r["name"][:29]
            print(
                f"{r['id']:<4} {name_cut:<30} | "
                f"{r['score_static']:<10.4f} | "
                f"{r['score_runtime']:<10.4f} | "
                f"{r['score_hybrid']:<10.4f} | "
                f"{r['label_hybrid']:<8}"
            )
        print("-" * 98)
        print("Catatan: Skor lebih rendah (negatif) menunjukkan tingkat anomali yang lebih tinggi.")
        return

    # Fallback / Single Mode
    features_path = args.features.resolve() if args.features else (
        combined_file if combined_file.is_file() else RESULTS_DIR / "features_model.csv"
    )
    if not features_path.is_file():
        print(f"[ERROR] File fitur tidak ditemukan: {features_path}")
        return

    X, cols = load_dataset(features_path)
    scores, preds = fit_and_predict(X)

    results = []
    for meta, score, pred in zip(metadata_rows, scores, preds):
        results.append({
            "id": meta.get("id", ""),
            "name": meta.get("name", "unknown"),
            "version": meta.get("version", "unknown"),
            "anomaly_score": round(float(score), 6),
            "model_label": "potential_outlier" if pred == -1 else "inlier",
            "interpretation": "exploratory_only",
        })

    results.sort(key=lambda r: r["anomaly_score"])
    output_path = args.output.resolve() if args.output else RESULTS_DIR / "isolation_forest_results.csv"
    with output_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    print(f"\n[OK] Hasil prediksi disimpan di: {output_path}")


if __name__ == "__main__":
    main()
