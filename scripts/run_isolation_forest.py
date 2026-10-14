import csv
from pathlib import Path
from sklearn.ensemble import IsolationForest

INPUT = Path("results/features_model_with_identity.csv")
OUTPUT = Path("results/isolation_forest_results.csv")

# Baca CSV
with INPUT.open(newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

if len(rows) < 2:
    raise SystemExit("ERROR: Minimal diperlukan 2 sampel.")

# Pisahkan identitas dari fitur model
identity_columns = {"name", "version"}
feature_columns = [c for c in rows[0].keys() if c not in identity_columns]

# Pastikan fitur numerik
X = []
for row in rows:
    try:
        X.append([float(row[c]) for c in feature_columns])
    except (ValueError, TypeError):
        raise SystemExit("ERROR: Ada nilai fitur yang bukan numerik.")

# Baseline eksploratif, bukan classifier malware
model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)

model.fit(X)

# Skor lebih rendah = lebih anomali menurut model
scores = model.decision_function(X)
predictions = model.predict(X)

results = []
for row, score, prediction in zip(rows, scores, predictions):
    results.append(
        {
            "name": row["name"],
            "version": row["version"],
            "anomaly_score": round(float(score), 6),
            "model_label": ("potential_outlier" if prediction == -1 else "inlier"),
            "interpretation": "exploratory_only",
        }
    )

# Urutkan dari skor paling rendah
results.sort(key=lambda r: r["anomaly_score"])

with OUTPUT.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)

print(f"Samples: {len(rows)}")
print(f"Features: {len(feature_columns)}")
print(f"Saved: {OUTPUT}")
print("\nExploratory ranking (lower score = more anomalous):")

for row in results:
    print(
        f"{row['name']}@{row['version']}: "
        f"score={row['anomaly_score']}, "
        f"label={row['model_label']}"
    )

print("\nWARNING: Anomaly labels are not malware verdicts.")
