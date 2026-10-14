import csv
from pathlib import Path

ROOT = Path.home() / "malware-research"
INPUT = ROOT / "results/features.csv"
OUTPUT = ROOT / "results/features_model.csv"
METADATA = ROOT / "results/features_model_metadata.csv"

IDENTIFIERS = {
    "name",
    "version",
    "package_dir",
    "feature_file",
}

with INPUT.open(newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

if not rows:
    raise SystemExit("ERROR: Dataset kosong.")

metadata_columns = [c for c in ("name", "version") if c in rows[0]]

numeric_columns = []
excluded = []

for column in rows[0]:
    if column in IDENTIFIERS:
        continue

    values = [row[column].strip() for row in rows]

    # Jangan memasukkan fitur dengan nilai kosong
    # atau nilai nonnumerik ke dataset model.
    try:
        numbers = [float(v) for v in values]
    except (ValueError, TypeError):
        excluded.append((column, "non-numeric/missing"))
        continue

    # Kolom konstan tidak membantu membedakan sampel.
    if len(set(numbers)) <= 1:
        excluded.append((column, "constant"))
        continue

    numeric_columns.append(column)

with OUTPUT.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=numeric_columns)
    writer.writeheader()
    writer.writerows([{c: row[c] for c in numeric_columns} for row in rows])

with METADATA.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=metadata_columns)
    writer.writeheader()
    writer.writerows([{c: row[c] for c in metadata_columns} for row in rows])

print("Jumlah sampel:", len(rows))
print("Fitur numerik bervariasi:", len(numeric_columns))
print("Kolom dikecualikan:", len(excluded))
print("\nFitur yang dipakai:")
for c in numeric_columns:
    print(" -", c)

print("\nKolom yang dikecualikan:")
for c, reason in excluded:
    print(f" - {c}: {reason}")

print("\nDataset model:", OUTPUT)
print("Metadata:", METADATA)
