import argparse
import csv
import json
import shutil
import subprocess
import tarfile
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "samples" / "inventory.csv"
SOURCE_DIR = ROOT / "samples" / "source"
BENIGN_CANDIDATES = ROOT / "data" / "raw" / "benign_candidates_1000.csv"

REQUIRED_COLUMNS = {
    "id",
    "name",
    "source",
    "reference_label",
    "static_status",
    "notes",
}

ALLOWED_LABELS = {"malicious", "benign", "unknown"}
ALLOWED_STATUSES = {
    "not-started",
    "in-progress",
    "completed",
    "failed",
}


def load_inventory():
    if not INVENTORY.exists():
        raise FileNotFoundError(f"Inventory tidak ditemukan: {INVENTORY}")

    with INVENTORY.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("CSV kosong.")

        reader.fieldnames = [field.strip() for field in reader.fieldnames]

        missing = REQUIRED_COLUMNS - set(reader.fieldnames)
        if missing:
            raise ValueError(f"Kolom wajib tidak ada: {sorted(missing)}")

        rows = []
        for row in reader:
            clean_row = {
                key.strip(): (value or "").strip()
                for key, value in row.items()
                if key is not None
            }
            rows.append(clean_row)

    return rows


def save_inventory(rows):
    if not rows:
        return

    with INVENTORY.open("w", encoding="utf-8-sig", newline="") as file:
        fieldnames = list(rows[0].keys())
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def validate_inventory(rows):
    errors = 0
    warnings = 0
    seen_ids = set()

    for line, row in enumerate(rows, start=2):
        sample_id = row.get("id", "")
        name = row.get("name", "")
        source = row.get("source", "")
        label = row.get("reference_label", "").lower()
        status = row.get("static_status", "").lower()

        if not sample_id.isdigit():
            print(f"[ERROR] Baris {line}: ID harus angka.")
            errors += 1
        elif sample_id in seen_ids:
            print(f"[ERROR] Baris {line}: ID duplikat {sample_id}.")
            errors += 1
        else:
            seen_ids.add(sample_id)

        if not name:
            print(f"[ERROR] Baris {line}: name kosong.")
            errors += 1

        if not source:
            print(f"[ERROR] Baris {line}: source kosong.")
            errors += 1

        if label not in ALLOWED_LABELS:
            print(f"[WARNING] Baris {line}: reference_label tidak dikenal: {label!r}")
            warnings += 1

        if status not in ALLOWED_STATUSES:
            print(f"[WARNING] Baris {line}: static_status tidak dikenal: {status!r}")
            warnings += 1

        if name.startswith(("http://", "https://")):
            parsed = urlparse(name)
            if parsed.scheme != "https" or not parsed.netloc:
                print(f"[WARNING] Baris {line}: URL perlu diperiksa.")
                warnings += 1

    print("\n=== Validasi Inventory ===")
    print(f"Jumlah baris: {len(rows)}")
    print(f"Error: {errors}")
    print(f"Warning: {warnings}")

    return errors == 0


def list_samples(rows, limit, category):
    if category == "not-started":
        rows = [
            row for row in rows if row.get("static_status", "").lower() == "not-started"
        ]
    elif category in {"malicious", "benign"}:
        rows = [
            row for row in rows if row.get("reference_label", "").lower() == category
        ]

    if limit is not None:
        rows = rows[:limit]

    if not rows:
        print("Tidak ada sampel yang cocok.")
        return

    print(f"{'ID':<6} {'LABEL':<11} {'STATUS':<13} {'SOURCE':<14} NAME / SPEC")
    print("-" * 90)

    for row in rows:
        print(
            f"{row.get('id', ''):<6} "
            f"{row.get('reference_label', ''):<11} "
            f"{row.get('static_status', ''):<13} "
            f"{row.get('source', ''):<14} "
            f"{row.get('name', '')}"
        )

    print(f"\nDitampilkan: {len(rows)} sampel")


def ingest_benign(rows, count):
    if not BENIGN_CANDIDATES.is_file():
        print(f"[ERROR] File dataset benign tidak ditemukan di: {BENIGN_CANDIDATES}")
        return

    with BENIGN_CANDIDATES.open("r", encoding="utf-8-sig") as f:
        candidates = list(csv.DictReader(f))

    if not candidates:
        print("[ERROR] File kandidat benign kosong.")
        return

    # Hitung ID tertinggi yang sudah ada di inventory
    existing_ids = [int(r["id"]) for r in rows if r["id"].isdigit()]
    next_id = max(existing_ids, default=0) + 1

    existing_names = {r["name"].strip() for r in rows}

    added = 0
    for cand in candidates:
        if added >= count:
            break

        pkg_name = cand.get("name", "").strip()
        version = cand.get("latest", "").strip()

        if not pkg_name:
            continue

        pkg_spec = f"{pkg_name}@{version}" if version else pkg_name

        # Hindari duplikat paket benign yang sudah terdaftar
        if pkg_spec in existing_names or pkg_name in existing_names:
            continue

        new_row = {
            "id": str(next_id),
            "name": pkg_spec,
            "source": "npm-registry",
            "reference_label": "benign",
            "static_status": "not-started",
            "notes": f"downloads_last_month={cand.get('downloads_last_month', '')};license={cand.get('license', '')}",
        }

        rows.append(new_row)
        existing_names.add(pkg_spec)
        next_id += 1
        added += 1

    save_inventory(rows)
    print(f"[OK] Berhasil mendaftarkan {added} paket benign ke {INVENTORY.name}.")
    print(f"Total sampel di inventory sekarang: {len(rows)}")


def download_malware(row, folder):
    url = row.get("name", "")
    if not url.startswith(("http://", "https://")):
        print("[ERROR] Kolom name bukan URL valid untuk malware Datadog.")
        return False

    filename = url.split("/")[-1]
    filepath = folder / filename

    print(f"[INFO] Mendownload dari Datadog: {url}")
    try:
        subprocess.run(
            ["wget", "-q", "--show-progress", "-O", str(filepath), url], check=True
        )
        print("[OK] Download zip berhasil.")
    except Exception as e:
        print(f"[ERROR] wget gagal: {e}")
        return False

    print(f"[INFO] Mengekstrak file: {filename}")
    try:
        subprocess.run(
            ["unzip", "-P", "infected", "-o", str(filepath), "-d", str(folder)],
            check=True,
        )
        print("[OK] Ekstrak berhasil.")
        return True
    except Exception as e:
        print(f"[ERROR] Ekstrak zip gagal: {e}")
        return False


def download_benign(row, folder):
    pkg_spec = row.get("name", "")
    if not pkg_spec:
        print("[ERROR] Nama paket kosong.")
        return False

    print(f"[INFO] Mendownload paket resmi dari npm registry: {pkg_spec}")
    try:
        # Jalankan npm pack di dalam folder target
        res = subprocess.run(
            ["npm", "pack", pkg_spec],
            cwd=str(folder),
            capture_output=True,
            text=True,
            check=True,
        )
        tgz_filename = res.stdout.strip().splitlines()[-1]
        tgz_path = folder / tgz_filename

        if not tgz_path.is_file():
            print(f"[ERROR] File tarball {tgz_path} tidak ditemukan setelah npm pack.")
            return False

        print(f"[OK] Downloaded: {tgz_filename}")
        print(f"[INFO] Mengekstrak tarball {tgz_filename}...")

        # Ekstrak tarball .tgz (default npm pack menghasilkan folder 'package/')
        with tarfile.open(tgz_path, "r:gz") as tar:
            tar.extractall(path=folder)

        print("[OK] Ekstrak tarball selesai (folder 'package/' siap dianalisis).")
        return True

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] npm pack gagal: {e.stderr or e}")
        return False
    except Exception as e:
        print(f"[ERROR] Gagal memproses tarball: {e}")
        return False


def inspect_sample(rows, sample_id):
    matches = [row for row in rows if row.get("id", "") == str(sample_id)]

    if not matches:
        print(f"[ERROR] ID {sample_id} tidak ditemukan.")
        return

    row = matches[0]
    folder = SOURCE_DIR / str(sample_id)
    folder.mkdir(parents=True, exist_ok=True)

    print(f"\n=== Mengambil Sampel ID {sample_id} ===")
    print(f"Name / Spec    : {row.get('name', '')}")
    print(f"Source         : {row.get('source', '')}")
    print(f"Reference label: {row.get('reference_label', '')}")
    print(f"Static status  : {row.get('static_status', '')}")
    print(f"Folder lokal   : {folder}")

    source_type = row.get("source", "").lower()
    label = row.get("reference_label", "").lower()

    if "npm" in source_type or label == "benign":
        success = download_benign(row, folder)
    else:
        success = download_malware(row, folder)

    if success:
        print("[INFO] Mengupdate status menjadi 'in-progress'...")
        row["static_status"] = "in-progress"
        save_inventory(rows)
        print("[OK] Inventory berhasil diperbarui.")
    else:
        print("[WARNING] Status inventory tidak diubah karena download/ekstrak gagal.")


def main():
    parser = argparse.ArgumentParser(
        description="Mengelola dan memvalidasi inventory sampel (Malware & Benign)."
    )

    parser.add_argument(
        "--list", type=int, metavar="N", help="Tampilkan maksimal N sampel."
    )

    parser.add_argument(
        "--category",
        choices=["all", "not-started", "malicious", "benign"],
        default="all",
        help="Filter berdasarkan status pemeriksaan atau label.",
    )

    parser.add_argument(
        "--ingest-benign",
        type=int,
        metavar="N",
        help="Daftarkan N paket dari data/raw/benign_candidates_1000.csv ke inventory.csv.",
    )

    parser.add_argument(
        "--get",
        type=int,
        metavar="ID",
        help="Download, ekstrak file sampel (Malware via wget/unzip atau Benign via npm pack), dan update status.",
    )

    parser.add_argument(
        "--get-range",
        type=str,
        metavar="START-END",
        help="Download serangkaian ID sekaligus (contoh: 148-157).",
    )

    parser.add_argument(
        "--validate", action="store_true", help="Validasi inventory CSV."
    )

    args = parser.parse_args()

    try:
        rows = load_inventory()
    except (FileNotFoundError, ValueError) as error:
        print(f"[ERROR] {error}")
        return

    if args.validate:
        validate_inventory(rows)

    if args.ingest_benign is not None:
        if args.ingest_benign < 1:
            parser.error("--ingest-benign harus lebih besar dari 0.")
        ingest_benign(rows, args.ingest_benign)

    if args.list is not None:
        if args.list < 1:
            parser.error("--list harus lebih besar dari 0.")
        list_samples(rows, args.list, args.category)

    if args.get is not None:
        inspect_sample(rows, args.get)

    if args.get_range is not None:
        try:
            start_s, end_s = args.get_range.split("-")
            start_id, end_id = int(start_s), int(end_s)
        except ValueError:
            parser.error("--get-range format harus START-END (contoh: 148-155)")
            return

        for sid in range(start_id, end_id + 1):
            inspect_sample(rows, sid)

    if (
        not args.validate
        and args.list is None
        and args.get is None
        and args.get_range is None
        and args.ingest_benign is None
    ):
        parser.print_help()


if __name__ == "__main__":
    main()
