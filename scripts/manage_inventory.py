import argparse
import csv
import subprocess
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "samples" / "inventory.csv"
SOURCE_DIR = ROOT / "samples" / "source"

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
        # Ambil urutan kolom dari baris pertama
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

    if limit is not None:
        rows = rows[:limit]

    if not rows:
        print("Tidak ada sampel yang cocok.")
        return

    print(f"{'ID':<6} {'STATUS':<15} {'SOURCE':<12} NAME / URL")
    print("-" * 90)

    for row in rows:
        print(
            f"{row.get('id', ''):<6} "
            f"{row.get('static_status', ''):<15} "
            f"{row.get('source', ''):<12} "
            f"{row.get('name', '')}"
        )

    print(f"\nDitampilkan: {len(rows)} sampel")


def inspect_sample(rows, sample_id):
    matches = [row for row in rows if row.get("id", "") == str(sample_id)]

    if not matches:
        print(f"[ERROR] ID {sample_id} tidak ditemukan.")
        return

    row = matches[0]
    folder = SOURCE_DIR / str(sample_id)
    url = row.get("name", "")

    print(f"ID             : {row.get('id', '')}")
    print(f"Name / URL     : {url}")
    print(f"Source         : {row.get('source', '')}")
    print(f"Reference label: {row.get('reference_label', '')}")
    print(f"Static status  : {row.get('static_status', '')}")
    print(f"Notes          : {row.get('notes', '')}")
    print(f"Folder lokal   : {folder}")

    folder.mkdir(parents=True, exist_ok=True)

    if not url.startswith(("http://", "https://")):
        print("[ERROR] Kolom name bukan berisi URL yang valid untuk didownload.")
        return

    filename = url.split("/")[-1]
    filepath = folder / filename

    print(f"\n[INFO] Mendownload dari: {url}")
    try:
        subprocess.run(
            ["wget", "-q", "--show-progress", "-O", str(filepath), url], check=True
        )
        print("[OK] Download berhasil.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] wget gagal: {e}")
        return
    except FileNotFoundError:
        print("[ERROR] wget tidak terinstall di sistem.")
        return

    print(f"[INFO] Mengekstrak file: {filename}")
    try:
        subprocess.run(
            ["unzip", "-P", "infected", "-o", str(filepath), "-d", str(folder)],
            check=True,
        )
        print("[OK] Ekstrak berhasil.")

        # Update status di dictionary dan simpan ke CSV
        print("[INFO] Mengupdate status menjadi 'in-progress'...")
        row["static_status"] = "in-progress"
        save_inventory(rows)
        print("[OK] File inventory.csv berhasil diperbarui.")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] unzip gagal (mungkin password salah atau bukan file zip): {e}")
    except FileNotFoundError:
        print("[ERROR] unzip tidak terinstall di sistem.")


def main():
    parser = argparse.ArgumentParser(
        description="Mengelola dan memvalidasi inventory sampel."
    )

    parser.add_argument(
        "--list", type=int, metavar="N", help="Tampilkan maksimal N sampel."
    )

    parser.add_argument(
        "--category",
        choices=["all", "not-started"],
        default="all",
        help="Filter berdasarkan status pemeriksaan.",
    )

    parser.add_argument(
        "--get",
        type=int,
        metavar="ID",
        help="Download, ekstrak file sampel, dan update status berdasarkan ID.",
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

    if args.list is not None:
        if args.list < 1:
            parser.error("--list harus lebih besar dari 0.")
        list_samples(rows, args.list, args.category)

    if args.get is not None:
        inspect_sample(rows, args.get)

    if not args.validate and args.list is None and args.get is None:
        parser.print_help()


if __name__ == "__main__":
    main()
