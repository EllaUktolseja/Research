import argparse
import csv
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath
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

CMD_TIMEOUT = 60  # detik per proses download/ekstrak


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
    """Menulis inventory secara atomic agar tidak korup jika proses terputus."""
    if not rows:
        return

    INVENTORY.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys())

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8-sig",
        newline="",
        dir=str(INVENTORY.parent),
        prefix=".inventory_",
        suffix=".tmp",
        delete=False,
    ) as tmp_file:
        tmp_path = Path(tmp_file.name)
        writer = csv.DictWriter(tmp_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        tmp_file.flush()
        os.fsync(tmp_file.fileno())

    os.replace(tmp_path, INVENTORY)


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

        if label == "malicious" and not name.startswith(("http://", "https://")):
            print(f"[WARNING] Baris {line}: Sampel malicious bukan URL: {name!r}")
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
    if category in ALLOWED_STATUSES:
        rows = [row for row in rows if row.get("static_status", "").lower() == category]
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


def extract_base_pkg_name(spec):
    """Mengambil nama paket tanpa versi (mendukung scoped package seperti @scope/pkg@1.0.0)."""
    spec = spec.strip()
    if spec.startswith(("http://", "https://")):
        return spec
    if spec.startswith("@"):
        parts = spec.split("@")
        return f"@{parts[1]}" if len(parts) >= 2 else spec
    return spec.split("@")[0]


def ingest_benign(rows, count):
    if not BENIGN_CANDIDATES.is_file():
        print(f"[ERROR] File dataset benign tidak ditemukan di: {BENIGN_CANDIDATES}")
        return

    with BENIGN_CANDIDATES.open("r", encoding="utf-8-sig") as f:
        candidates = list(csv.DictReader(f))

    if not candidates:
        print("[ERROR] File kandidat benign kosong.")
        return

    existing_ids = [int(r["id"]) for r in rows if r["id"].isdigit()]
    next_id = max(existing_ids, default=0) + 1

    existing_specs = {r["name"].strip() for r in rows}
    existing_base_names = {
        extract_base_pkg_name(r["name"])
        for r in rows
        if r.get("reference_label", "").lower() == "benign"
    }

    added = 0
    for cand in candidates:
        if added >= count:
            break

        pkg_name = cand.get("name", "").strip()
        version = cand.get("latest", "").strip()

        if not pkg_name:
            continue

        pkg_spec = f"{pkg_name}@{version}" if version else pkg_name

        # Hindari duplikat baik berdasarkan spec persis maupun nama dasar paket
        if pkg_spec in existing_specs or pkg_name in existing_base_names:
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
        existing_specs.add(pkg_spec)
        existing_base_names.add(pkg_name)
        next_id += 1
        added += 1

    save_inventory(rows)
    print(f"[OK] Berhasil mendaftarkan {added} paket benign ke {INVENTORY.name}.")
    print(f"Total sampel di inventory sekarang: {len(rows)}")


def is_safe_archive_member(member_name):
    """Mencegah Zip Slip / Path Traversal ke luar direktori ekstraksi."""
    if not member_name:
        return True
    normalized = member_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts:
        return False
    return True


def is_safe_zip(zip_path):
    try:
        res = subprocess.run(
            ["unzip", "-Z1", str(zip_path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        for line in res.stdout.splitlines():
            if not is_safe_archive_member(line.strip()):
                print(f"[SECURITY] Path berbahaya terdeteksi dalam zip: {line!r}")
                return False
        return True
    except Exception as e:
        print(f"[ERROR] Gagal memeriksa isi zip: {e}")
        return False


def safe_extract_tar(tgz_path, dest_dir):
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tgz_path, "r:*") as tar:
        if hasattr(tarfile, "data_filter"):
            tar.extractall(path=dest_dir, filter="data")
        else:
            for member in tar.getmembers():
                if not is_safe_archive_member(member.name):
                    raise ValueError(f"Path berbahaya dalam tarball: {member.name}")
            tar.extractall(path=dest_dir)


def normalize_to_package_dir(extracted_dir, package_dir):
    """
    Menyeragamkan hasil ekstraksi (baik malware maupun benign) agar selalu
    menghasilkan folder '<id>/package/' berisi root source code paket npm.
    """
    ignore_names = {"__MACOSX", ".DS_Store"}
    entries = [p for p in extracted_dir.iterdir() if p.name not in ignore_names]

    if not entries:
        return False

    # Kasus 1: Zip Datadog membungkus file .tgz / .tar.gz di dalamnya
    tarballs = [
        p
        for p in entries
        if p.is_file() and (p.name.endswith(".tgz") or p.name.endswith(".tar.gz"))
    ]
    if len(entries) == 1 and len(tarballs) == 1:
        nested_dir = extracted_dir / "_nested_tar"
        safe_extract_tar(tarballs[0], nested_dir)
        entries = [p for p in nested_dir.iterdir() if p.name not in ignore_names]
        source_root = nested_dir
    else:
        source_root = extracted_dir

    if not entries:
        return False

    # Kasus 2: Struktur standar npm tarball ('package/...')
    pkg_subdir = source_root / "package"
    if pkg_subdir.is_dir():
        shutil.move(str(pkg_subdir), str(package_dir))
        return True

    # Kasus 3: Terbungkus dalam satu folder tunggal (misal 'nama-paket-1.0.0/')
    if len(entries) == 1 and entries[0].is_dir():
        shutil.move(str(entries[0]), str(package_dir))
        return True

    # Kasus 4: File (package.json, index.js, dll.) langsung berada di root arsip
    package_dir.mkdir(parents=True, exist_ok=True)
    for item in entries:
        shutil.move(str(item), str(package_dir / item.name))

    return any(package_dir.iterdir())


def download_malware(row, folder):
    url = row.get("name", "").strip()
    if not url.startswith(("http://", "https://")):
        print("[ERROR] Kolom name bukan URL valid untuk sampel malicious.")
        return False

    parsed_name = Path(urlparse(url).path).name
    filename = parsed_name if parsed_name else f"sample_{row['id']}.zip"

    staging_dir = folder / "_staging"
    unzip_dir = staging_dir / "unzipped"
    archive_dir = folder / "archive"
    package_dir = folder / "package"

    staging_dir.mkdir(parents=True, exist_ok=True)
    unzip_dir.mkdir(parents=True, exist_ok=True)
    archive_dir.mkdir(parents=True, exist_ok=True)

    filepath = staging_dir / filename

    print(f"[INFO] Mendownload sampel malicious: {url}")
    try:
        subprocess.run(
            [
                "wget",
                "-q",
                "--show-progress",
                "--tries=2",
                f"--timeout={CMD_TIMEOUT}",
                "-O",
                str(filepath),
                url,
            ],
            timeout=CMD_TIMEOUT + 15,
            check=True,
        )
        print("[OK] Download arsip selesai.")

        if not is_safe_zip(filepath):
            return False

        print(f"[INFO] Mengekstrak arsip: {filename}")
        subprocess.run(
            [
                "unzip",
                "-P",
                "infected",
                "-q",
                "-o",
                str(filepath),
                "-d",
                str(unzip_dir),
            ],
            timeout=CMD_TIMEOUT,
            check=True,
        )

        if not normalize_to_package_dir(unzip_dir, package_dir):
            print("[ERROR] Hasil ekstraksi arsip malware kosong atau tidak valid.")
            return False

        shutil.move(str(filepath), str(archive_dir / filename))
        shutil.rmtree(staging_dir, ignore_errors=True)
        print("[OK] Sampel malicious siap di folder 'package/'.")
        return True

    except subprocess.TimeoutExpired:
        print(f"[ERROR] Timeout ({CMD_TIMEOUT}s) saat memproses sampel malicious.")
        return False
    except Exception as e:
        print(f"[ERROR] Gagal download/ekstrak malware: {e}")
        return False


def download_benign(row, folder):
    pkg_spec = row.get("name", "").strip()
    if not pkg_spec:
        print("[ERROR] Nama paket kosong.")
        return False

    staging_dir = folder / "_staging"
    npm_cache_dir = staging_dir / "_npm_cache"
    untar_dir = staging_dir / "untarred"
    archive_dir = folder / "archive"
    package_dir = folder / "package"

    staging_dir.mkdir(parents=True, exist_ok=True)
    npm_cache_dir.mkdir(parents=True, exist_ok=True)
    untar_dir.mkdir(parents=True, exist_ok=True)
    archive_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["NPM_CONFIG_CACHE"] = str(npm_cache_dir)

    print(f"[INFO] Mendownload paket benign dari npm registry: {pkg_spec}")
    try:
        res = subprocess.run(
            ["npm", "pack", pkg_spec, "--json", "--loglevel=error"],
            cwd=str(staging_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=CMD_TIMEOUT,
            check=True,
        )

        tgz_path = None
        try:
            pack_info = json.loads(res.stdout)
            if isinstance(pack_info, list) and pack_info and "filename" in pack_info[0]:
                candidate = staging_dir / pack_info[0]["filename"]
                if candidate.is_file():
                    tgz_path = candidate
        except json.JSONDecodeError:
            pass

        # Fallback jika npm tidak mengeluarkan JSON murni
        if tgz_path is None:
            tgz_files = list(staging_dir.glob("*.tgz"))
            if tgz_files:
                tgz_path = tgz_files[0]

        if tgz_path is None or not tgz_path.is_file():
            print("[ERROR] File tarball .tgz tidak ditemukan setelah npm pack.")
            return False

        print(f"[OK] Downloaded: {tgz_path.name}")
        safe_extract_tar(tgz_path, untar_dir)

        if not normalize_to_package_dir(untar_dir, package_dir):
            print("[ERROR] Hasil ekstraksi tarball benign kosong.")
            return False

        shutil.move(str(tgz_path), str(archive_dir / tgz_path.name))
        shutil.rmtree(staging_dir, ignore_errors=True)
        print("[OK] Sampel benign siap di folder 'package/'.")
        return True

    except subprocess.TimeoutExpired:
        print(f"[ERROR] Timeout ({CMD_TIMEOUT}s) saat menjalankan npm pack.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] npm pack gagal: {e.stderr.strip() or e}")
        return False
    except Exception as e:
        print(f"[ERROR] Gagal memproses tarball benign: {e}")
        return False


def inspect_sample(rows, sample_id, force=False):
    matches = [row for row in rows if row.get("id", "") == str(sample_id)]

    if not matches:
        print(f"[ERROR] ID {sample_id} tidak ditemukan.")
        return False

    row = matches[0]
    status = row.get("static_status", "").lower()
    label = row.get("reference_label", "").lower()
    folder = SOURCE_DIR / str(sample_id)

    if status == "completed" and not force:
        print(
            f"[SKIP] ID {sample_id} sudah berstatus 'completed' (gunakan --force untuk timpa)."
        )
        return False

    if label not in {"malicious", "benign"}:
        print(f"[ERROR] ID {sample_id} memiliki reference_label tidak valid: {label!r}")
        return False

    # Bersihkan sisa folder lama jika sebelumnya gagal/in-progress
    if folder.exists():
        shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(parents=True, exist_ok=True)

    print(f"\n=== Mengambil Sampel ID {sample_id} ===")
    print(f"Name / Spec    : {row.get('name', '')}")
    print(f"Source         : {row.get('source', '')}")
    print(f"Reference label: {label}")
    print(f"Static status  : {status}")
    print(f"Folder lokal   : {folder}")

    if label == "benign":
        success = download_benign(row, folder)
    else:
        success = download_malware(row, folder)

    if success:
        print("[INFO] Mengupdate status menjadi 'in-progress'...")
        row["static_status"] = "in-progress"
        save_inventory(rows)
        print("[OK] Inventory berhasil diperbarui.")
        return True
    else:
        # Hapus folder agar tidak meninggalkan direktori kosong/korup
        shutil.rmtree(folder, ignore_errors=True)
        print(
            "[WARNING] Download/ekstrak gagal; folder dibersihkan & status tidak diubah."
        )
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Mengelola dan memvalidasi inventory sampel (Malware & Benign)."
    )

    parser.add_argument(
        "--list", type=int, metavar="N", help="Tampilkan maksimal N sampel."
    )

    parser.add_argument(
        "--category",
        choices=[
            "all",
            "not-started",
            "in-progress",
            "completed",
            "failed",
            "malicious",
            "benign",
        ],
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
        help="Download, ekstrak file sampel ke struktur seragam, dan update status.",
    )

    parser.add_argument(
        "--get-range",
        type=str,
        metavar="START-END",
        help="Download serangkaian ID sekaligus (contoh: 1-50).",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Timpa ulang sampel meskipun statusnya sudah 'completed'.",
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Jeda antar-download dalam detik saat menggunakan --get-range (default: 0.5).",
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
        inspect_sample(rows, args.get, force=args.force)

    if args.get_range is not None:
        try:
            start_s, end_s = args.get_range.split("-")
            start_id, end_id = int(start_s), int(end_s)
        except ValueError:
            parser.error("--get-range format harus START-END (contoh: 1-50)")
            return

        if start_id < 1 or end_id < start_id:
            parser.error("--get-range harus berupa angka positif dengan START <= END.")
            return

        total = end_id - start_id + 1
        succeeded = 0
        for idx, sid in enumerate(range(start_id, end_id + 1), start=1):
            if inspect_sample(rows, sid, force=args.force):
                succeeded += 1
                if idx < total and args.delay > 0:
                    time.sleep(args.delay)

        print(f"\n=== Ringkasan Batch ({start_id}-{end_id}) ===")
        print(f"Berhasil diproses: {succeeded}/{total} sampel")

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
