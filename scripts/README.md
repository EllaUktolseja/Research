# Fungsi Script

## 1. `manage_inventory.py`

* **Fungsi:** Mandor dataset.
* **Cara pakai:**
* `python scripts/manage_inventory.py --validate` (Cek CSV aman/nggak).
* `python scripts/manage_inventory.py --list 10` (Liat daftar paket).
* `python scripts/manage_inventory.py --get 1` (Otomatis download dan ekstrak sampel ID 1 ke `samples/source/1/`).

## 2. `scan_sbom.sh`

* **Fungsi:** Bikin "daftar bahan baku" (SBOM) dari source code yang baru di-download.
* **Cara pakai:** `bash scripts/scan_sbom.sh`. Script ini bakal nyari kode di `samples/source/1/` trus nge-generate hasilnya jadi `results/sbom/1.json`.

## 3. `extract_features.py`

* **Fungsi:** Ekstrak fitur statis (baca kode tanpa ngejalanin malware).
* **Cara pakai:** `python scripts/extract_features.py samples/source/1 --sbom results/sbom/1.json`. Dia baca source code + baca SBOM, trus masukin datanya ke baris baru di `results/features.csv`.

## 4. `extract_runtime_features.py`

* **Fungsi:** Ekstrak fitur dinamis dari log eBPF Tetragon (setelah malware sempat lu eksekusi di *sandbox*).
* **Cara pakai:** `python scripts/extract_runtime_features.py --input logs/tetragon.jsonl --output results/ebpf/1.json --sample-id 1`. (Trus hasil akhirnya direkap ke `runtime_features.csv`).

## 5. `json_to_csv.py`

* **Fungsi:** Tukang sapu/penggabung. Kalau lu nyimpen hasil ekstrak fitur ke bentuk JSON pisah-pisah dulu, script ini gabungin semuanya jadi satu tabel.
* **Cara pakai:** `python scripts/json_to_csv.py --input-dir results/ --output results/features.csv`.

## 6. `prepare_dataset.py`

* **Fungsi:** Tukang cuci piring (data cleaning) sebelum masuk ke *Machine Learning*.
* **Cara pakai:** `python scripts/prepare_dataset.py`. Dia ngambil `features.csv`, misahin yang murni angka ke `features_model.csv` (buat ML) dan string/teks ke `features_model_metadata.csv` (buat identitas).

## 7. `run_isolation_forest.py`

* **Fungsi:** Otak AI-nya. Nyari mana sampel yang *behavior*-nya aneh/menyimpang.
* **Cara pakai:** `python scripts/run_isolation_forest.py`. Dia nelen data angka, nyocokin sama metadata, trus ngeluarin rapor akhirnya di `results/isolation_forest_results.csv` lengkap sama *anomaly score*-nya.
