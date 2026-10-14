# Malware Package Research

Riset analisis statis paket perangkat lunak dan evaluasi fitur anomali.

## Folder

- `samples/`: inventory dan referensi sampel.
- `scripts/`: script ekstraksi fitur dan eksperimen model.
- `tetragon/`: konfigurasi observabilitas.
- `logs/`: log pengujian.
- `results/`: SBOM, dataset fitur, dan hasil eksperimen.

## Alur

1. Catat metadata sampel.
2. Lakukan analisis statis pada input yang tersedia.
3. Hasilkan SBOM dan fitur.
4. Uji pipeline telemetry dengan program benign.
5. Evaluasi model secara eksploratif.

