import pandas as pd

# 1. Baca dataset mentah
df = pd.read_csv("dataset/original_dataset.csv")

print("=== 5 BARIS PERTAMA DATA MENTAH ===")
print(df.head())
print("\n=== INFO KOLOM ===")
print(df.info())

# 2. Samakan nama kolom menjadi huruf kecil semua (untuk jaga-jaga jika nama kolom aslinya 'URL' atau 'Label')
df.columns = df.columns.str.strip().str.lower()

# Otomatis deteksi jika kolom label di dataset bernama 'status', 'type', atau 'class'
for alt_col in ["status", "type", "class", "result"]:
    if alt_col in df.columns and "label" not in df.columns:
        df = df.rename(columns={alt_col: "label"})

# 3. Cek dan hapus data kosong serta duplikat
print("\n=== CEK DATA KOSONG & DUPLIKAT ===")
print("Data kosong per kolom:\n", df[["url", "label"]].isnull().sum())
print("Jumlah URL duplikat:", df.duplicated(subset=["url"]).sum())

df = df.dropna(subset=["url", "label"])
df = df.drop_duplicates(subset=["url"])

# 4. Bersihkan teks & seragamkan format label menjadi 'Phishing' dan 'Legitimate'
df["url"] = df["url"].astype(str).str.strip()
df["label"] = df["label"].astype(str).str.strip().str.lower()

mapping_label = {
    "phishing": "Phishing",
    "bad": "Phishing",
    "malicious": "Phishing",
    "1": "Phishing",
    "legitimate": "Legitimate",
    "good": "Legitimate",
    "benign": "Legitimate",
    "0": "Legitimate"
}
df["label"] = df["label"].map(mapping_label)

# Buang baris jika ada kategori lain di luar Phishing dan Legitimate
df = df.dropna(subset=["label"])

# 5. Simpan hasil bersih ke cleaned_dataset.csv
df[["url", "label"]].to_csv("dataset/cleaned_dataset.csv", index=False)
print("\n[SUKSES] Dataset bersih tersimpan di dataset/cleaned_dataset.csv!")
print("Total data siap pakai:", len(df))