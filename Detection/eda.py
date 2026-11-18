import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# 1. Baca dataset yang sudah dibersihkan
df = pd.read_csv("dataset/cleaned_dataset.csv")

# 2. Analisis Distribusi Jumlah Kategori
print("==========================================")
print("1. DISTRIBUSI JUMLAH LEGITIMATE VS PHISHING")
print("==========================================")
print(df["label"].value_counts())
print("\nPersentase (%):")
print((df["label"].value_counts(normalize=True) * 100).round(2))

# 3. Analisis Panjang URL (untuk menentukan batas aman/threshold)
df["url_length"] = df["url"].apply(len)
print("\n==========================================")
print("2. STATISTIK PANJANG URL (KARAKTER)")
print("==========================================")
print(df.groupby("label")["url_length"].describe().round(2))

# 4. Analisis Karakter Khusus & Indikasi IP
df["hyphen_count"] = df["url"].apply(lambda x: x.count("-"))
df["has_at"] = df["url"].apply(lambda x: int("@" in x))
df["dot_count"] = df["url"].apply(lambda x: x.count("."))
df["slash_count"] = df["url"].apply(lambda x: x.count("/"))

print("\n==========================================")
print("3. RATA-RATA KEMUNCULAN KARAKTER KHUSUS")
print("==========================================")
print(df.groupby("label")[["hyphen_count", "has_at", "dot_count", "slash_count"]].mean().round(3))

# 5. Simpan Grafik Visualisasi ke file gambar (untuk laporan & presentasi)
plt.figure(figsize=(6, 4))
df["label"].value_counts().plot(kind="bar", color=["#2ecc71", "#e74c3c"])
plt.title("Perbandingan Jumlah URL Legitimate vs Phishing")
plt.xlabel("Kategori")
plt.ylabel("Jumlah URL")
plt.xticks(rotation=0)
plt.tight_layout()
plt.savefig("dataset/distribusi_url.png")
print("\n[SUKSES] Grafik tersimpan di dataset/distribusi_url.png")
#plt.show()