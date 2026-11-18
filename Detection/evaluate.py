import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from feature_extraction import extract_features

# Baca dataset bersih dan ambil 2.000 sampel acak untuk evaluasi cepat
df = pd.read_csv("Detection/dataset/cleaned_dataset.csv").sample(n=2000, random_state=42)

def predict_lexical_only(url: str) -> str:
    f = extract_features(url)
    score = 0
    if f["has_ip"] == 1:
        score += 40
    if f["has_at"] == 1:
        score += 30
    if f["url_length"] > 75:
        score += 20
    elif f["url_length"] > 54:
        score += 10
    if f["hyphen_count"] >= 3:
        score += 20
    elif f["hyphen_count"] >= 1:
        score += 5
    if f["subdomain_count"] >= 3:
        score += 20
    elif f["subdomain_count"] == 2:
        score += 10
    if f["is_https"] == 0:
        score += 10

    # Gabungkan Suspicious & Phishing sebagai kelas Phishing untuk evaluasi biner
    return "Phishing" if score >= 30 else "Legitimate"

y_true = df["label"]
y_pred = df["url"].astype(str).apply(predict_lexical_only)

print("=== HASIL EVALUASI ALGORITMA (2.000 SAMPEL) ===")
print(f"Accuracy: {accuracy_score(y_true, y_pred):.2%}\n")
print("Classification Report:")
print(classification_report(y_true, y_pred))
print("Confusion Matrix:")
print(confusion_matrix(y_true, y_pred))