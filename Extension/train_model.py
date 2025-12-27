import pandas as pd
import numpy as np
import os
import torch
import torch.nn as nn
import torch.optim as optim
import json
import re
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from collections import Counter


# ---------------- Feature Extractor --------------------
class URLFeatureExtractor:
    @staticmethod
    def extract(url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            
            feats = {
                "url_length": len(url),
                "domain_length": len(domain),
                "path_length": len(path),
                "num_dots": url.count("."),
                "num_slashes": url.count("/"),
                "num_question": url.count("?"),
                "num_equal": url.count("="),
                "num_hyphens": url.count("-"),
                "num_at": url.count("@"),
                "num_and": url.count("&"),
                "num_hash": url.count("#"),
                "num_percent": url.count("%"),
                "num_digits_url": len(re.findall(r"\d", url)),
                "num_letters_url": len(re.findall(r"[a-zA-Z]", url)),
                "https": 1 if parsed.scheme == "https" else 0,
                "has_ip": 1 if re.match(r"\d+\.\d+\.\d+\.\d+", domain) else 0,
                "num_subdomains": max(0, domain.count(".") - 1),
            }

            suspicious_words = ["login","secure","update","account","verify"]
            feats["has_suspicious_words"] = int(any(w in url.lower() for w in suspicious_words))

            shortening_services = ["bit.ly", "goo.gl", "tinyurl", "t.co"]
            feats["has_shortening"] = int(any(s in domain for s in shortening_services))

            # Ratios
            feats["digit_ratio"] = feats["num_digits_url"] / len(url)
            feats["special_char_ratio"] = (
                feats["num_dots"] + feats["num_hyphens"] + feats["num_at"]
            ) / len(url)

            return feats

        except:
            return None



# ---------------- Neural Net ---------------------------
class PhishNet(nn.Module):
    def __init__(self, n_features):
        super().__init__()
        self.fc1 = nn.Linear(n_features, 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, 1)
        self.relu = nn.ReLU()
        self.sig = nn.Sigmoid()

    def forward(self, x):
        return self.sig(self.fc3(self.relu(self.fc2(self.relu(self.fc1(x))))))



# -------- Smart Dataset Loader with Auto Labeling ------
def load_any_dataset(file):
    fname = os.path.basename(file).lower()
    print(f"\n📁 Checking {fname}")

    df = pd.read_csv(file, encoding="latin1", on_bad_lines="skip", engine="python")
    df.columns = [c.lower().strip() for c in df.columns]

    url_col = next((c for c in ["url", "domain", "link"] if c in df.columns), None)
    if not url_col:
        print("❌ No URL column → Skipped")
        return None

    label_col = next((c for c in ["label", "type", "phishing", "malicious"]
                       if c in df.columns), None)

    df = df[[url_col] + ([label_col] if label_col else [])].rename(columns={url_col: "url"})
    df = df.dropna(subset=["url"])
    df = df[df["url"].astype(str).str.startswith("http")]

    if df.empty:
        print("🚫 Skipped (Invalid URLs)")
        return None

    if label_col:
        df["label"] = df[label_col].astype(str).str.lower().map(
            lambda x: 1 if x in ["1","malicious","phish","bad"] else 0
        )
        print(f"✔ Using dataset labels: {Counter(df['label'])}")
    else:
        # Auto labeling (filename hint)
        df["label"] = 1 if any(k in fname for k in ["phish","malicious","spam"]) else 0
        print(f"⚠ Auto labeled: {Counter(df['label'])}")

    df = df[["url","label"]]
    print(f"✔ Loaded rows: {len(df)}")
    return df



def load_all_datasets(path="datasets"):
    dfs = []
    for f in os.listdir(path):
        if f.endswith(".csv"):
            df = load_any_dataset(os.path.join(path, f))
            if df is not None:
                dfs.append(df)

    if not dfs:
        raise Exception("❌ No valid datasets!")

    df = pd.concat(dfs, ignore_index=True)
    print(f"\n📊 Total combined: {len(df)} rows → Label: {Counter(df['label'])}")
    return df



# ---------------- Train Model --------------------------
def main():
    df = load_all_datasets()

    # Balance dataset
    phish_df = df[df.label == 1]
    legit_df = df[df.label == 0].sample(len(phish_df), random_state=42)
    df = pd.concat([phish_df, legit_df], ignore_index=True)

    print(f"\n⚖ Balanced dataset: {Counter(df['label'])}")

    extractor = URLFeatureExtractor()
    feats, labels = [], []

    for i, row in df.iterrows():
        f = extractor.extract(row["url"])
        if f:
            feats.append(f)
            labels.append(row["label"])
        if i % 10000 == 0:
            print(f"🔄 Extracted: {i}/{len(df)}")

    X = pd.DataFrame(feats)
    y = np.array(labels)

    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)

    model = PhishNet(Xs.shape[1])
    opt = optim.Adam(model.parameters(), lr=0.001)
    crit = nn.BCELoss()

    X_tensor = torch.FloatTensor(Xs)
    y_tensor = torch.FloatTensor(y).reshape(-1, 1)

    print("\n🚀 Training...")
    for epoch in range(1, 51):
        opt.zero_grad()
        out = model(X_tensor)
        loss = crit(out, y_tensor)
        loss.backward()
        opt.step()

        if epoch % 10 == 0:
            acc = ((out > 0.5) == y_tensor).float().mean().item()
            print(f"Epoch {epoch:02d} | Loss={loss:.4f} | Acc={acc:.4f}")

    # Save model and scaler
    model_dir = "phishguard-extension/model"
    os.makedirs(model_dir, exist_ok=True)

    torch.onnx.export(model, torch.randn(1, Xs.shape[1]),
                      f"{model_dir}/model.onnx",
                      input_names=["input"], output_names=["output"],
                      opset_version=11)

    with open(f"{model_dir}/scaler.json","w") as f:
        json.dump({
            "mean": scaler.mean_.tolist(),
            "scale": scaler.scale_.tolist(),
            "feature_names": list(X.columns)
        }, f, indent=2)

    print("\n🎉 Model + Scaler Saved Successfully!")


if __name__ == "__main__":
    main()
