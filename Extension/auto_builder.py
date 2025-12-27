import pandas as pd
import requests
import zipfile
import os
import time

print("\nPHISHGUARD DATASET BUILDER - AUTO (v2.2)\n")

TARGET_LEGIT = 150_000
TARGET_PHISH = 150_000

# ---- LOCAL LEGIT CSV ----
LEGIT_FILE = "C:/Users/pragy/Desktop/New folder/PhisGaurd-AI/datasets/Newfolder/top-1m.csv"

# ---- LIVE PHISH FEEDS ----
PHISH_SOURCES = [
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://openphish.com/feed.txt",
]

# ---- Local Legit Loader ----
def load_legit_csv(path, limit):
    print(f"→ Loading legit CSV: {path}")
    df = pd.read_csv(path, header=None)
    df.columns = ["rank", "domain"]
    df["url"] = "http://" + df["domain"].astype(str)
    df["label"] = 0
    return df[["url", "label"]].head(limit)

# ---- Phish Feed Loader ----
def fetch_text_feed(url, label, limit):
    try:
        print(f"→ Fetching feed: {url}")
        res = requests.get(url, timeout=15)
        res.raise_for_status()
        urls = [u.strip() for u in res.text.splitlines() if u.startswith("http")]
        df = pd.DataFrame({"url": urls})
        df["label"] = label
        return df.head(limit)
    except Exception as e:
        print(f"❌ Failed to fetch {url} — {e}")
        return pd.DataFrame(columns=["url", "label"])

# ---- Build Phishing Set ----
phish_list = []
for src in PHISH_SOURCES:
    df = fetch_text_feed(src, 1, TARGET_PHISH * 2)
    if not df.empty:
        phish_list.append(df)
    time.sleep(1)

df_phish = pd.concat(phish_list, ignore_index=True).drop_duplicates(subset=["url"])
df_phish = df_phish.head(TARGET_PHISH)
print(f"✔ Phishing URLs collected: {len(df_phish)}")

# ---- Build Legit Set ----
if os.path.exists(LEGIT_FILE):
    df_legit = load_legit_csv(LEGIT_FILE, TARGET_LEGIT)
    print(f"✔ Legit URLs collected: {len(df_legit)}")
else:
    print(f"❌ Legit file missing: {LEGIT_FILE}")
    df_legit = pd.DataFrame(columns=["url", "label"])

# ---- Mixed ----
df_mixed = pd.concat([df_legit, df_phish]).sample(frac=1).reset_index(drop=True)
print(f"✔ Mixed total: {len(df_mixed)}")

os.makedirs("datasets", exist_ok=True)
df_legit.to_csv("datasets/dataset_legit.csv", index=False)
df_phish.to_csv("datasets/dataset_phish.csv", index=False)
df_mixed.to_csv("datasets/dataset_mixed.csv", index=False)

with zipfile.ZipFile("phishguard_dataset_L_auto.zip", "w") as z:
    z.write("datasets/dataset_legit.csv")
    z.write("datasets/dataset_phish.csv")
    z.write("datasets/dataset_mixed.csv")

print("\n🎉 DONE! Final ZIP: phishguard_dataset_L_auto.zip")
