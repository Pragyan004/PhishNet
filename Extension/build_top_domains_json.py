import pandas as pd
import json
import os

# Adjust path if needed
TOP_CSV = "datasets/Newfolder/top-1m.csv"

df = pd.read_csv(TOP_CSV, header=None, names=["rank", "domain"])

# Take first 50k popular domains (you can change this number)
top_domains = df["domain"].head(50000).str.strip().str.lower().tolist()

out_dir = "phishguard-extension/data"
os.makedirs(out_dir, exist_ok=True)

out_path = os.path.join(out_dir, "top_domains_small.json")
with open(out_path, "w") as f:
    json.dump(top_domains, f)

print("Saved:", out_path, "| count:", len(top_domains))
