import pandas as pd
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import os

# Load old dataset
base_data = [
    ("hello world", 0),
    ("search python", 0),
    ("admin' OR 1=1 --", 1),
    ("<script>alert(1)</script>", 1),
    ("; rm -rf /", 1),
    ("normal user input", 0),
    ("DROP TABLE users;", 1),
]

df = pd.DataFrame(base_data, columns=["text", "label"])

# If log exists, parse blocked attempts as malicious
if os.path.exists("blocked.log"):
    blocked_data = []
    with open("blocked.log") as f:
        for line in f:
            parts = line.strip().split("QUERY=")
            if len(parts) == 2:
                query = parts[1]
                blocked_data.append((query, 1))  # everything blocked = malicious
    if blocked_data:
        df = pd.concat([df, pd.DataFrame(blocked_data, columns=["text", "label"])])

# Vectorize + train
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(df["text"])
y = df["label"]

model = LogisticRegression()
model.fit(X, y)

# Save updated model
with open("waf_model.pkl", "wb") as f:
    pickle.dump((vectorizer, model), f)

print("✅ Model retrained with logs + base data.")
