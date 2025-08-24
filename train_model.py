# train_model.py
import json, os
import numpy as np
import joblib
import argparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_recall_curve, f1_score, classification_report

def load_dataset(path="dataset.json"):
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} not found. Run make_dataset.py first.")
    data = json.load(open(path, "r", encoding="utf-8"))
    texts = [x["query"] for x in data]
    labels = [1 if x["label"] != "safe" else 0 for x in data]
    return texts, labels, data

def build_pipeline():
    # Two views: char n-grams and word n-grams
    char_vec = TfidfVectorizer(analyzer="char", ngram_range=(3,5), min_df=2)
    word_vec = TfidfVectorizer(analyzer="word", ngram_range=(1,2), min_df=2)
    union = FeatureUnion([("char", char_vec), ("word", word_vec)])
    clf = LogisticRegression(max_iter=2000, class_weight="balanced")
    pipe = Pipeline([("union", union), ("clf", clf)])
    return pipe

def choose_threshold(y_true, probs, precision_target=0.90):
    # choose threshold that gets precision >= precision_target with highest recall
    prec, recall, thr = precision_recall_curve(y_true, probs)
    candidates = [(p, r, t) for p, r, t in zip(prec, recall, np.append(thr, 1.0)) if p >= precision_target]
    if candidates:
        # choose one with max recall
        best = max(candidates, key=lambda x: x[1])
        return float(best[2])
    # fallback to 0.7
    return 0.7

def train_and_save(dataset="dataset.json", out="waf_model.joblib", augment_with_blocked=False):
    texts, labels, raw = load_dataset(dataset)
    # Optionally append blocked.log entries labelled malicious
    if augment_with_blocked and os.path.exists("blocked.log"):
        with open("blocked.log", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split("QUERY=")
                if len(parts) == 2:
                    q = parts[1]
                    texts.append(q); labels.append(1)
    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42, stratify=labels)
    pipe = build_pipeline()
    print("Training pipeline on", len(X_train), "examples...")
    pipe.fit(X_train, y_train)
    probs = pipe.predict_proba(X_test)[:,1]
    thr = choose_threshold(y_test, probs, precision_target=0.9)
    preds = (probs >= thr).astype(int)
    print("Threshold chosen:", thr)
    print("Classification report (test):")
    print(classification_report(y_test, preds, digits=4))
    # Save pipeline + metadata
    model_bundle = {"pipeline": pipe, "threshold": thr}
    joblib.dump(model_bundle, out)
    print("Saved model bundle to", out)
    return out

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="dataset.json")
    parser.add_argument("--out", default="waf_model.joblib")
    parser.add_argument("--augment", action="store_true", help="augment training with blocked.log entries")
    args = parser.parse_args()
    train_and_save(dataset=args.dataset, out=args.out, augment_with_blocked=args.augment)
