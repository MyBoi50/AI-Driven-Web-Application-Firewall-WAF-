# waf.py
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import httpx, re, joblib, time, json, os
from datetime import datetime
from typing import List, Dict

MODEL_PATH = "waf_model.joblib"
BLOCKED_LOG = "blocked.log"
DECISIONS = []   # memory store of last decisions

# Load model bundle
def load_model(path=MODEL_PATH):
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} not found. Train model first (train_model.py).")
    bundle = joblib.load(path)
    pipe = bundle["pipeline"]
    threshold = bundle.get("threshold", 0.7)
    return pipe, float(threshold)

try:
    PIPE, THRESHOLD = load_model()
except Exception as e:
    PIPE, THRESHOLD = None, 0.7
    print("Model not loaded:", e)

app = FastAPI(title="AI-Driven WAF (improved)")

UPSTREAM = "http://127.0.0.1:9000"

# Expanded regex safety net (can be tuned)
PATTERNS = {
    "SQL Injection": re.compile(r"(?i)(\b(or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?|\bunion\b|\bdrop\b|\binsert\b|\bupdate\b|\bdelete\b|--|\bexec\b)"),
    "XSS": re.compile(r"(?i)(<script|onerror=|onload=|<svg|<img|javascript:|<iframe)"),
    "Command Injection": re.compile(r"(?i)(;|\||\&\&|\|\||`|\$\(.*\)|\bexec\b)"),
    "Path Traversal": re.compile(r"(?i)(\.\./|\.\.\\|/etc/passwd|boot.ini)"),
}

def regex_check(payload: str):
    for name, patt in PATTERNS.items():
        if patt.search(payload):
            return True, name
    return False, None

def ml_score_and_explain(text: str) -> Dict:
    """Return score (0-100), prob, predicted_label, top_tokens"""
    if PIPE is None:
        return {"score": 0, "prob": 0.0, "pred": 0, "top_tokens": []}
    # probability
    prob = float(PIPE.predict_proba([text])[0][1])
    score = int(round(prob * 100))
    pred = 1 if prob >= THRESHOLD else 0
    top_tokens = []
    try:
        union = PIPE.named_steps["union"]
        clf = PIPE.named_steps["clf"]
        token_names = []
        for name, trans in union.transformer_list:
            try:
                fn = trans.get_feature_names_out()
            except Exception:
                fn = []
            token_names.extend([f"{name}__{t}" for t in fn])
        X = union.transform([text])
        weights = (X.multiply(clf.coef_[0])).toarray()[0]
        idx = weights.argsort()[-8:][::-1]
        top_tokens = [token_names[i] for i in idx if i < len(token_names) and weights[i] > 0][:6]
    except Exception:
        top_tokens = []
    return {"score": score, "prob": prob, "pred": pred, "top_tokens": top_tokens}

def log_blocked(query: str, score: int, reason: str, pred_label: str):
    with open(BLOCKED_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().isoformat()}] REASON={reason} | SCORE={score} | PRED={pred_label} | QUERY={query}\n")

# ------------------ Admin Endpoints ------------------

@app.get("/_waf/health")
def health():
    return {"ok": True, "model_loaded": PIPE is not None, "threshold": THRESHOLD}

@app.get("/_waf/last_decisions")
def last_decisions(limit: int = 50):
    return DECISIONS[-limit:]

@app.post("/_waf/retrain")
def retrain(augment: bool = False):
    import subprocess, sys
    cmd = [sys.executable, "train_model.py", "--out", MODEL_PATH]
    if augment:
        cmd.append("--augment")
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Retrain failed: {p.stderr}")
    global PIPE, THRESHOLD
    try:
        PIPE, THRESHOLD = load_model()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model reload failed: {e}")
    return {"ok": True, "threshold": THRESHOLD, "stdout": p.stdout}

class ConfigUpdate(BaseModel):
    threshold: float | None = None
    upstream: str | None = None

@app.post("/_waf/config")
def set_config(cfg: ConfigUpdate):
    global THRESHOLD, UPSTREAM
    if cfg.threshold is not None:
        THRESHOLD = float(cfg.threshold)
    if cfg.upstream:
        UPSTREAM = cfg.upstream
    return {"ok": True, "threshold": THRESHOLD, "upstream": UPSTREAM}

# ------------------ Middleware ------------------

@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    # ✅ Skip WAF's own admin endpoints
    if request.url.path.startswith("/_waf/"):
        return await call_next(request)

    url_text = str(request.url)

    # regex safety net
    r_mal, r_name = regex_check(url_text)

    # ML scoring
    ml = ml_score_and_explain(url_text)

    decision = {
        "ts": time.time(),
        "path": request.url.path,
        "method": request.method,
        "url": url_text,
        "score": ml["score"],
        "prob": ml["prob"],
        "pred": ml["pred"],
        "top_tokens": ml["top_tokens"],
        "matched_rules": [],
    }
    if r_mal:
        decision["matched_rules"].append({"name": r_name, "type": "regex"})
    DECISIONS.append(decision)
    if len(DECISIONS) > 1000:
        DECISIONS.pop(0)

    # block if regex OR ML says malicious
    if r_mal or ml["pred"] == 1:
        reason = r_name if r_mal else "ml_threshold"
        pred_label = "malicious" if ml["pred"] == 1 else "malicious_by_rule"
        log_blocked(url_text, ml["score"], reason, pred_label)
        return JSONResponse(status_code=403, content={
            "blocked": True,
            "reason": reason,
            "score": ml["score"],
            "top_tokens": ml["top_tokens"],
            "matched_rules": decision["matched_rules"],
        })

    # forward to upstream backend
    async with httpx.AsyncClient() as client:
        backend_url = f"{UPSTREAM}{request.url.path}"
        resp = await client.request(
            request.method, backend_url,
            params=dict(request.query_params),
            content=await request.body()
        )
        return Response(content=resp.content, status_code=resp.status_code, headers=dict(resp.headers))
