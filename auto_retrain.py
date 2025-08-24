# auto_retrain.py
import time, subprocess, requests, sys

WAF_URL = "http://127.0.0.1:8080/_waf/retrain"

while True:
    print("[AutoRetrain] Training model with blocked.log ...")
    # retrain model (with augment)
    subprocess.run([sys.executable, "train_model.py", "--out", "waf_model.joblib", "--augment"])
    
    # tell WAF to reload
    try:
        r = requests.post(WAF_URL, params={"augment": "true"})
        print("[AutoRetrain] Reload response:", r.json())
    except Exception as e:
        print("[AutoRetrain] Failed to reload:", e)
    
    # wait before next cycle (e.g. 10 mins)
    time.sleep(600)
