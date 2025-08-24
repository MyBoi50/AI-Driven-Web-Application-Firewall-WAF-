AI-Powered Web Application Firewall (WAF) ----- This is Completely CLI Based Model.

🚀 A self-learning Web Application Firewall built with FastAPI and Machine Learning.
It protects a vulnerable backend app by detecting and blocking malicious requests such as SQL Injection, XSS, Command Injection, and Path Traversal.

The WAF improves itself continuously by retraining on blocked requests.

🔥 Features

✅ Machine Learning classifier (TF-IDF + Logistic Regression)

✅ Regex rules as safety net

✅ Blocks + logs malicious requests

✅ Auto retrains every 10 minutes using new attack logs

✅ Exposes admin endpoints for health, retraining, config

📂 Workflow
flowchart LR
    Client -->|HTTP Request| WAF[waf.py]
    WAF -->|Malicious?| Logs[blocked.log]
    WAF -->|Safe| Backend[backend.py]

    Logs --> Retrain[train_model.py]
    Retrain --> Model[waf_model.joblib]
    Model --> WAF

    Auto[auto_retrain.py] --> Retrain


Client sends request → intercepted by waf.py.

WAF runs regex checks + ML classifier.

If malicious → blocked & logged into blocked.log.

If safe → forwarded to backend.py.

auto_retrain.py retrains model every 10 min with blocked.log.

WAF reloads updated model → gets smarter over time.

⚙️ Setup
1. Clone repo
   
git clone https://github.com/MyBoi50/AI-Driven-Web-Application-Firewall-WAF-

cd ai-waf

3. Install dependencies
   
pip install -r requirements.txt

5. Generate dataset
   
python make_dataset.py

7. Train initial model
   
python train_model.py --dataset dataset.json --out waf_model.joblib

9. Start backend (port 9000)
    
uvicorn backend:app --reload --port 9000

11. Start WAF (port 8080)
    
uvicorn waf:app --reload --port 8080


Now, access your app through the WAF:

http://127.0.0.1:8080/search?q=hello
 → allowed

http://127.0.0.1:8080/search?q=%3Cscript%3Ealert(1)%3C/script%3E
 → blocked 🚫

7. Run auto retrain (optional)
python auto_retrain.py

🔧 Admin Endpoints

/_waf/health → Check if model loaded

/_waf/last_decisions → Recent WAF verdicts

/_waf/retrain → Trigger manual retrain

/_waf/config → Adjust threshold/upstream

🛡️ Disclaimer

This project is for educational & research purposes only.
Do not deploy in production without rigorous testing.



