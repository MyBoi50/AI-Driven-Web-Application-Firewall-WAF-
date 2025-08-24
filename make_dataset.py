# make_dataset.py
import json
import random

SAFE_TEMPLATES = [
    "search?q={t}",
    "echo?q={t}",
    "login?user={u}&password={p}",
    "profile?id={id}",
    "products?category={t}",
]
SQLI_TEMPLATES = [
    "login?user={u}' OR 1=1 --&password={p}",
    "search?q=' OR '1'='1",
    "search?q=UNION SELECT {c}",
    "search?q=SELECT * FROM users WHERE id={id}",
    "search?q=DROP TABLE {t}",
]
XSS_TEMPLATES = [
    "search?q=<script>alert(1)</script>",
    "echo?q=<img src=x onerror=alert('XSS')>",
    "search?q=<svg/onload=alert('XSS')>",
    "search?q=<iframe src=javascript:alert(1)>",
    "search?q=<body onload=alert('XSS')>",
]
CMD_TEMPLATES = [
    "search?q=; ls -la",
    "search?q=| whoami",
    "search?q=$(id)",
    "search?q=`uname -a`",
    "search?q=|| shutdown -h now",
]
PATH_TEMPLATES = [
    "search?q=../../etc/passwd",
    "search?q=..%2f..%2f..%2fetc%2fpasswd",
    "search?q=..\\..\\..\\windows\\system32",
    "search?q=/etc/passwd",
    "search?q=..%2F..%2Fboot.ini",
]

def random_word():
    words = ["hello","books","python","example","safe","user","product","order","search","id"]
    return random.choice(words) + str(random.randint(1,9999))

def gen_records(n_safe=300, n_sqli=250, n_xss=200, n_cmd=150, n_path=150):
    recs = []
    for _ in range(n_safe):
        t = random_word()
        u = "user" + str(random.randint(1,500))
        p = "pass" + str(random.randint(100,999))
        idv = random.randint(1,5000)
        tmpl = random.choice(SAFE_TEMPLATES)
        recs.append({"query": tmpl.format(t=t,u=u,p=p,id=idv), "label": "safe"})
    for _ in range(n_sqli):
        t = random_word()
        u = "admin" + str(random.randint(1,400))
        p = "p"
        idv = random.randint(1,5000)
        c = ",".join(["null"]*random.randint(2,6))
        tmpl = random.choice(SQLI_TEMPLATES)
        recs.append({"query": tmpl.format(t=t,u=u,p=p,id=idv,c=c), "label": "sql_injection"})
    for _ in range(n_xss):
        tmpl = random.choice(XSS_TEMPLATES)
        recs.append({"query": tmpl, "label": "xss"})
    for _ in range(n_cmd):
        tmpl = random.choice(CMD_TEMPLATES)
        recs.append({"query": tmpl, "label": "command_injection"})
    for _ in range(n_path):
        tmpl = random.choice(PATH_TEMPLATES)
        recs.append({"query": tmpl, "label": "path_traversal"})
    random.shuffle(recs)
    return recs

if __name__ == "__main__":
    # Produces ~1050 examples by default
    records = gen_records()
    with open("dataset.json", "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
    print(f"Generated dataset.json with {len(records)} records.")
