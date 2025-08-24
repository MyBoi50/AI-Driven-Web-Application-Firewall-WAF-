from fastapi import FastAPI, Request

app = FastAPI()

@app.get("/")
def home():
    return {"message": "Hello from backend", "tip": "Try /echo?q=hello or /search?q=python"}

@app.get("/echo")
def echo(q: str = ""):
    return {"echo": q}

@app.get("/search")
def search(q: str = ""):
    # Fake search logic (vulnerable style, just returns query back)
    return {"results": f"You searched for: {q}"}

@app.get("/login")
def login(user: str = "", password: str = ""):
    # Intentionally naive/vulnerable (just for WAF testing)
    if "admin" in user and "123" in password:
        return {"login": "success", "user": user}
    else:
        return {"login": "failed", "user": user}
