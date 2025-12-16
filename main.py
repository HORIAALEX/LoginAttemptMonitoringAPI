import os
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from datetime import datetime
from elasticsearch import Elasticsearch
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse
from typing import Optional
import bcrypt

# ================= FastAPI App =================
app = FastAPI(
    title="Login Attempt Tracker",
    description="Secure login API with Elasticsearch logging",
    version="1.0.0"
)

# ================= Rate Limiter =================
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many login attempts"}
    )

# ================= Elasticsearch Client =================
ES_HOST = os.getenv("ELASTIC_URL", "https://localhost:9200")
ES_USER = os.getenv("ELASTIC_USER", "elastic")
ES_PASSWORD = os.getenv("ELASTIC_PASSWORD", "oUjJ1jPAv9dToVff9ZwQ")

es = Elasticsearch(
    [ES_HOST],
    basic_auth=(ES_USER, ES_PASSWORD),
    verify_certs=False  # ⚠️ Use proper certs in prod
)

INDEX_NAME = "login_attempts"

# ================= Dummy User Store =================
USERS = {
    "alice": bcrypt.hashpw(b"password123", bcrypt.gensalt()),
    "bob": bcrypt.hashpw(b"secret456", bcrypt.gensalt()),
}

# ================= Request Models =================
class LoginRequest(BaseModel):
    username: str
    password: str

class LoginAttempt(BaseModel):
    username: str
    ip_address: str
    success: bool
    user_agent: Optional[str] = None

# ================= Utility =================
def log_attempt(
    username: str,
    ip: str,
    success: bool,
    user_agent: Optional[str]
):
    doc = {
        "username": username,
        "ip_address": ip,
        "timestamp": datetime.utcnow(),
        "success": success,
        "user_agent": user_agent,
    }
    es.index(index=INDEX_NAME, document=doc)

# ================= Routes =================
@app.get("/", tags=["Health"])
def health():
    return {"message": "Login Attempt Tracker API is running"}

# ================= LOGIN ENDPOINT =================
@app.post("/login", tags=["Authentication"])
@limiter.limit("5/minute")
def login(request: Request, credentials: LoginRequest):
    username = credentials.username
    password = credentials.password.encode()
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent")

    stored_hash = USERS.get(username)

    success = (
        stored_hash is not None
        and bcrypt.checkpw(password, stored_hash)
    )

    log_attempt(username, ip_address, success, user_agent)

    # Generic error (no user enumeration)
    if not success:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    return {"message": "Login successful"}

# ================= Query Endpoints =================
@app.get("/login-attempts/{username}", tags=["Login Attempts"])
def get_attempts(username: str):
    res = es.search(
        index=INDEX_NAME,
        query={"term": {"username": username}},
        sort=[{"timestamp": {"order": "desc"}}]
    )
    return {"attempts": [hit["_source"] for hit in res["hits"]["hits"]]}

@app.get("/alerts/failed-logins", tags=["Alerts"])
def failed_login_alerts():
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"success": False}},
                    {"range": {"timestamp": {"gte": "now-5m"}}}
                ]
            }
        },
        "aggs": {
            "by_user": {
                "terms": {"field": "username", "min_doc_count": 5}
            }
        }
    }
    res = es.search(index=INDEX_NAME, body=query)
    return res["aggregations"]["by_user"]["buckets"]
