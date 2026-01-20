import os
from fastapi import FastAPI, Request
from pydantic import BaseModel
from datetime import datetime
from elasticsearch import Elasticsearch
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse
from typing import Optional

# ================= FastAPI App =================
app = FastAPI(title="Login Attempt Tracker")

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
    verify_certs=False  # ⚠️ Use proper certificates in production
)

# ================= Data Model =================
class LoginAttempt(BaseModel):
    username: str
    ip_address: str
    success: bool
    user_agent: Optional[str] = None

# ================= Routes =================
@app.post("/login-attempt/")
@limiter.limit("5/minute")  # Limit to 5 login attempts per minute per IP
def log_login_attempt(request: Request, attempt: LoginAttempt):
    doc = {
        "username": attempt.username,
        "ip_address": attempt.ip_address,
        "timestamp": datetime.utcnow(),
        "success": attempt.success,
        "user_agent": attempt.user_agent
    }
    res = es.index(index="login_attempts", document=doc)
    return {"message": "Login attempt logged", "id": res["_id"]}

@app.get("/login-attempts/{username}")
def get_attempts(username: str):
    res = es.search(
        index="login_attempts",
        query={"term": {"username": username}},
        sort=[{"timestamp": {"order": "desc"}}]
    )
    return {"attempts": [hit["_source"] for hit in res["hits"]["hits"]]}

@app.get("/alerts/failed-logins")
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
    res = es.search(index="login_attempts", body=query)
    return res["aggregations"]["by_user"]["buckets"]

# ================= Root Endpoint =================
@app.get("/")
def root():
    return {"message": "Login Attempt Tracker API is running"}
