import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch import NotFoundError
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse, HTMLResponse
from pathlib import Path
from typing import Optional

# ================= FastAPI App =================
app = FastAPI(title="Login Attempt Tracker")

# ================= Rate Limiter =================
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


# ================= Error Envelopes =================
def error_response(code: str, message: str, status_code: int, details=None):
    payload = {"error": {"code": code, "message": message}}
    if details is not None:
        payload["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=payload)


@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return error_response("rate_limited", "Too many login attempts", 429)


@app.exception_handler(HTTPException)
def http_exception_handler(request: Request, exc: HTTPException):
    return error_response("http_error", str(exc.detail), exc.status_code)


@app.exception_handler(RequestValidationError)
def validation_exception_handler(request: Request, exc: RequestValidationError):
    return error_response("validation_error", "Invalid request", 422, details=exc.errors())


# ================= Elasticsearch Client =================
ES_HOST = os.getenv("ELASTIC_URL", "http://localhost:9200")
ES_USER = os.getenv("ELASTIC_USER", "elastic")
ES_PASSWORD = os.getenv("ELASTIC_PASSWORD", "oUjJ1jPAv9dToVff9ZwQ")

es = Elasticsearch(
    [ES_HOST],
    basic_auth=(ES_USER, ES_PASSWORD),
    verify_certs=False,
)


# ================= Data Models =================
class LoginAttempt(BaseModel):
    username: str
    ip_address: str
    success: bool
    user_agent: Optional[str] = None


class LoginAttemptUpdate(BaseModel):
    username: Optional[str] = None
    ip_address: Optional[str] = None
    success: Optional[bool] = None
    user_agent: Optional[str] = None


# ================= Routes =================
INDEX_NAME = "login_attempts"


@app.post("/login-attempts", status_code=201)
@limiter.limit("5/minute")
def create_login_attempt(request: Request, attempt: LoginAttempt):
    doc = {
        "username": attempt.username,
        "ip_address": attempt.ip_address,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "success": attempt.success,
        "user_agent": attempt.user_agent,
    }
    res = es.index(index=INDEX_NAME, document=doc)
    return {"id": res["_id"], "attempt": doc}


@app.get("/login-attempts")
def list_login_attempts(username: Optional[str] = None, page: int = 1, size: int = 20):
    size = max(1, min(size, 100))
    page = max(1, page)
    offset = (page - 1) * size
    query = {"match_all": {}} if not username else {"term": {"username.keyword": username}}
    res = es.search(
        index=INDEX_NAME,
        from_=offset,
        size=size,
        query=query,
        sort=[{"timestamp": {"order": "desc"}}],
    )
    total_raw = res["hits"]["total"]
    total = total_raw["value"] if isinstance(total_raw, dict) else total_raw
    attempts = [hit["_source"] | {"id": hit["_id"]} for hit in res["hits"]["hits"]]
    return {"page": page, "size": size, "total": total, "attempts": attempts}


@app.get("/login-attempts/{attempt_id}")
def get_login_attempt(attempt_id: str):
    try:
        res = es.get(index=INDEX_NAME, id=attempt_id)
        return {"id": res["_id"], "attempt": res["_source"]}
    except NotFoundError:
        return error_response("not_found", "Login attempt not found", 404)


@app.put("/login-attempts/{attempt_id}")
def update_login_attempt(attempt_id: str, payload: LoginAttemptUpdate):
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not updates:
        return {"message": "No changes applied"}
    try:
        es.update(index=INDEX_NAME, id=attempt_id, doc={"doc": updates})
        res = es.get(index=INDEX_NAME, id=attempt_id)
        return {"id": res["_id"], "attempt": res["_source"]}
    except NotFoundError:
        return error_response("not_found", "Login attempt not found", 404)


@app.delete("/login-attempts/{attempt_id}")
def delete_login_attempt(attempt_id: str):
    try:
        es.delete(index=INDEX_NAME, id=attempt_id)
        return {"message": "Deleted", "id": attempt_id}
    except NotFoundError:
        return error_response("not_found", "Login attempt not found", 404)


@app.get("/alerts/failed-logins")
def failed_login_alerts():
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"success": False}},
                    {"range": {"timestamp": {"gte": "now-5m"}}},
                ]
            }
        },
        "aggs": {"by_user": {"terms": {"field": "username", "min_doc_count": 5}}},
    }
    res = es.search(index=INDEX_NAME, body=query)
    return res["aggregations"]["by_user"]["buckets"]


# ================= Root Endpoint =================
@app.get("/")
def root():
    return {"message": "Login Attempt Tracker API is running"}


@app.get("/docs", include_in_schema=False)
def api_docs():
    html_path = Path(__file__).parent / "index.html"
    return HTMLResponse(html_path.read_text(encoding="utf-8"))
