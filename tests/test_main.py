import bcrypt
from fastapi.testclient import TestClient

import main


class DummyES:
    def __init__(self):
        self.index_calls = []
        self.search_calls = []
        self.ping_ok = True

    def index(self, index, document):
        self.index_calls.append((index, document))
        return {"result": "created"}

    def search(self, **kwargs):
        self.search_calls.append(kwargs)
        docs = [doc for _, doc in self.index_calls]
        return {
            "hits": {
                "total": {"value": len(docs)},
                "hits": [{"_source": doc} for doc in docs],
            }
        }

    def ping(self):
        return self.ping_ok


def setup_state():
    main.USERS.clear()
    main.USERS["alice"] = bcrypt.hashpw(b"Password1", bcrypt.gensalt())
    main.refresh_tokens.clear()
    main.failed_attempts.clear()
    main.lockout_until.clear()
    main.user_attempts.clear()
    storage = getattr(main.limiter, "storage", None) or getattr(main.limiter, "_storage", None)
    if storage is not None:
        if hasattr(storage, "reset"):
            storage.reset()
        elif hasattr(storage, "clear"):
            storage.clear()


def test_login_success_and_fail():
    setup_state()
    dummy = DummyES()
    main.es = dummy
    client = TestClient(main.app)

    ok = client.post("/sessions", json={"username": "alice", "password": "Password1"})
    assert ok.status_code == 201
    assert "access_token" in ok.json()["data"]
    assert len(dummy.index_calls) == 1
    assert dummy.index_calls[0][1]["success"] is True

    bad = client.post("/sessions", json={"username": "alice", "password": "wrong"})
    assert bad.status_code == 401
    assert len(dummy.index_calls) == 2
    assert dummy.index_calls[1][1]["success"] is False


def test_rate_limit_per_user():
    setup_state()
    dummy = DummyES()
    main.es = dummy
    main.MAX_ATTEMPTS_PER_USER_PER_MIN = 2
    main.LOCKOUT_THRESHOLD = 100
    client = TestClient(main.app)

    r1 = client.post("/sessions", json={"username": "alice", "password": "wrong"})
    r2 = client.post("/sessions", json={"username": "alice", "password": "wrong"})
    r3 = client.post("/sessions", json={"username": "alice", "password": "wrong"})
    assert r1.status_code == 401
    assert r2.status_code == 401
    assert r3.status_code == 429


def test_lockout_and_unblock():
    setup_state()
    dummy = DummyES()
    main.es = dummy
    main.LOCKOUT_THRESHOLD = 2
    main.LOCKOUT_WINDOW_SECONDS = 300
    main.LOCKOUT_DURATION_SECONDS = 600
    main.MAX_ATTEMPTS_PER_USER_PER_MIN = 100
    client = TestClient(main.app)

    first = client.post("/sessions", json={"username": "alice", "password": "wrong"})
    second = client.post("/sessions", json={"username": "alice", "password": "wrong"})
    assert first.status_code == 401
    assert second.status_code == 423

    status = client.get("/users/alice/lockout")
    assert status.status_code == 200
    assert status.json()["data"]["locked"] is True

    unblock = client.post("/users/alice/lockout/unblock")
    assert unblock.status_code == 200
    status2 = client.get("/users/alice/lockout")
    assert status2.json()["data"]["locked"] is False


def test_health_endpoints():
    setup_state()
    dummy = DummyES()
    main.es = dummy
    client = TestClient(main.app)

    root = client.get("/health")
    assert root.status_code == 200

    health = client.get("/health/elasticsearch")
    assert health.status_code == 200
    assert health.json()["data"]["status"] == "ok"
