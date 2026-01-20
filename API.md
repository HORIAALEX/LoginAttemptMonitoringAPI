# Login Attempt Tracker API (cURL)

Base URL: `http://127.0.0.1:8000`

## Health

```bash
curl http://127.0.0.1:8000/
```

## Create login attempt

```bash
curl -X POST http://127.0.0.1:8000/login-attempts \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "ip_address": "127.0.0.1",
    "success": false,
    "user_agent": "curl"
  }'
```

## List login attempts (all)

```bash
curl "http://127.0.0.1:8000/login-attempts"
```

## List login attempts (paging)

```bash
curl "http://127.0.0.1:8000/login-attempts?page=1&size=20"
```

## List login attempts (filter by username)

```bash
curl "http://127.0.0.1:8000/login-attempts?username=alice&page=1&size=20"
```

## Get login attempt by id

```bash
curl "http://127.0.0.1:8000/login-attempts/{attempt_id}"
```

## Update login attempt by id (PUT)

```bash
curl -X PUT "http://127.0.0.1:8000/login-attempts/{attempt_id}" \
  -H "Content-Type: application/json" \
  -d '{
    "success": true,
    "user_agent": "updated-agent"
  }'
```

## Delete login attempt by id

```bash
curl -X DELETE "http://127.0.0.1:8000/login-attempts/{attempt_id}"
```

## Failed login alerts (last 5 minutes, min 5 attempts)

```bash
curl "http://127.0.0.1:8000/alerts/failed-logins"
```
