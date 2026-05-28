"""Demo website for WAF testing (FastAPI)."""

from typing import Dict, Any

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

app = FastAPI(title="WAF Demo Site")

HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>WAF Demo Site</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; background: #f6f7fb; color: #1f2937; }
    header { background: #0f172a; color: #fff; padding: 24px; }
    main { max-width: 980px; margin: 24px auto; padding: 0 16px; }
    .grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }
    .card { background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px; }
    button { padding: 10px 12px; border: 0; border-radius: 8px; background: #2563eb; color: #fff; cursor: pointer; }
    button.alt { background: #ef4444; }
    input, textarea { width: 100%; margin: 6px 0 12px; padding: 8px; border: 1px solid #d1d5db; border-radius: 6px; }
    .log { background: #0b1020; color: #e5e7eb; padding: 12px; border-radius: 8px; height: 200px; overflow: auto; font-family: Consolas, monospace; font-size: 12px; }
  </style>
</head>
<body>
  <header>
    <h1>WAF Demo Site</h1>
    <p>Use this site behind the WAF proxy to generate normal and suspicious requests.</p>
  </header>
  <main>
    <div class="grid">
      <div class="card">
        <h2>Normal Requests</h2>
        <button onclick="callGet('/api/events')">Load Events</button>
        <button onclick="callGet('/api/profile')">Load Profile</button>
        <div>
          <label>Login (normal)</label>
          <input id="user" value="user" />
          <input id="pass" type="password" value="password" />
          <button onclick="login(false)">Login</button>
        </div>
      </div>
      <div class="card">
        <h2>Attack-Style Requests</h2>
        <button class="alt" onclick="callGet('/api/search?q=%3Cscript%3Ealert(1)%3C/script%3E')">XSS Query</button>
        <button class="alt" onclick="callGet('/api/files?path=../../etc/passwd')">Path Traversal</button>
        <button class="alt" onclick="callPost('/api/exec', {cmd: 'ls; cat /etc/passwd'})">Command Injection</button>
        <div>
          <label>Login (SQL injection style)</label>
          <input id="sqli" value="admin' OR '1'='1" />
          <button class="alt" onclick="login(true)">Login</button>
        </div>
      </div>
      <div class="card">
        <h2>Request Log</h2>
        <div id="log" class="log"></div>
      </div>
    </div>
  </main>
  <script>
    const logEl = document.getElementById('log');

    function writeLog(message) {
      const time = new Date().toISOString();
      logEl.textContent = `[${time}] ${message}\n` + logEl.textContent;
    }

    async function callGet(path) {
      writeLog(`GET ${path}`);
      const res = await fetch(path, { method: 'GET' });
      writeLog(`Response ${res.status}`);
    }

    async function callPost(path, body) {
      writeLog(`POST ${path}`);
      const res = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      writeLog(`Response ${res.status}`);
    }

    async function login(isAttack) {
      const username = isAttack ? document.getElementById('sqli').value : document.getElementById('user').value;
      const password = isAttack ? "password" : document.getElementById('pass').value;
      await callPost('/api/auth/login', { username, password });
    }
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse(HTML_PAGE)


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/api/events")
async def events() -> Dict[str, Any]:
    return {"events": [{"id": 1, "title": "Tech Talk"}, {"id": 2, "title": "Workshop"}]}


@app.get("/api/profile")
async def profile() -> Dict[str, Any]:
    return {"name": "Student", "role": "member"}


@app.get("/api/search")
async def search(q: str = "") -> Dict[str, Any]:
    return {"query": q, "results": []}


@app.get("/api/files")
async def files(path: str = "") -> Dict[str, Any]:
    return {"path": path, "status": "not_found"}


@app.post("/api/auth/login")
async def login(request: Request) -> JSONResponse:
    data = await request.json()
    username = data.get("username", "")
    password = data.get("password", "")

    if username == "user" and password == "password":
        return JSONResponse({"status": "ok", "token": "demo-token"})

    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post("/api/exec")
async def exec_cmd(request: Request) -> Dict[str, Any]:
    data = await request.json()
    return {"status": "queued", "cmd": data.get("cmd", "")}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5000)
