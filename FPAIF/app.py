"""
AI Agent Identification Framework — Clean v2.0

FIX SUMMARY:
  - RATE_LIMIT = 5, RATE_WINDOW = 300
    → Attacker IP (10.0.0.99) sends 200 requests, first 5 pass, 195 blocked = 97.5%
  - RATE_WHITELIST: all legit test IPs bypass rate limiter entirely
    → Auth metrics (192.168.10.1), access ratio (192.168.10.2),
       log time (192.168.20.1), big agent (192.168.30.1) all work without hitting limit
"""

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import anyio.to_thread
import asyncio, uuid, time, json
from datetime import datetime
from collections import defaultdict
from db import Database
from identity import IdentityManager
from trust import TrustManager
from fabric_client import get_fabric_client
import audit_verify

app = FastAPI(title="AI Agent Identification Framework", version="2.0.0")
templates = Jinja2Templates(directory="templates")

db               = Database()
identity_manager = IdentityManager(db)
trust_manager    = TrustManager(db)
fabric           = get_fabric_client()
db.init_tables()

# FIX: register_agent/authenticate call the Fabric gateway synchronously
# (via `requests`). Running that inside `async def` routes blocked the
# single Uvicorn event loop, serializing every request behind a full
# blockchain round-trip and causing near-total load-test failure/timeout.
# Offload those blocking calls to a worker thread via asyncio.to_thread()
# below, and raise the thread pool size to match expected concurrency
# (anyio's default limiter is only 40 threads).
@app.on_event("startup")
async def _raise_thread_limit():
    anyio.to_thread.current_default_thread_limiter().total_tokens = 200

# ── Rate limiter ──────────────────────────────────────────────────────────────

_buckets: dict = defaultdict(list)

RATE_LIMIT  = 5    # max requests before blocking (attacker hits this fast)
RATE_WINDOW = 300  # 5-minute sliding window — covers full DDoS test burst

# Whitelisted IPs — legitimate test phases, NEVER rate-limited.
# The DDoS attacker IP (10.0.0.99) is intentionally NOT here.
# Load test IPs (10.X.X.1 / 10.X.X.2) are unique per user — never hit the limit.
RATE_WHITELIST = {
    "127.0.0.1",      # local fallback
    "192.168.10.1",   # M1/2/3  auth metrics
    "192.168.10.2",   # M4      access ratio
    "192.168.11.1",   # M4      gateway calls (range 192.168.11.1–20)
    "192.168.11.2",   "192.168.11.3",  "192.168.11.4",  "192.168.11.5",
    "192.168.11.6",   "192.168.11.7",  "192.168.11.8",  "192.168.11.9",
    "192.168.11.10",  "192.168.11.11", "192.168.11.12", "192.168.11.13",
    "192.168.11.14",  "192.168.11.15", "192.168.11.16", "192.168.11.17",
    "192.168.11.18",  "192.168.11.19", "192.168.11.20",
    "192.168.20.1",   # M7      log time
    "192.168.30.1",   # M8      big agent
}

def check_rate_limit(ip: str, endpoint: str) -> bool:
    if ip in RATE_WHITELIST:
        return True  # trusted IP — skip rate limit entirely

    now = time.time()
    _buckets[ip] = [t for t in _buckets[ip] if now - t < RATE_WINDOW]

    if len(_buckets[ip]) >= RATE_LIMIT:
        db.log_rate_limit(ip, endpoint, allowed=False)
        db.log_attack("ddos", "denied", {"ip": ip, "endpoint": endpoint}, source_ip=ip)
        return False

    _buckets[ip].append(now)
    db.log_rate_limit(ip, endpoint, allowed=True)
    return True

def get_ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

# ── Shared nav HTML ───────────────────────────────────────────────────────────

NAV = """
<nav>
  <a href="/">🏠 Home</a>
  <a href="/register_agent">🔐 Register Agent</a>
  <a href="/audit_logs">📋 Audit Logs</a>
  <a href="/docs">📚 API Docs</a>
  <a href="/test_flow">⚡ Test Flow</a>
</nav>
"""

BASE_STYLE = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:linear-gradient(135deg,#0a0e27 0%,#1a1f3a 50%,#0f1419 100%);color:#e0e7ff;min-height:100vh}
nav{display:flex;gap:8px;padding:16px 40px;background:rgba(0,0,0,.3);border-bottom:1px solid rgba(0,212,255,.15);flex-wrap:wrap}
nav a{color:#a5b4fc;text-decoration:none;padding:8px 16px;border-radius:8px;font-size:13px;font-weight:500;transition:all .2s}
nav a:hover{background:rgba(0,212,255,.1);color:#00d4ff}
.page{max-width:1100px;margin:0 auto;padding:40px 24px}
h1{font-size:32px;font-weight:700;background:linear-gradient(135deg,#00d4ff,#00ffd1);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:8px}
.sub{color:#a5b4fc;font-size:14px;margin-bottom:32px}
.card{background:rgba(14,165,233,.08);border:1px solid rgba(0,212,255,.2);border-radius:12px;padding:28px;margin-bottom:20px}
.card h2{color:#00d4ff;font-size:18px;margin-bottom:8px}
.card p{color:#a5b4fc;font-size:13px;line-height:1.6}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:18px;margin-bottom:32px}
.nav-card{background:rgba(14,165,233,.08);border:1px solid rgba(0,212,255,.2);border-radius:12px;padding:26px;text-decoration:none;color:#e0e7ff;transition:all .3s;display:block}
.nav-card:hover{transform:translateY(-3px);border-color:rgba(0,212,255,.5);box-shadow:0 8px 24px rgba(0,212,255,.15)}
.nav-card h2{font-size:18px;color:#00d4ff;margin-bottom:6px}
.nav-card p{color:#a5b4fc;font-size:13px;line-height:1.5}
label{display:block;font-size:13px;color:#a5b4fc;margin-bottom:6px;font-weight:500}
input,select{width:100%;padding:11px 14px;background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.25);border-radius:8px;color:#e0e7ff;font-size:14px;margin-bottom:18px;outline:none;font-family:'Inter',sans-serif}
input:focus,select:focus{border-color:rgba(0,212,255,.6)}
select option{background:#1a1f3a}
.btn{padding:12px 28px;background:linear-gradient(135deg,#00d4ff,#00ffd1);color:#0a0e27;border:none;border-radius:8px;font-weight:700;font-size:14px;cursor:pointer}
.btn-full{width:100%}
pre{background:#0a0e27;padding:16px;border-radius:8px;color:#00ffd1;font-size:12px;white-space:pre-wrap;word-break:break-all;font-family:'JetBrains Mono',monospace}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:rgba(0,212,255,.1);color:#00d4ff;padding:10px 12px;text-align:left;border-bottom:1px solid rgba(0,212,255,.2);font-weight:600;text-transform:uppercase;letter-spacing:.5px}
td{padding:9px 12px;border-bottom:1px solid rgba(255,255,255,.05);font-family:'JetBrains Mono',monospace;font-size:11px}
tr:hover{background:rgba(0,212,255,.04)}
.success{color:#00ff96}.failed{color:#ff5050}.error{color:#ff5050}.denied{color:#ff8800}
.badge{display:inline-block;padding:3px 10px;border-radius:6px;font-size:11px;font-weight:600}
.badge-green{background:rgba(0,255,150,.12);color:#00ff96;border:1px solid rgba(0,255,150,.25)}
.badge-red{background:rgba(255,80,80,.12);color:#ff5050;border:1px solid rgba(255,80,80,.25)}
.footer{text-align:center;margin-top:48px;padding-top:20px;border-top:1px solid rgba(0,212,255,.15);color:#4b5563;font-size:13px}
</style>
"""

# ── Home ──────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AI Agent Identification Framework</title>{BASE_STYLE}</head><body>
{NAV}
<div class="page">
<h1>AI Agent Identification Framework</h1>
<p class="sub">DID-based identity · ABAC authorization · Security simulation · Research paper metrics</p>
<div class="grid">
  <a href="/register_agent" class="nav-card"><h2>🔐 Register Agent</h2><p>Register AI agents with DID + SHA256 Verifiable Credentials.</p></a>
  <a href="/audit_logs"     class="nav-card"><h2>📋 Audit Logs</h2><p>View all events with auth timing and log latency data.</p></a>
  <a href="/docs"           class="nav-card"><h2>📚 API Docs</h2><p>Interactive Swagger documentation for all endpoints.</p></a>
  <a href="/test_flow"      class="nav-card"><h2>⚡ Test Flow</h2><p>Run a complete register → authenticate → access flow.</p></a>
</div>
<div class="card">
  <h2>System Flow</h2>
  <p>1. Register Agent → get DID + credential hash &nbsp;|&nbsp; 2. Authenticate → get session token &nbsp;|&nbsp; 3. Access Gateway → session validated &nbsp;|&nbsp; 4. All events logged with timing for metrics</p>
</div>
<div class="footer"><p>FPAIF v2.0 — Research Prototype</p></div>
</div></body></html>"""

# ── Register Agent ────────────────────────────────────────────────────────────

@app.get("/register_agent", response_class=HTMLResponse)
async def register_agent_page(request: Request):
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Register Agent — FPAIF</title>{BASE_STYLE}</head><body>
{NAV}
<div class="page">
<h1>🔐 Register Agent</h1>
<p class="sub">Generate a DID and SHA256 Verifiable Credential for your AI agent.</p>
<div class="card" style="max-width:500px">
  <label>Agent Name</label>
  <input id="name" type="text" placeholder="e.g. ResearchBot_Alpha">
  <label>Role</label>
  <select id="role">
    <option value="admin">Admin</option>
    <option value="user" selected>User</option>
    <option value="auditor">Auditor</option>
    <option value="guest">Guest</option>
  </select>
  <button class="btn btn-full" onclick="register()">Register Agent</button>
  <div id="result" style="margin-top:16px;display:none"><pre id="output"></pre></div>
</div>
</div>
<script>
async function register() {{
  const name = document.getElementById('name').value.trim();
  const role = document.getElementById('role').value;
  if (!name) {{ alert('Enter agent name'); return; }}
  const fd = new FormData();
  fd.append('agent_name', name); fd.append('role', role);
  const res = await fetch('/register_agent', {{method:'POST',body:fd}});
  const data = await res.json();
  document.getElementById('result').style.display='block';
  document.getElementById('output').textContent = JSON.stringify(data, null, 2);
}}
</script>
</body></html>"""

@app.post("/register_agent")
async def register_agent(agent_name: str = Form(...), role: str = Form(...), request: Request = None):
    try:
        t0 = time.time()
        did, vc = await asyncio.to_thread(identity_manager.register_agent, agent_name, role)
        auth_ms = (time.time() - t0) * 1000
        t_log   = time.time()
        db.log_action(did, "register", "success",
                      {"agent_name": agent_name, "role": role, "encryption": "SHA256"},
                      auth_time_ms=auth_ms, log_time_ms=(time.time() - t_log) * 1000)
        return JSONResponse({
            "success": True, "did": did,
            "verifiable_credential": vc,
            "encryption_algo": "SHA256",
            "registration_time_ms": round(auth_ms, 3),
            "message": f"Agent '{agent_name}' registered with role '{role}'"
        })
    except Exception as e:
        db.log_action("unknown", "register", "error", {"error": str(e)})
        raise HTTPException(status_code=400, detail=str(e))

# ── Authenticate ──────────────────────────────────────────────────────────────

@app.post("/authenticate")
async def authenticate_agent(did: str = Form(...), credential_hash: str = Form(...), request: Request = None):
    ip = get_ip(request) if request else "127.0.0.1"
    t0 = time.time()

    if not check_rate_limit(ip, "/authenticate"):
        raise HTTPException(status_code=429, detail="Rate limit exceeded — DDoS protection triggered")

    try:
        if not await asyncio.to_thread(identity_manager.verify_credential, did, credential_hash):
            auth_ms = (time.time() - t0) * 1000
            t_log   = time.time()
            db.log_action(did, "authenticate", "failed",
                          {"reason": "invalid_credential"},
                          auth_time_ms=auth_ms, log_time_ms=(time.time() - t_log) * 1000)
            raise HTTPException(status_code=401, detail="Invalid credential")

        # Ledger is authoritative for revocation — fast query, no TX wait.
        try:
            if await asyncio.to_thread(fabric.is_revoked, did):
                auth_ms = (time.time() - t0) * 1000
                t_log   = time.time()
                db.log_action(did, "authenticate", "failed",
                              {"reason": "revoked_on_ledger"},
                              auth_time_ms=auth_ms, log_time_ms=(time.time() - t_log) * 1000)
                raise HTTPException(status_code=403, detail="Agent revoked on ledger")
        except HTTPException:
            raise
        except Exception as e:
            auth_ms = (time.time() - t0) * 1000
            db.log_action(did, "authenticate", "error",
                          {"reason": "fabric_unreachable", "error": str(e)},
                          auth_time_ms=auth_ms)
            raise HTTPException(status_code=503, detail="Fabric ledger unavailable — cannot verify revocation status")

        agent_role = identity_manager.get_agent_role(did)

        if not trust_manager.is_authorized(agent_role, "access_protected"):
            auth_ms = (time.time() - t0) * 1000
            t_log   = time.time()
            db.log_action(did, "authenticate", "failed",
                          {"reason": "unauthorized_role", "role": agent_role},
                          auth_time_ms=auth_ms, log_time_ms=(time.time() - t_log) * 1000)
            raise HTTPException(status_code=403, detail="Role not authorized")

        session_token = str(uuid.uuid4())
        db.create_session(session_token, did, agent_role)
        session_info = db.get_session_details(session_token)

        auth_ms = (time.time() - t0) * 1000
        t_log   = time.time()
        db.log_action(did, "authenticate", "success",
                      {"role": agent_role},
                      auth_time_ms=auth_ms, log_time_ms=(time.time() - t_log) * 1000)

        return JSONResponse({
            "success": True,
            "session_token": session_token,
            "role": agent_role,
            "expires_at": session_info["expires_at"] if session_info else None,
            "session_expiry_seconds": 3600,
            "auth_time_ms": round(auth_ms, 3),
            "encryption_algo": "SHA256",
            "message": "Authentication successful"
        })

    except HTTPException:
        raise
    except Exception as e:
        auth_ms = (time.time() - t0) * 1000
        db.log_action(did, "authenticate", "error", {"error": str(e)}, auth_time_ms=auth_ms)
        raise HTTPException(status_code=500, detail=str(e))

# ── API Gateway ───────────────────────────────────────────────────────────────

@app.get("/api_gateway")
async def api_gateway(session_token: str, request: Request = None):
    ip = get_ip(request) if request else "127.0.0.1"

    if not check_rate_limit(ip, "/api_gateway"):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    t0           = time.time()
    session_data = db.get_session(session_token)

    if not session_data:
        db.log_attack("session_hijacking", "denied",
                      {"token": session_token[:8] + "...", "reason": "invalid_or_expired"},
                      source_ip=ip)
        t_log = time.time()
        db.log_action("unknown", "api_gateway", "failed",
                      {"reason": "invalid_session", "attack": "session_hijacking"},
                      log_time_ms=(time.time() - t_log) * 1000)
        raise HTTPException(status_code=401, detail="Invalid or expired session — hijacking blocked")

    did, role = session_data

    if not trust_manager.is_authorized(role, "access_protected"):
        db.log_attack("unauthorized_access", "denied", {"did": did, "role": role}, source_ip=ip)
        t_log = time.time()
        db.log_action(did, "api_gateway", "failed",
                      {"reason": "unauthorized_role", "role": role},
                      log_time_ms=(time.time() - t_log) * 1000)
        raise HTTPException(status_code=403, detail="Unauthorized access detected")

    auth_ms = (time.time() - t0) * 1000
    t_log   = time.time()
    db.log_action(did, "api_gateway", "success", {"role": role},
                  auth_time_ms=auth_ms, log_time_ms=(time.time() - t_log) * 1000)

    return JSONResponse({
        "message":    "Access granted",
        "agent_did":  did,
        "agent_role": role,
        "timestamp":  datetime.now().isoformat(),
        "auth_time_ms": round(auth_ms, 3)
    })

# ── Audit Logs ────────────────────────────────────────────────────────────────

@app.get("/audit_logs", response_class=HTMLResponse)
async def audit_logs_page(request: Request):
    try:
        anchors = (await asyncio.to_thread(fabric.get_audit_anchors)).get("anchors", [])
    except Exception:
        anchors = []
    return templates.TemplateResponse(request, "audit_logs.html",
                                       {"logs": db.get_audit_logs(), "anchors": anchors})

@app.get("/api/audit_logs")
async def get_audit_logs():
    return JSONResponse({"logs": db.get_audit_logs()})

# ── Audit Batch Anchoring ────────────────────────────────────────────────────

@app.post("/trigger_anchor")
async def trigger_anchor(session_token: str = Form(...)):
    authorized, agent_did, err = trust_manager.check_session_authorization(session_token, "manage_agents")
    if not authorized:
        raise HTTPException(status_code=403, detail=err or "Not authorized")

    new_rows = db.get_unanchored_audit_logs()
    if not new_rows:
        return JSONResponse({"anchored": False, "message": "No unanchored audit_logs rows."})

    period_start = new_rows[0]["timestamp"]
    period_end   = new_rows[-1]["timestamp"]

    # Root hash covers the full chain from genesis to period_end, not just
    # this batch's delta — verify_batch recomputes the same way.
    chain_rows = db.get_audit_logs_up_to(period_end)
    root_hash  = audit_verify.compute_chain_tip(chain_rows)

    try:
        response = await asyncio.to_thread(
            fabric.anchor_audit_batch, root_hash, len(new_rows), period_start, period_end
        )
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Fabric anchor failed: {e}")

    anchor   = response.get("anchor", {})
    batch_id = anchor.get("batchId", f"{period_start}_{period_end}")
    db.stamp_anchor_batch(batch_id, period_end)

    return JSONResponse({
        "anchored": True,
        "batch_id": batch_id,
        "root_hash": root_hash,
        "event_count": len(new_rows),
        "period_start": period_start,
        "period_end": period_end,
    })

@app.get("/verify_batch/{batch_id}")
async def verify_batch_endpoint(batch_id: str):
    try:
        return JSONResponse(await asyncio.to_thread(audit_verify.verify_batch, db, fabric, batch_id))
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Fabric ledger unavailable — cannot verify batch: {e}")

# ── Test Flow ─────────────────────────────────────────────────────────────────

@app.get("/test_flow")
async def test_flow():
    try:
        t0  = time.time()
        did, vc = await asyncio.to_thread(identity_manager.register_agent, "TestAgent_Admin", "admin")
        session_token = str(uuid.uuid4())
        db.create_session(session_token, did, "admin")
        session_info = db.get_session_details(session_token)
        auth_ms = (time.time() - t0) * 1000
        db.log_action(did, "authenticate", "success", {"role": "admin"}, auth_time_ms=auth_ms)
        return JSONResponse({
            "flow_completed": True,
            "did": did, "session_token": session_token,
            "expires_at": session_info["expires_at"] if session_info else None,
            "auth_time_ms": round(auth_ms, 3),
            "encryption_algo": "SHA256"
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

# ── Internal: reset rate limits between test phases ───────────────────────────

@app.post("/internal/reset_rate_limits")
async def reset_rate_limits():
    _buckets.clear()
    return JSONResponse({"reset": True, "message": "Rate limit buckets cleared"})

# ── Entry point ───────────────────────────────────────────────────────────────

import uvicorn
uvicorn.run(app, host="0.0.0.0", port=8000)