"""
baselines.py - comparison systems for the FPAIF evaluation
==========================================================
FPAIF can run in three modes, chosen with the FPAIF_MODE environment variable.
All three share the same HTTP API, the same rate limiter and the same
SQLite credential store, so the identical test suite runs against each.

  fabric (default)  B2  FPAIF as published: identity + revocation on the
                        Hyperledger Fabric ledger, SQLite sessions, audit log.
  local             B1  FPAIF without the blockchain: the ledger calls are served
                        by a local SQLite registry. Same logic, no consensus.
                        (B2 - B1 = cost of Fabric)
  jwt               B0  Plain token auth, the OAuth/JWT-style minimum: credential
                        check -> signed HS256 JWT; the gateway only verifies the
                        signature and expiry. No ledger, no revocation check, no
                        server-side session table, no audit log.
                        (B1 - B0 = cost of FPAIF's logic)

Other env vars: FPAIF_DB (SQLite file), FPAIF_LEDGER_DB (local ledger file),
FPAIF_PORT (default 8000), FPAIF_JWT_SECRET.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime
from typing import Dict, Optional, Tuple

MODE = os.environ.get("FPAIF_MODE", "fabric").lower()
if MODE not in ("fabric", "local", "jwt"):
    raise SystemExit(f"FPAIF_MODE must be fabric, local or jwt (got {MODE!r})")

JWT_TTL_SECONDS = 3600  # same lifetime as the SQLite sessions in db.create_session
_JWT_SECRET = os.environ.get("FPAIF_JWT_SECRET", secrets.token_hex(32)).encode()


# ── Minimal HS256 JWT (stdlib only) ───────────────────────────────────────────

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue_jwt(did: str, role: str) -> Tuple[str, str]:
    """Returns (token, expires_at_iso)."""
    now = int(time.time())
    exp = now + JWT_TTL_SECONDS
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64(json.dumps({"sub": did, "role": role, "iat": now, "exp": exp,
                            "jti": uuid.uuid4().hex}, separators=(",", ":")).encode())
    sig = _b64(hmac.new(_JWT_SECRET, f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}", datetime.fromtimestamp(exp).isoformat()


def verify_jwt(token: str) -> Optional[Tuple[str, str]]:
    """Returns (did, role) for a valid, unexpired token, else None."""
    try:
        header, body, sig = token.split(".")
        expected = _b64(hmac.new(_JWT_SECRET, f"{header}.{body}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        if json.loads(_unb64(header)).get("alg") != "HS256":
            return None
        claims = json.loads(_unb64(body))
        if claims["exp"] <= time.time():
            return None
        return claims["sub"], claims["role"]
    except Exception:
        return None


# ── Ledger substitutes (same interface as FabricGatewayClient) ────────────────

class LocalLedgerClient:
    """B1: a conventional database standing in for the Fabric ledger."""

    def __init__(self, path: str = None):
        self._path = path or os.environ.get("FPAIF_LEDGER_DB", "local_ledger.db")
        self._tl = threading.local()
        c = self._conn()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS agents (
                did TEXT PRIMARY KEY, public_key TEXT, role TEXT, credential_hash TEXT,
                status TEXT, created_at TEXT, revoked_at TEXT, revoke_reason TEXT);
            CREATE TABLE IF NOT EXISTS anchors (
                batch_id TEXT PRIMARY KEY, root_hash TEXT, event_count INTEGER,
                period_start TEXT, period_end TEXT, anchored_at TEXT, tx_id TEXT);
        """)
        c.commit()

    def _conn(self):
        if getattr(self._tl, "c", None) is None:
            c = sqlite3.connect(self._path, timeout=30)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            self._tl.c = c
        return self._tl.c

    def health(self) -> Dict:
        return {"status": "healthy", "gateway": "local-sqlite"}

    def register_agent(self, did, public_key, role, credential_hash) -> Dict:
        c = self._conn()
        now = datetime.now().isoformat()
        try:
            c.execute("INSERT INTO agents VALUES (?,?,?,?, 'active', ?, NULL, NULL)",
                      (did, public_key, role, credential_hash, now))
            c.commit()
        except sqlite3.IntegrityError:
            raise Exception(f"Agent with DID {did} is already registered.")
        return {"success": True, "agent": {"did": did, "role": role, "status": "active", "createdAt": now}}

    def get_agent(self, did) -> Dict:
        r = self._conn().execute("SELECT * FROM agents WHERE did=?", (did,)).fetchone()
        if not r:
            raise Exception(f"Agent {did} not found")
        return {"success": True, "agent": dict(r)}

    def get_all_agents(self) -> Dict:
        rows = [dict(r) for r in self._conn().execute("SELECT * FROM agents")]
        return {"success": True, "count": len(rows), "agents": rows}

    def is_revoked(self, did) -> bool:
        r = self._conn().execute("SELECT status FROM agents WHERE did=?", (did,)).fetchone()
        return bool(r and r["status"] == "revoked")

    def revoke_agent(self, did, reason="") -> Dict:
        c = self._conn()
        cur = c.execute("UPDATE agents SET status='revoked', revoked_at=?, revoke_reason=? "
                        "WHERE did=? AND status!='revoked'",
                        (datetime.now().isoformat(), reason or "Not specified", did))
        c.commit()
        return {"success": cur.rowcount > 0, "did": did}

    def anchor_audit_batch(self, root_hash, event_count, period_start, period_end) -> Dict:
        batch_id = f"{period_start}_{period_end}"
        anchor = {"batchId": batch_id, "rootHash": root_hash, "eventCount": event_count,
                  "periodStart": period_start, "periodEnd": period_end,
                  "anchoredAt": datetime.now().isoformat(), "txId": uuid.uuid4().hex}
        c = self._conn()
        c.execute("INSERT OR REPLACE INTO anchors VALUES (?,?,?,?,?,?,?)",
                  (batch_id, root_hash, event_count, period_start, period_end,
                   anchor["anchoredAt"], anchor["txId"]))
        c.commit()
        return {"success": True, "anchor": anchor}

    def get_audit_anchors(self) -> Dict:
        rows = [{"batchId": r["batch_id"], "rootHash": r["root_hash"], "eventCount": r["event_count"],
                 "periodStart": r["period_start"], "periodEnd": r["period_end"],
                 "anchoredAt": r["anchored_at"], "txId": r["tx_id"]}
                for r in self._conn().execute("SELECT * FROM anchors")]
        return {"success": True, "count": len(rows), "anchors": rows}

    def get_audit_anchor(self, batch_id) -> Optional[Dict]:
        return next((a for a in self.get_audit_anchors()["anchors"] if a["batchId"] == batch_id), None)


class NullLedgerClient:
    """B0: no ledger at all. Accepts writes, remembers nothing, never reports revocation."""

    def health(self) -> Dict:
        return {"status": "healthy", "gateway": "none"}

    def register_agent(self, did, public_key, role, credential_hash) -> Dict:
        return {"success": True}

    def get_agent(self, did) -> Dict:
        raise Exception("no ledger in jwt mode")

    def get_all_agents(self) -> Dict:
        return {"success": True, "count": 0, "agents": []}

    def is_revoked(self, did) -> bool:
        return False  # stateless tokens cannot be revoked

    def revoke_agent(self, did, reason="") -> Dict:
        return {"success": False, "message": "revocation unsupported in jwt mode"}

    def anchor_audit_batch(self, *a, **k) -> Dict:
        raise Exception("audit anchoring unsupported in jwt mode")

    def get_audit_anchors(self) -> Dict:
        return {"success": True, "count": 0, "anchors": []}

    def get_audit_anchor(self, batch_id) -> Optional[Dict]:
        return None


_ledger = None


def get_ledger():
    """Ledger client for the active non-fabric mode (None means use the real Fabric client)."""
    global _ledger
    if MODE == "fabric":
        return None
    if _ledger is None:
        _ledger = LocalLedgerClient() if MODE == "local" else NullLedgerClient()
    return _ledger
