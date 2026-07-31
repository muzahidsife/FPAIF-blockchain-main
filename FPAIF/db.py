"""
Database helper — AI Agent Identification Framework
Tracks: auth_time_ms, log_time_ms, session expiry, attack events, rate limit events.

FIX: Replaced single shared SQLite connection with per-thread connection pool
to eliminate lock contention causing ~2000ms latency and load test auth failures.
"""

import sqlite3
import json
import time
import threading
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple


class Database:

    def __init__(self, db_path: str = "ai_agent_framework.db"):
        self._db_path = db_path
        self._local = threading.local()

    def _get_conn(self) -> sqlite3.Connection:
        """Return a per-thread SQLite connection, creating one if needed."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            conn = sqlite3.connect(self._db_path, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")   # allows concurrent reads + writes
            conn.execute("PRAGMA synchronous=NORMAL") # faster writes, still safe
            self._local.conn = conn
        return self._local.conn

    def init_tables(self):
        c = self._get_conn().cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                did         TEXT UNIQUE NOT NULL,
                agent_name  TEXT NOT NULL,
                role        TEXT NOT NULL,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_did        TEXT NOT NULL,
                credential_data  TEXT NOT NULL,
                credential_hash  TEXT UNIQUE NOT NULL,
                encryption_algo  TEXT DEFAULT 'SHA256',
                issued_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (agent_did) REFERENCES agents(did)
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT UNIQUE NOT NULL,
                agent_did     TEXT NOT NULL,
                agent_role    TEXT NOT NULL,
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at    TEXT NOT NULL,
                expires_at_ts REAL NOT NULL,
                is_active     INTEGER DEFAULT 1,
                FOREIGN KEY (agent_did) REFERENCES agents(did)
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_did   TEXT,
                action      TEXT NOT NULL,
                result      TEXT NOT NULL,
                details     TEXT,
                auth_time_ms REAL DEFAULT 0,
                log_time_ms  REAL DEFAULT 0,
                timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                anchor_batch_id TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS attack_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT NOT NULL,
                source_ip   TEXT DEFAULT '127.0.0.1',
                result      TEXT NOT NULL,
                details     TEXT,
                timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS rate_limit_events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip  TEXT NOT NULL,
                endpoint   TEXT NOT NULL,
                allowed    INTEGER NOT NULL,
                timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Migration: older DBs were created before anchor_batch_id existed.
        # CREATE TABLE IF NOT EXISTS above only applies to brand-new DBs.
        c.execute("PRAGMA table_info(audit_logs)")
        existing_cols = {row[1] for row in c.fetchall()}
        if "anchor_batch_id" not in existing_cols:
            c.execute("ALTER TABLE audit_logs ADD COLUMN anchor_batch_id TEXT")

        self._get_conn().commit()

    # ── Agents ───────────────────────────────────────────────────────────────

    def create_agent(self, did, agent_name, role):
        try:
            conn = self._get_conn()
            conn.cursor().execute(
                "INSERT INTO agents (did, agent_name, role) VALUES (?,?,?)",
                (did, agent_name, role)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_agent(self, did):
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM agents WHERE did=?", (did,))
        r = c.fetchone()
        return dict(r) if r else None

    def get_agent_role(self, did):
        c = self._get_conn().cursor()
        c.execute("SELECT role FROM agents WHERE did=?", (did,))
        r = c.fetchone()
        return r[0] if r else None

    # ── Credentials ──────────────────────────────────────────────────────────

    def create_credential(self, agent_did, credential_data, credential_hash):
        try:
            conn = self._get_conn()
            conn.cursor().execute(
                "INSERT INTO credentials (agent_did, credential_data, credential_hash) VALUES (?,?,?)",
                (agent_did, credential_data, credential_hash)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def verify_credential(self, did, credential_hash):
        c = self._get_conn().cursor()
        c.execute("""
            SELECT c.* FROM credentials c
            JOIN agents a ON c.agent_did = a.did
            WHERE a.did=? AND c.credential_hash=?
        """, (did, credential_hash))
        return c.fetchone() is not None

    # ── Sessions ─────────────────────────────────────────────────────────────

    def create_session(self, session_token, agent_did, agent_role):
        try:
            now = datetime.now()
            exp = now + timedelta(hours=1)
            conn = self._get_conn()
            conn.cursor().execute("""
                INSERT INTO sessions (session_token, agent_did, agent_role, expires_at, expires_at_ts)
                VALUES (?,?,?,?,?)
            """, (session_token, agent_did, agent_role, exp.isoformat(), exp.timestamp()))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_session(self, session_token):
        c = self._get_conn().cursor()
        c.execute("""
            SELECT agent_did, agent_role FROM sessions
            WHERE session_token=? AND expires_at_ts>? AND is_active=1
        """, (session_token, time.time()))
        r = c.fetchone()
        return (r[0], r[1]) if r else None

    def get_session_details(self, session_token):
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM sessions WHERE session_token=?", (session_token,))
        r = c.fetchone()
        return dict(r) if r else None

    def invalidate_session(self, session_token):
        conn = self._get_conn()
        c = conn.cursor()
        c.execute("UPDATE sessions SET is_active=0 WHERE session_token=?", (session_token,))
        conn.commit()
        return c.rowcount > 0

    # ── Logging ──────────────────────────────────────────────────────────────

    def log_action(self, agent_did, action, result, details=None,
                   auth_time_ms=0.0, log_time_ms=0.0):
        conn = self._get_conn()
        conn.cursor().execute("""
            INSERT INTO audit_logs (agent_did, action, result, details, auth_time_ms, log_time_ms)
            VALUES (?,?,?,?,?,?)
        """, (agent_did, action, result,
              json.dumps(details) if details else None,
              auth_time_ms, log_time_ms))
        conn.commit()

    def log_attack(self, attack_type, result, details=None, source_ip="127.0.0.1"):
        conn = self._get_conn()
        conn.cursor().execute("""
            INSERT INTO attack_events (attack_type, source_ip, result, details)
            VALUES (?,?,?,?)
        """, (attack_type, source_ip, result,
              json.dumps(details) if details else None))
        conn.commit()

    def log_rate_limit(self, source_ip, endpoint, allowed):
        conn = self._get_conn()
        conn.cursor().execute("""
            INSERT INTO rate_limit_events (source_ip, endpoint, allowed)
            VALUES (?,?,?)
        """, (source_ip, endpoint, 1 if allowed else 0))
        conn.commit()

    # ── Reads ─────────────────────────────────────────────────────────────────

    def get_audit_logs(self, limit=200):
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(r) for r in c.fetchall()]

    def get_audit_logs_up_to(self, period_end):
        """All audit_logs rows from genesis through period_end, oldest-first.
        Used by audit_verify to recompute the chain tip for a batch."""
        c = self._get_conn().cursor()
        c.execute("""
            SELECT * FROM audit_logs WHERE timestamp<=?
            ORDER BY timestamp ASC, id ASC
        """, (period_end,))
        return [dict(r) for r in c.fetchall()]

    def get_unanchored_audit_logs(self):
        """Rows not yet covered by any anchor batch, oldest-first."""
        c = self._get_conn().cursor()
        c.execute("""
            SELECT * FROM audit_logs WHERE anchor_batch_id IS NULL
            ORDER BY timestamp ASC, id ASC
        """)
        return [dict(r) for r in c.fetchall()]

    def stamp_anchor_batch(self, batch_id, period_end):
        """Mark rows up to period_end as covered by batch_id. Display cache
        only — the Fabric ledger stays the source of truth for what's anchored."""
        conn = self._get_conn()
        c = conn.cursor()
        c.execute("""
            UPDATE audit_logs SET anchor_batch_id=?
            WHERE anchor_batch_id IS NULL AND timestamp<=?
        """, (batch_id, period_end))
        conn.commit()
        return c.rowcount

    def cleanup_expired_sessions(self):
        conn = self._get_conn()
        c = conn.cursor()
        c.execute("UPDATE sessions SET is_active=0 WHERE expires_at_ts<=?", (time.time(),))
        conn.commit()
        return c.rowcount

    def close(self):
        if hasattr(self._local, 'conn') and self._local.conn:
            try:
                self._local.conn.close()
            except Exception:
                pass
            self._local.conn = None

    def __del__(self):
        self.close()