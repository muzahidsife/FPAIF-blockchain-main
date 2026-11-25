"""
run_audit_tamper.py - can tampering with the audit log be detected?
===================================================================
FPAIF anchors the tip of an HMAC hash chain over audit_logs. verify_batch() recomputes
the chain from the raw rows and compares it with the anchored root. This script attacks
the audit_logs table directly (in the SQLite file) and checks whether /verify_batch notices.

Two attacker strengths:
  level 1  "database only"   edits audit_logs, nothing else.
  level 2  "host access"     also knows the HMAC key and can rewrite the anchor store *if it is
                             reachable*: in local mode that is a SQLite file; on Fabric it is the
                             ledger held by the peers, which this attacker cannot edit.

Attacks:  modify a row | delete a row | insert a forged row | reorder two rows
          modify auth_time_ms / log_time_ms (covered since chain v2)
          modify anchor_batch_id (a display cache - deliberately NOT covered; expected undetected)
Control:  no tampering (measures false alarms)

Each trial applies the attack, calls GET /verify_batch/<id>, then reverts the change so
trials are independent. "Detected" = verify_batch reports match=false.

Usage (server running in the matching mode, same database files):
  python run_audit_tamper.py --mode fabric --db ai_agent_framework.db
  python run_audit_tamper.py --mode local  --db bench_runs/local_app.db --ledger-db bench_runs/local_ledger.db
(compare_baselines.py calls this for you.) The jwt mode has no audit log; it is reported as N/A.
"""

import argparse
import json
import random
import sqlite3
import sys
import time
import uuid

import requests

import audit_verify
from db import Database
from stats import wilson

parser = argparse.ArgumentParser()
parser.add_argument("--url", default="http://localhost:8000")
parser.add_argument("--mode", choices=["jwt", "local", "fabric"], default="fabric")
parser.add_argument("--db", default="ai_agent_framework.db", help="SQLite file the server writes audit_logs to")
parser.add_argument("--ledger-db", default="local_ledger.db", help="local-mode anchor store (SQLite)")
parser.add_argument("--batches", type=int, default=5, help="anchored batches to attack")
parser.add_argument("--events", type=int, default=20, help="audit events generated per batch")
parser.add_argument("--tamper-n", type=int, default=100, help="trials per (attack, level)")
parser.add_argument("--seed", type=int, default=7)
parser.add_argument("--out", default="tamper_results.json")
args = parser.parse_args()

BASE = args.url.rstrip("/")
random.seed(args.seed)
TRUSTED = {"X-Forwarded-For": "192.168.10.1"}


def row_out(attack, level, k, n, note=""):
    lo, hi = wilson(k, n)
    return {"attack": attack, "level": level, "detected": k, "n": n,
            "detect_rate_pct": round(100 * k / n, 2) if n else 0,
            "ci95_low_pct": round(100 * lo, 2), "ci95_high_pct": round(100 * hi, 2), "note": note}


if args.mode == "jwt":
    rows = [row_out("all attacks", "-", 0, 0, "jwt mode keeps no audit log: nothing to tamper with and nothing to verify")]
    json.dump({"mode": "jwt", "results": rows}, open(args.out, "w"), indent=2)
    print("jwt mode has no audit log - N/A. Saved", args.out)
    sys.exit(0)

db = Database(args.db)
conn = db._get_conn()
conn.row_factory = sqlite3.Row


def api(method, path, **kw):
    return requests.request(method, f"{BASE}{path}", timeout=60, **kw)


# ── set up: an admin session and several anchored batches ──────────────────────

def admin_token():
    r = api("POST", "/register_agent", data={"agent_name": f"TamperAdmin_{uuid.uuid4().hex[:6]}", "role": "admin"}, headers=TRUSTED).json()
    a = api("POST", "/authenticate", data={"did": r["did"], "credential_hash": r["verifiable_credential"]["credential_hash"]}, headers=TRUSTED)
    if a.status_code != 200:
        sys.exit(f"cannot authenticate admin: {a.status_code} {a.text}")
    return a.json()["session_token"]


def make_batch(token):
    """Generate audit events, anchor them, return (batch_id, period_end)."""
    for i in range(args.events // 2):
        r = api("POST", "/register_agent", data={"agent_name": f"TamperEv_{uuid.uuid4().hex[:6]}", "role": "user"}, headers=TRUSTED).json()
        api("POST", "/authenticate", data={"did": r["did"], "credential_hash": r["verifiable_credential"]["credential_hash"]}, headers=TRUSTED)
    res = api("POST", "/trigger_anchor", data={"session_token": token})
    if res.status_code != 200 or not res.json().get("anchored"):
        sys.exit(f"anchoring failed: {res.status_code} {res.text}")
    j = res.json()
    # audit timestamps have 1 s resolution and verification covers `timestamp <= periodEnd`;
    # wait so later events cannot share the anchor's last second.
    time.sleep(1.2)
    return j["batch_id"], j["period_end"]


def verify(batch_id):
    r = api("GET", f"/verify_batch/{batch_id}")
    return r.json().get("match") is True


print(f"  mode={args.mode}: creating {args.batches} anchored batches of ~{args.events} events...")
token = admin_token()
batches = [make_batch(token) for _ in range(args.batches)]
untouched_ok = [verify(b) for b, _ in batches]
print(f"  baseline: {sum(untouched_ok)}/{len(batches)} batches verify cleanly before any tampering")
if not all(untouched_ok):
    print("  WARNING: some untouched batches already fail verification - see note in the report")


# ── attacks (each returns an undo callable) ────────────────────────────────────

def chain_rows(period_end):
    return [dict(r) for r in db.get_audit_logs_up_to(period_end)]


def atk_modify(period_end):
    r = random.choice(chain_rows(period_end))
    new = "failed" if r["result"] == "success" else "success"
    conn.execute("UPDATE audit_logs SET result=? WHERE id=?", (new, r["id"])); conn.commit()
    return lambda: (conn.execute("UPDATE audit_logs SET result=? WHERE id=?", (r["result"], r["id"])), conn.commit())


def atk_delete(period_end):
    r = random.choice(chain_rows(period_end))
    cols = list(r.keys())
    conn.execute("DELETE FROM audit_logs WHERE id=?", (r["id"],)); conn.commit()

    def undo():
        conn.execute(f"INSERT INTO audit_logs ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", [r[c] for c in cols])
        conn.commit()
    return undo


def atk_insert(period_end):
    r = random.choice(chain_rows(period_end))
    cur = conn.execute("INSERT INTO audit_logs (agent_did, action, result, details, timestamp) VALUES (?,?,?,?,?)",
                       (r["agent_did"], "authenticate", "success", '{"role": "admin"}', r["timestamp"]))
    conn.commit()
    new_id = cur.lastrowid
    return lambda: (conn.execute("DELETE FROM audit_logs WHERE id=?", (new_id,)), conn.commit())


def atk_reorder(period_end):
    rows = chain_rows(period_end)
    # Only pairs whose events differ: swapping timestamps of two identical events changes nothing
    # observable (the chain sees the same sequence), so that would not be an attack.
    content = lambda r: (r["agent_did"], r["action"], r["result"], r["details"])
    pairs = [(a, b) for a, b in zip(rows, rows[1:])
             if a["timestamp"] != b["timestamp"] and content(a) != content(b)]
    if not pairs:
        return None
    a, b = random.choice(pairs)
    conn.execute("UPDATE audit_logs SET timestamp=? WHERE id=?", (b["timestamp"], a["id"]))
    conn.execute("UPDATE audit_logs SET timestamp=? WHERE id=?", (a["timestamp"], b["id"])); conn.commit()

    def undo():
        conn.execute("UPDATE audit_logs SET timestamp=? WHERE id=?", (a["timestamp"], a["id"]))
        conn.execute("UPDATE audit_logs SET timestamp=? WHERE id=?", (b["timestamp"], b["id"]))
        conn.commit()
    return undo


def _atk_column(column, mutate):
    def attack(period_end):
        r = random.choice(chain_rows(period_end))
        conn.execute(f"UPDATE audit_logs SET {column}=? WHERE id=?", (mutate(r[column]), r["id"])); conn.commit()
        return lambda: (conn.execute(f"UPDATE audit_logs SET {column}=? WHERE id=?", (r[column], r["id"])), conn.commit())
    return attack


atk_auth_time = _atk_column("auth_time_ms", lambda v: (v or 0) + 1000)    # falsify latency evidence
atk_log_time = _atk_column("log_time_ms", lambda v: (v or 0) + 1000)
atk_batch_id = _atk_column("anchor_batch_id", lambda v: "forged-batch")   # display cache, not integrity data


ATTACKS = [("modify a row", atk_modify), ("delete a row", atk_delete),
           ("insert a forged row", atk_insert), ("reorder two rows", atk_reorder),
           ("modify auth_time_ms (latency evidence)", atk_auth_time),
           ("modify log_time_ms (latency evidence)", atk_log_time),
           ("modify anchor_batch_id (display cache)", atk_batch_id)]


# ── level 2: also rewrite the anchor, if the anchor store is reachable ─────────

def repair_anchor(batch_id, period_end):
    """Attacker with host access recomputes the root over the tampered rows and overwrites the
    stored anchor. Possible for the local SQLite registry; impossible on a Fabric ledger.
    Returns an undo callable, or None when the anchor store is out of reach."""
    if args.mode != "local":
        return None
    lc = sqlite3.connect(args.ledger_db, timeout=30)
    old = lc.execute("SELECT root_hash FROM anchors WHERE batch_id=?", (batch_id,)).fetchone()
    if not old:
        lc.close()
        return None
    new_root = audit_verify.anchor_root(chain_rows(period_end))
    lc.execute("UPDATE anchors SET root_hash=? WHERE batch_id=?", (new_root, batch_id)); lc.commit()

    def undo():
        lc.execute("UPDATE anchors SET root_hash=? WHERE batch_id=?", (old[0], batch_id)); lc.commit(); lc.close()
    return undo


# ── run ────────────────────────────────────────────────────────────────────────

results = []

fa = sum(not verify(batches[i % len(batches)][0]) for i in range(args.tamper_n))
results.append(row_out("CONTROL: no tampering (false alarms)", "-", fa, args.tamper_n, "detected = false alarm; lower is better"))

for level in (1, 2):
    for name, attack in ATTACKS:
        k = n = 0
        for i in range(args.tamper_n):
            batch_id, period_end = batches[i % len(batches)]
            undo = attack(period_end)
            if undo is None:
                continue
            undo_anchor = repair_anchor(batch_id, period_end) if level == 2 else None
            k += not verify(batch_id)
            n += 1
            if undo_anchor:
                undo_anchor()
            undo()
        note = ""
        if level == 2:
            note = ("anchor store rewritten by attacker" if args.mode == "local"
                    else "anchor is on the ledger - attacker cannot rewrite it")
        results.append(row_out(name, level, k, n, note))

after = [verify(b) for b, _ in batches]
print(f"  after reverting every change: {sum(after)}/{len(batches)} batches verify cleanly (should equal baseline)")

print(f"\n  {'Attack':<42}{'Lvl':>4}{'Detected/N':>14}{'Rate %':>9}{'95% CI %':>16}")
print("  " + "-" * 85)
for r in results:
    print(f"  {r['attack']:<42}{r['level']:>4}{f'{r['detected']}/{r['n']}':>14}{r['detect_rate_pct']:>9}"
          f"{f'{r['ci95_low_pct']} - {r['ci95_high_pct']}':>16}")
print("\n  Level 1 = database-only attacker. Level 2 = host attacker who knows the HMAC key and can edit the anchor store if it is a local file.")
json.dump({"mode": args.mode, "baseline_clean": untouched_ok, "after_revert_clean": after, "results": results},
          open(args.out, "w"), indent=2)
print("  Saved:", args.out)
