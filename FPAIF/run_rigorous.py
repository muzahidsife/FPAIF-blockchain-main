"""
run_rigorous.py - Repeated-run performance tests + large adversarial security tests
===================================================================================
Complements run_tests.py (which is left unchanged). It addresses three weaknesses:

  1. Single-run results      -> every performance test is repeated --runs times
                                after a discarded warm-up
  2. No variance / CIs       -> mean, SD, CV and a bootstrap 95% CI across runs
  3. Small security samples  -> thousands of invalid cases of several attack kinds,
                                reported with Wilson 95% CIs (so "0 failures" shows
                                how small the true failure rate could still be)

Usage:
  python run_rigorous.py                       # 10 runs, 1000 security cases
  python run_rigorous.py --runs 30 --sec-n 2000
  python run_rigorous.py --skip-perf           # security part only
  python run_rigorous.py --skip-security       # performance part only

The server must be running (python app.py) and, for valid logins, the Fabric
gateway must be up because /authenticate checks revocation on the ledger.
Output: printed tables + rigorous_results.json (includes raw per-run values).
"""

import argparse
import json
import random
import statistics
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests

from stats import fmt, percentile, summarize, wilson

parser = argparse.ArgumentParser()
parser.add_argument("--url", default="http://localhost:8000")
parser.add_argument("--runs", type=int, default=10, help="repetitions of the performance tests")
parser.add_argument("--warmup", type=int, default=20, help="discarded requests before each run")
parser.add_argument("--auth-n", type=int, default=100, help="sequential auths measured per run")
parser.add_argument("--users", type=int, default=200, help="concurrent users in each load test")
parser.add_argument("--sec-n", type=int, default=1000, help="invalid cases per security test group")
parser.add_argument("--valid-n", type=int, default=200, help="valid cases used to measure false rejects")
parser.add_argument("--revoke-n", type=int, default=30, help="agents revoked in the revocation test")
parser.add_argument("--seed", type=int, default=42)
parser.add_argument("--skip-perf", action="store_true")
parser.add_argument("--skip-security", action="store_true")
parser.add_argument("--out", default="rigorous_results.json")
args = parser.parse_args()

BASE = args.url.rstrip("/")
random.seed(args.seed)
TRUSTED_IP = {"X-Forwarded-For": "192.168.10.1"}  # in RATE_WHITELIST (app.py)
ROLES = ["admin", "user", "auditor"]               # roles allowed to authenticate
RESULTS = {"started": datetime.now().isoformat(timespec="seconds"), "args": vars(args)}


def sep(title):
    pad = (64 - len(title) - 2) // 2
    print(f"\n{'=' * pad} {title} {'=' * pad}")


def reset_buckets():
    try:
        requests.post(f"{BASE}/internal/reset_rate_limits", timeout=5)
    except Exception:
        pass


def check_server():
    try:
        requests.get(BASE, timeout=5)
    except Exception as e:
        sys.exit(f"Cannot reach {BASE}: {e}\nStart it with: python app.py")
    reset_buckets()


def register(sess, name, role, headers=TRUSTED_IP):
    """Register one agent; returns (did, credential_hash, latency_ms) or None."""
    t0 = time.perf_counter()
    r = sess.post(f"{BASE}/register_agent", data={"agent_name": name, "role": role},
                  headers=headers, timeout=30)
    ms = (time.perf_counter() - t0) * 1000
    if r.status_code != 200:
        return None
    j = r.json()
    return j["did"], j["verifiable_credential"]["credential_hash"], ms


def authenticate(sess, did, cred, headers=TRUSTED_IP):
    """Returns (status_code, latency_ms, token_or_None)."""
    t0 = time.perf_counter()
    r = sess.post(f"{BASE}/authenticate", data={"did": did, "credential_hash": cred},
                  headers=headers, timeout=60)
    ms = (time.perf_counter() - t0) * 1000
    token = r.json().get("session_token") if r.status_code == 200 else None
    return r.status_code, ms, token


# ═══════════════════════════════════════════════════════════════════════════
# PART 1 - repeated-run performance tests
# ═══════════════════════════════════════════════════════════════════════════

def _load_register(i):
    t0 = time.perf_counter()
    try:
        r = requests.post(f"{BASE}/register_agent",
                          data={"agent_name": f"RigLoad_{uuid.uuid4().hex[:10]}", "role": ROLES[i % 3]},
                          headers={"X-Forwarded-For": f"10.{(i // 250) % 255}.{i % 250}.1"}, timeout=60)
        j = r.json() if r.status_code == 200 else {}
        return {"ok": r.status_code == 200, "ms": (time.perf_counter() - t0) * 1000,
                "did": j.get("did"), "cred": j.get("verifiable_credential", {}).get("credential_hash"), "i": i}
    except Exception:
        return {"ok": False, "ms": (time.perf_counter() - t0) * 1000, "i": i}


def _load_auth(item):
    did, cred, i = item
    t0 = time.perf_counter()
    try:
        r = requests.post(f"{BASE}/authenticate", data={"did": did, "credential_hash": cred},
                          headers={"X-Forwarded-For": f"10.{(i // 250) % 255}.{i % 250}.2"}, timeout=60)
        return {"ok": r.status_code == 200, "ms": (time.perf_counter() - t0) * 1000}
    except Exception:
        return {"ok": False, "ms": (time.perf_counter() - t0) * 1000}


def one_perf_run():
    """One full repetition. Returns scalar metrics plus success counters."""
    reset_buckets()
    sess = requests.Session()
    out = {}

    # sequential registration + authentication latency (after warm-up)
    reg_ms, auth_ms, auth_ok = [], [], 0
    for i in range(args.warmup + args.auth_n):
        reg = register(sess, f"RigAgent_{uuid.uuid4().hex[:10]}", ROLES[i % 3])
        if not reg:
            continue
        did, cred, r_ms = reg
        status, a_ms, _ = authenticate(sess, did, cred)
        if i < args.warmup:
            continue  # warm-up: discarded
        reg_ms.append(r_ms)
        auth_ms.append(a_ms)
        auth_ok += status == 200
    if not auth_ms:
        sys.exit("  No successful registrations - check the server and the Fabric gateway (python app.py, node gateway.js)")
    out["reg_mean_ms"] = statistics.mean(reg_ms) if reg_ms else 0
    out["auth_mean_ms"] = statistics.mean(auth_ms) if auth_ms else 0
    out["auth_median_ms"] = statistics.median(auth_ms) if auth_ms else 0
    out["auth_p95_ms"] = percentile(auth_ms, 95)
    out["auth_ok"], out["auth_total"] = auth_ok, len(auth_ms)

    # concurrent load test
    reset_buckets()
    n = args.users
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=100) as ex:
        regs = [f.result() for f in as_completed([ex.submit(_load_register, i) for i in range(n)])]
    reg_wall = time.perf_counter() - t0
    reg_ok = [r for r in regs if r["ok"]]
    out["load_reg_throughput_rps"] = len(reg_ok) / reg_wall if reg_wall else 0
    out["load_reg_mean_ms"] = statistics.mean(r["ms"] for r in regs) if regs else 0
    out["load_reg_ok"], out["load_reg_total"] = len(reg_ok), n

    reset_buckets()
    creds = [(r["did"], r["cred"], r["i"]) for r in reg_ok if r.get("did") and r.get("cred")]
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=100) as ex:
        auths = [f.result() for f in as_completed([ex.submit(_load_auth, c) for c in creds])]
    auth_wall = time.perf_counter() - t0
    out["load_auth_throughput_rps"] = sum(a["ok"] for a in auths) / auth_wall if auth_wall else 0
    out["load_auth_mean_ms"] = statistics.mean(a["ms"] for a in auths) if auths else 0
    out["load_auth_ok"], out["load_auth_total"] = sum(a["ok"] for a in auths), len(creds)
    return out


METRICS = [  # (key, label, unit)
    ("reg_mean_ms", "Registration latency, mean", " ms"),
    ("auth_mean_ms", "Auth latency, mean", " ms"),
    ("auth_median_ms", "Auth latency, median", " ms"),
    ("auth_p95_ms", "Auth latency, P95", " ms"),
    ("load_reg_throughput_rps", f"Load registration throughput ({args.users} users)", " req/s"),
    ("load_reg_mean_ms", "Load registration latency, mean", " ms"),
    ("load_auth_throughput_rps", "Load auth throughput", " req/s"),
    ("load_auth_mean_ms", "Load auth latency, mean", " ms"),
]


def perf_tests():
    sep(f"PERFORMANCE - {args.runs} RUNS (+{args.warmup} warm-up each)")
    runs = []
    for k in range(1, args.runs + 1):
        t0 = time.time()
        r = one_perf_run()
        runs.append(r)
        print(f"  run {k:>2}/{args.runs}  auth mean {r['auth_mean_ms']:.1f} ms  "
              f"load auth {r['load_auth_throughput_rps']:.1f} req/s  ({time.time() - t0:.0f}s)")

    summary = {key: summarize([r[key] for r in runs]) for key, _, _ in METRICS}
    print(f"\n  {'Metric':<40}{'Mean':>10}{'95% CI':>22}{'SD':>9}{'CV%':>7}")
    print("  " + "-" * 88)
    for key, label, unit in METRICS:
        s = summary[key]
        print(f"  {label:<40}{s['mean']:>10}{f'{s['ci95_low']} - {s['ci95_high']}':>22}"
              f"{s['sd']:>9}{s['cv_pct']:>7}")

    # success rates pooled over all runs, with Wilson CIs
    rates = {}
    for name, ok, tot in [("auth_success", "auth_ok", "auth_total"),
                          ("load_reg_success", "load_reg_ok", "load_reg_total"),
                          ("load_auth_success", "load_auth_ok", "load_auth_total")]:
        k, n = sum(r[ok] for r in runs), sum(r[tot] for r in runs)
        lo, hi = wilson(k, n)
        rates[name] = {"k": k, "n": n, "rate_pct": round(100 * k / n, 3) if n else 0,
                       "ci95_low_pct": round(100 * lo, 3), "ci95_high_pct": round(100 * hi, 3)}
        print(f"  {name:<40}{k}/{n} = {rates[name]['rate_pct']}%  (95% CI {rates[name]['ci95_low_pct']}-{rates[name]['ci95_high_pct']}%)")

    RESULTS["performance"] = {"runs": runs, "summary": summary, "success_rates": rates}


# ═══════════════════════════════════════════════════════════════════════════
# PART 2 - large adversarial security tests
# ═══════════════════════════════════════════════════════════════════════════

def rand_hex(n=64):
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def flip_one_char(s):
    i = random.randrange(len(s))
    alphabet = "0123456789abcdef" if all(c in "0123456789abcdef-" for c in s) else "abcdefghijklmnopqrstuvwxyz"
    c = random.choice([x for x in alphabet if x != s[i]])
    return s[:i] + c + s[i + 1:]


INJECTIONS = ["' OR '1'='1", "'; DROP TABLE sessions;--", "\" OR \"\"=\"", "admin'--", "%00", "../../etc/passwd"]


def sec_row(name, k, n, what):
    lo, hi = wilson(k, n)
    return {"test": name, "what": what, "errors": k, "n": n,
            "error_rate_pct": round(100 * k / n, 3) if n else 0,
            "ci95_low_pct": round(100 * lo, 3), "ci95_high_pct": round(100 * hi, 3)}


def security_tests():
    sep("SECURITY - LARGE ADVERSARIAL SAMPLES")
    sess = requests.Session()
    reset_buckets()

    # pool of legitimate agents (name -> did/cred), used as the bases for attacks
    print("  Registering agent pool...")
    pool = [register(sess, f"SecAgent_{i}_{uuid.uuid4().hex[:6]}", ROLES[i % 3]) for i in range(60)]
    pool = [p for p in pool if p]
    if len(pool) < 2:
        sys.exit("  Could not register agents - is the server healthy?")

    rows = []

    # ── A. invalid credentials: any HTTP 200 is a FALSE ACCEPT ────────────────
    kinds = {
        "random_hash":   lambda a, b: (a[0], rand_hex()),
        "one_char_flip": lambda a, b: (a[0], flip_one_char(a[1])),
        "cross_agent":   lambda a, b: (a[0], b[1]),          # valid hash of a different agent
        "unknown_did":   lambda a, b: (f"did:fpaif:{uuid.uuid4().hex}", a[1]),
        "injection":     lambda a, b: (a[0], random.choice(INJECTIONS)),
        "case_changed":  lambda a, b: (a[0], a[1].upper()),
    }
    per_kind = max(1, args.sec_n // len(kinds))
    print(f"  A. invalid credentials: {per_kind} per kind x {len(kinds)} kinds")
    tot_k = tot_n = 0
    for kind, make in kinds.items():
        k = n = 0
        for _ in range(per_kind):
            a, b = random.sample(pool, 2)
            did, cred = make(a, b)
            if kind == "case_changed" and cred == a[1]:
                continue  # hash had no letters; nothing changed
            status, _, _ = authenticate(sess, did, cred)
            n += 1
            k += status == 200
        rows.append(sec_row(f"invalid credential: {kind}", k, n, "false accepts"))
        tot_k, tot_n = tot_k + k, tot_n + n
    rows.append(sec_row("invalid credential: ALL KINDS", tot_k, tot_n, "false accepts"))

    # ── B. valid credentials: any non-200 is a FALSE REJECT ───────────────────
    print(f"  B. valid credentials: {args.valid_n} legitimate logins")
    tokens, k, n = [], 0, 0
    for i in range(args.valid_n):
        did, cred, _ = pool[i % len(pool)]
        status, _, tok = authenticate(sess, did, cred)
        n += 1
        if status != 200:
            k += 1
        else:
            tokens.append(tok)
    rows.append(sec_row("valid credential login", k, n, "false rejects"))

    # ── C. invalid session tokens: any HTTP 200 is a FALSE ACCEPT ─────────────
    def gateway(token, ip="192.168.10.1"):
        return sess.get(f"{BASE}/api_gateway", params={"session_token": token},
                        headers={"X-Forwarded-For": ip}, timeout=30).status_code

    tkinds = {
        "random_uuid": lambda t: str(uuid.uuid4()),
        "truncated":   lambda t: t[:random.randrange(8, len(t) - 1)],
        "one_char_flip": lambda t: flip_one_char(t),
        "uppercased":  lambda t: t.upper(),
        "injection":   lambda t: random.choice(INJECTIONS),
        "extended":    lambda t: t + rand_hex(4),
    }
    per_tk = max(1, args.sec_n // len(tkinds))
    print(f"  C. invalid session tokens: {per_tk} per kind x {len(tkinds)} kinds")
    tot_k = tot_n = 0
    for kind, make in tkinds.items():
        k = n = 0
        for _ in range(per_tk):
            base = random.choice(tokens) if tokens else str(uuid.uuid4())
            tok = make(base)
            if tok in tokens:
                continue
            n += 1
            k += gateway(tok) == 200
        rows.append(sec_row(f"invalid token: {kind}", k, n, "false accepts"))
        tot_k, tot_n = tot_k + k, tot_n + n
    rows.append(sec_row("invalid token: ALL KINDS", tot_k, tot_n, "false accepts"))

    # ── D. valid session tokens: any non-200 is a FALSE REJECT ────────────────
    n = len(tokens)
    k = sum(gateway(t) != 200 for t in tokens)
    rows.append(sec_row("valid session token", k, n, "false rejects"))

    # ── E. rate limiting (per-IP, 5 requests / window) ────────────────────────
    print("  E. rate limiting / DDoS")
    did, cred, _ = pool[0]

    def flood(ip, count):
        blocked = 0
        for _ in range(count):
            r = sess.post(f"{BASE}/authenticate", data={"did": f"did:x:{uuid.uuid4().hex[:8]}", "credential_hash": "x"},
                          headers={"X-Forwarded-For": ip}, timeout=30)
            blocked += r.status_code == 429
        return blocked

    reset_buckets()
    blocked = flood("10.9.9.9", args.sec_n)
    rows.append(sec_row("DDoS single IP: requests NOT blocked", args.sec_n - blocked, args.sec_n,
                        "attack requests that got through (5/window expected)"))

    reset_buckets()
    ips, per_ip = 200, 10
    got_through = 0
    for i in range(ips):
        got_through += per_ip - flood(f"10.8.{i // 250}.{i % 250 + 1}", per_ip)
    rows.append(sec_row("DDoS rotating IPs (spoofed XFF): not blocked", got_through, ips * per_ip,
                        "attack requests that got through"))

    reset_buckets()
    legit_n, legit_bad = 0, 0
    from threading import Thread
    attacker = Thread(target=flood, args=("10.7.7.7", args.sec_n // 2))
    attacker.start()
    for i in range(100):  # 100 distinct legitimate clients, 3 logins each (<= limit of 5)
        for _ in range(3):
            status, _, _ = authenticate(sess, did, cred, headers={"X-Forwarded-For": f"10.6.{i // 250}.{i % 250 + 1}"})
            legit_n += 1
            legit_bad += status != 200
    attacker.join()
    rows.append(sec_row("legitimate users during attack", legit_bad, legit_n, "false rejects (collateral damage)"))

    # ── F. revocation enforcement ─────────────────────────────────────────────
    print(f"  F. revocation: {args.revoke_n} agents revoked after receiving a session token")
    k_login = k_token = n = 0
    for i in range(args.revoke_n):
        reg = register(sess, f"RevokeAgent_{i}_{uuid.uuid4().hex[:6]}", ROLES[i % 3])
        if not reg:
            continue
        did, cred, _ = reg
        status, _, old_token = authenticate(sess, did, cred)
        if status != 200:
            continue
        sess.post(f"{BASE}/internal/revoke", data={"did": did, "reason": "benchmark"}, timeout=60)
        n += 1
        k_login += authenticate(sess, did, cred)[0] == 200      # revoked agent logs in again
        k_token += gateway(old_token) == 200                    # pre-issued token still works
    rows.append(sec_row("revoked agent can log in again", k_login, n, "false accepts"))
    rows.append(sec_row("pre-revocation token still accepted", k_token, n,
                        "false accepts (bearer tokens outlive revocation until expiry)"))

    print(f"\n  {'Test':<50}{'Errors/N':>12}{'Rate %':>9}{'95% CI %':>16}")
    print("  " + "-" * 87)
    for r in rows:
        print(f"  {r['test']:<50}{f'{r['errors']}/{r['n']}':>12}{r['error_rate_pct']:>9}"
              f"{f'{r['ci95_low_pct']} - {r['ci95_high_pct']}':>16}")
    print("\n  'Errors' = false accepts or false rejects as labelled in the JSON; for the DDoS rows it is")
    print("  attack traffic that was NOT blocked. The CI upper bound is the honest worst-case rate.")
    RESULTS["security"] = rows


if __name__ == "__main__":
    print("\n" + "=" * 64)
    print("  FPAIF rigorous experiments")
    print(f"  Server {BASE} | runs={args.runs} warmup={args.warmup} sec-n={args.sec_n}")
    print(f"  {datetime.now():%Y-%m-%d %H:%M:%S}")
    print("=" * 64)
    check_server()
    if not args.skip_perf:
        perf_tests()
    if not args.skip_security:
        security_tests()
    RESULTS["finished"] = datetime.now().isoformat(timespec="seconds")
    with open(args.out, "w") as f:
        json.dump(RESULTS, f, indent=2)
    sep("DONE")
    print(f"  Saved: {args.out}")
