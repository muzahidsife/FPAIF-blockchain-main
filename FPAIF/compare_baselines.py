"""
compare_baselines.py - run the same experiments against three systems and compare
==================================================================================
  jwt     B0  plain JWT token auth (no ledger, no revocation, no audit log)
  local   B1  FPAIF logic with a local SQLite registry instead of Fabric
  fabric  B2  FPAIF with Hyperledger Fabric (the published system)

For each mode this script starts `python app.py` with FPAIF_MODE=<mode> and a fresh
database, runs run_rigorous.py against it, stops the server, then prints:
  * performance per mode (mean, 95% CI across runs)
  * overhead:  FPAIF logic = local - jwt     Fabric = fabric - local   (with 95% CI)
  * security results per mode side by side

Usage:
  python compare_baselines.py                        # all three, defaults
  python compare_baselines.py --runs 30 --sec-n 1000
  python compare_baselines.py --modes jwt local      # skip Fabric
Any other options (e.g. --users, --auth-n) are passed through to run_rigorous.py.

Fabric mode needs the network and gateway running (cd ../fabric-gateway && npm start).
Do not run it while another app.py is already listening on the same port.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import requests

from stats import diff_ci, summarize

HERE = Path(__file__).resolve().parent
OUT_DIR = HERE / "bench_runs"

parser = argparse.ArgumentParser()
parser.add_argument("--modes", nargs="+", default=["jwt", "local", "fabric"],
                    choices=["jwt", "local", "fabric"])
parser.add_argument("--port", type=int, default=8000)
parser.add_argument("--gateway", default="http://localhost:3000")
parser.add_argument("--skip-tamper", action="store_true", help="skip the audit-tampering experiment")
parser.add_argument("--tamper-n", type=int, default=100, help="trials per (attack, level) in the tampering test")
parser.add_argument("--tamper-batches", type=int, default=5)
parser.add_argument("--reuse", action="store_true",
                    help="skip running; only compare existing bench_runs/rigorous_<mode>.json")
args, passthrough = parser.parse_known_args()

NAMES = {"jwt": "B0 JWT-only", "local": "B1 FPAIF/local", "fabric": "B2 FPAIF/Fabric"}


def wait_for(url, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        try:
            requests.get(url, timeout=2)
            return True
        except Exception:
            time.sleep(0.5)
    return False


def run_mode(mode):
    print(f"\n{'#' * 64}\n#  {NAMES[mode]}   (FPAIF_MODE={mode})\n{'#' * 64}", flush=True)
    if mode == "fabric":
        try:
            health = requests.get(f"{args.gateway}/health", timeout=5).json()
            assert health.get("gateway") == "connected", health
        except Exception as e:
            print(f"  SKIPPED: Fabric gateway not healthy at {args.gateway} ({e})")
            return False

    OUT_DIR.mkdir(exist_ok=True)
    for f in OUT_DIR.glob(f"{mode}_*.db*"):
        f.unlink()
    env = dict(os.environ, FPAIF_MODE=mode, FPAIF_PORT=str(args.port),
               FPAIF_DB=str(OUT_DIR / f"{mode}_app.db"),
               FPAIF_LEDGER_DB=str(OUT_DIR / f"{mode}_ledger.db"))
    log = open(OUT_DIR / f"{mode}_server.log", "w")
    server = subprocess.Popen([sys.executable, "app.py"], cwd=HERE, env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        if not wait_for(f"http://localhost:{args.port}/"):
            print(f"  ERROR: server did not start; see {OUT_DIR / f'{mode}_server.log'}")
            return False
        url = f"http://localhost:{args.port}"
        rc = subprocess.call([sys.executable, "run_rigorous.py", "--url", url,
                              "--out", str(OUT_DIR / f"rigorous_{mode}.json"), *passthrough], cwd=HERE)
        if rc == 0 and not args.skip_tamper:
            print(f"\n{'=' * 22} AUDIT TAMPERING ({mode}) {'=' * 22}", flush=True)
            subprocess.call([sys.executable, "run_audit_tamper.py", "--url", url, "--mode", mode,
                             "--db", env["FPAIF_DB"], "--ledger-db", env["FPAIF_LEDGER_DB"],
                             "--tamper-n", str(args.tamper_n), "--batches", str(args.tamper_batches),
                             "--out", str(OUT_DIR / f"tamper_{mode}.json")], cwd=HERE, env=env)
        return rc == 0
    finally:
        server.terminate()
        try:
            server.wait(10)
        except subprocess.TimeoutExpired:
            server.kill()
        log.close()


def load(mode):
    p = OUT_DIR / f"rigorous_{mode}.json"
    return json.loads(p.read_text()) if p.exists() else None


PERF = [("auth_mean_ms", "Auth latency mean (ms)"), ("auth_median_ms", "Auth latency median (ms)"),
        ("auth_p95_ms", "Auth latency P95 (ms)"), ("reg_mean_ms", "Registration latency mean (ms)"),
        ("load_reg_throughput_rps", "Load registration throughput (req/s)"),
        ("load_auth_throughput_rps", "Load auth throughput (req/s)"),
        ("load_auth_mean_ms", "Load auth latency mean (ms)")]


def compare(modes, data):
    out = {"performance": {}, "overhead": {}}
    print(f"\n{'=' * 24} PERFORMANCE (mean, 95% CI over runs) {'=' * 24}")
    print(f"  {'Metric':<40}" + "".join(f"{NAMES[m]:>26}" for m in modes))
    print("  " + "-" * (40 + 26 * len(modes)))
    for key, label in PERF:
        cells = []
        for m in modes:
            vals = [r[key] for r in data[m]["performance"]["runs"]]
            s = summarize(vals)
            out["performance"].setdefault(key, {})[m] = s
            cells.append(f"{s['mean']} [{s['ci95_low']}-{s['ci95_high']}]")
        print(f"  {label:<40}" + "".join(f"{c:>26}" for c in cells))

    pairs = [("local", "jwt", "FPAIF logic  (B1 - B0)"), ("fabric", "local", "Fabric cost  (B2 - B1)")]
    pairs = [(hi, lo, name) for hi, lo, name in pairs if hi in data and lo in data]
    if pairs:
        print(f"\n{'=' * 22} OVERHEAD: difference of means, 95% CI {'=' * 22}")
        print(f"  {'Metric':<40}" + "".join(f"{p[2]:>34}" for p in pairs))
        print("  " + "-" * (40 + 34 * len(pairs)))
        for key, label in PERF:
            cells = []
            for hi, lo, name in pairs:
                d, l, h = diff_ci([r[key] for r in data[lo]["performance"]["runs"]],
                                  [r[key] for r in data[hi]["performance"]["runs"]])
                sig = "" if l <= 0 <= h else " *"
                out["overhead"].setdefault(key, {})[name] = {"diff": d, "ci95_low": l, "ci95_high": h}
                cells.append(f"{d:+.2f} [{l:+.2f}, {h:+.2f}]{sig}")
            print(f"  {label:<40}" + "".join(f"{c:>34}" for c in cells))
        print("  * = 95% CI excludes 0 (difference is larger than run-to-run noise)")

    print(f"\n{'=' * 18} SECURITY (errors/N  [95% CI upper bound %]) {'=' * 18}")
    print(f"  {'Test':<46}" + "".join(f"{NAMES[m]:>26}" for m in modes))
    print("  " + "-" * (46 + 26 * len(modes)))
    names = []
    for m in modes:
        for r in data[m].get("security", []):
            if r["test"] not in names:
                names.append(r["test"])
    for t in names:
        cells = []
        for m in modes:
            r = next((x for x in data[m].get("security", []) if x["test"] == t), None)
            cells.append(f"{r['errors']}/{r['n']} [<={r['ci95_high_pct']}%]" if r else "n/a")
        print(f"  {t:<46}" + "".join(f"{c:>26}" for c in cells))
    out["security"] = {m: data[m].get("security", []) for m in modes}

    tamper = {m: json.loads((OUT_DIR / f"tamper_{m}.json").read_text()) for m in modes
              if (OUT_DIR / f"tamper_{m}.json").exists()}
    if tamper:
        print(f"\n{'=' * 14} AUDIT TAMPERING: detected/N  (95% CI lower bound %) {'=' * 14}")
        print(f"  {'Attack':<44}{'Lvl':>4}" + "".join(f"{NAMES[m]:>24}" for m in tamper))
        print("  " + "-" * (48 + 24 * len(tamper)))
        keys = []
        for m in tamper:
            for r in tamper[m]["results"]:
                if (r["attack"], r["level"]) not in keys:
                    keys.append((r["attack"], r["level"]))
        for attack, level in keys:
            cells = []
            for m in tamper:
                r = next((x for x in tamper[m]["results"] if x["attack"] == attack and x["level"] == level), None)
                if m == "jwt":
                    cells.append("no audit log")
                elif r is None:
                    cells.append("n/a")
                else:
                    cells.append(f"{r['detected']}/{r['n']} [>={r['ci95_low_pct']}%]")
            if attack.startswith("all attacks"):
                continue
            print(f"  {attack:<44}{level:>4}" + "".join(f"{c:>24}" for c in cells))
        print("  Lvl 1 = database-only attacker; Lvl 2 = host attacker who can also rewrite the anchor if it is a local file.")
        print("  CONTROL row: 'detected' means a false alarm (lower is better).")
        out["audit_tampering"] = tamper
    return out


if __name__ == "__main__":
    ran = []
    for m in args.modes:
        if args.reuse or run_mode(m):
            ran.append(m)
    data = {m: load(m) for m in ran}
    data = {m: d for m, d in data.items() if d and d.get("performance")}
    if len(data) < 2:
        sys.exit("\nNeed results from at least two modes to compare "
                 f"(have: {list(data)}). See {OUT_DIR}")
    modes = [m for m in ("jwt", "local", "fabric") if m in data]
    result = compare(modes, data)
    (OUT_DIR / "comparison.json").write_text(json.dumps(result, indent=2))
    print(f"\n  Saved: {OUT_DIR / 'comparison.json'}  (per-mode raw data: rigorous_<mode>.json)")
