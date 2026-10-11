"""
blockchain_metrics.py - On-chain metrics for FPAIF (Hyperledger Fabric)
=======================================================================
Combines two sources into one report, in the same style as run_tests.py:

  1. Caliper   - throughput / latency / success rate per AgentIdentityContract
                 function (parsed from caliper-workspace/report.html)
  2. Explorer  - ledger statistics (blocks, transactions, per-org activity,
                 block size / interval) from the Hyperledger Explorer REST API

Prereqs:
  - Fabric network up, AgentIdentityContract committed on mychannel
  - caliper-workspace/run-benchmark.sh has been run (creates report.html)
  - Explorer running:  cd explorer && docker compose up -d

Usage:
  python blockchain_metrics.py
  python blockchain_metrics.py --explorer http://localhost:8080 --channel mychannel
Output:
  printed table + blockchain_metrics.json
"""

import argparse
import json
import re
import statistics
import sys
from datetime import datetime
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent

parser = argparse.ArgumentParser()
parser.add_argument("--explorer", default="http://localhost:8080")
parser.add_argument("--network", default="test-network", help="Explorer network name")
parser.add_argument("--channel", default="mychannel")
parser.add_argument("--user", default="exploreradmin")
parser.add_argument("--password", default="exploreradminpw")
parser.add_argument("--report", default=str(ROOT / "caliper-workspace" / "report.html"))
parser.add_argument("--out", default=str(Path(__file__).resolve().parent / "blockchain_metrics.json"))
args = parser.parse_args()

RESULTS = {}


def sep(title=""):
    w = 64
    if title:
        pad = (w - len(title) - 2) // 2
        print(f"\n{'=' * pad} {title} {'=' * pad}")
    else:
        print("=" * w)


# ── 1. Caliper ────────────────────────────────────────────────────────────────

def parse_caliper(report_path):
    """Return one dict per round from the 'Summary of performance metrics' table."""
    html = Path(report_path).read_text()
    start = html.index("Summary of performance metrics")
    end = html.index("</table>", start)
    rows = []
    for tr in re.findall(r"<tr>(.*?)</tr>", html[start:end], re.S):
        cells = [c.strip() for c in re.findall(r"<td>(.*?)</td>", tr)]
        if len(cells) != 8:
            continue
        name, succ, fail, send, mx, mn, avg, tps = cells
        succ, fail = int(succ), int(fail)
        rows.append({
            "round": name,
            "success": succ,
            "fail": fail,
            "success_rate": round(100 * succ / (succ + fail), 2) if succ + fail else 0.0,
            "send_rate_tps": float(send),
            "latency_max_ms": round(float(mx) * 1000),
            "latency_min_ms": round(float(mn) * 1000),
            "latency_avg_ms": round(float(avg) * 1000),
            "throughput_tps": float(tps),
        })
    return rows


def caliper_section():
    sep("CALIPER - ON-CHAIN PERFORMANCE")
    try:
        rows = parse_caliper(args.report)
    except (OSError, ValueError) as e:
        print(f"  SKIPPED: cannot read Caliper report ({args.report}): {e}")
        print("  Run caliper-workspace/run-benchmark.sh first.")
        return
    if not rows:
        print("  SKIPPED: no rounds found in the Caliper report.")
        return

    print(f"  {'Round':<24}{'Succ':>6}{'Fail':>6}{'Succ%':>8}{'Send TPS':>10}{'Thru TPS':>10}"
          f"{'Min ms':>8}{'Avg ms':>8}{'Max ms':>8}")
    print("  " + "-" * 88)
    for r in rows:
        print(f"  {r['round']:<24}{r['success']:>6}{r['fail']:>6}{r['success_rate']:>8}"
              f"{r['send_rate_tps']:>10}{r['throughput_tps']:>10}"
              f"{r['latency_min_ms']:>8}{r['latency_avg_ms']:>8}{r['latency_max_ms']:>8}")

    total_ok = sum(r["success"] for r in rows)
    total_fail = sum(r["fail"] for r in rows)
    RESULTS["caliper_rounds"] = rows
    RESULTS["chain_tx_total"] = total_ok + total_fail
    RESULTS["chain_tx_success_rate"] = round(100 * total_ok / (total_ok + total_fail), 2)

    def group(prefix):
        g = [r for r in rows if r["round"].startswith(prefix)]
        if not g:
            return None
        ok = sum(r["success"] for r in g)
        return {
            "avg_ms": round(statistics.mean(r["latency_avg_ms"] for r in g)),
            "max_throughput_tps": max(r["throughput_tps"] for r in g),
            "success_rate": round(100 * ok / (ok + sum(r["fail"] for r in g)), 2),
        }

    for key, prefix in [("register", "registerAgent"), ("get_agent", "getAgent"),
                        ("is_revoked", "isRevoked"), ("revoke", "revokeAgent"),
                        ("anchor", "anchorAuditBatch")]:
        g = group(prefix)
        if g:
            RESULTS[f"chain_{key}_avg_ms"] = g["avg_ms"]
            RESULTS[f"chain_{key}_max_throughput_tps"] = g["max_throughput_tps"]
            RESULTS[f"chain_{key}_success_rate"] = g["success_rate"]


# ── 2. Explorer ───────────────────────────────────────────────────────────────

def explorer_section():
    sep("EXPLORER - LEDGER STATISTICS")
    base = args.explorer.rstrip("/")
    try:
        r = requests.post(f"{base}/auth/login", timeout=10, json={
            "user": args.user, "password": args.password, "network": args.network})
        r.raise_for_status()
        hdr = {"Authorization": f"Bearer {r.json()['token']}"}

        def get(path):
            resp = requests.get(f"{base}/{path}", headers=hdr, timeout=15)
            resp.raise_for_status()
            return resp.json()

        chans = get("api/channels/info")["channels"]
        ch = next(c for c in chans if c["channelname"] == args.channel)
        gh = ch["channel_genesis_hash"]  # most Explorer endpoints key on the genesis hash
        status = get(f"api/status/{gh}")
        by_org = get(f"api/txByOrg/{gh}")["rows"]
        cc = get(f"api/chaincode/{gh}")["chaincode"]
        blocks = get(f"api/blockActivity/{gh}")["row"]
    except Exception as e:
        print(f"  SKIPPED: Explorer not reachable/usable at {base}: {e}")
        print("  Start it with:  cd explorer && docker compose up -d")
        return

    blocks_total = ch["blocks"]
    tx_total = ch["transactions"]
    times = sorted(datetime.fromisoformat(b["createdt"].replace("Z", "+00:00")) for b in blocks)
    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    tx_per_block = [b["txcount"] for b in blocks]

    RESULTS.update({
        "ledger_blocks": blocks_total,
        "ledger_transactions": tx_total,
        "ledger_latest_block": int(status["latestBlock"]),
        "ledger_peers": int(status["peerCount"]),
        "ledger_avg_tx_per_block": round(tx_total / blocks_total, 2) if blocks_total else 0,
        "ledger_recent_block_interval_avg_s": round(statistics.mean(gaps), 3) if gaps else None,
        "ledger_recent_tx_per_block_max": max(tx_per_block) if tx_per_block else None,
        "ledger_tx_by_org": {r["creator_msp_id"]: int(r["count"]) for r in by_org},
        "ledger_chaincode_tx": {c["chaincodename"]: c["txCount"] for c in cc},
    })
    for k in ("ledger_blocks", "ledger_transactions", "ledger_latest_block", "ledger_peers",
              "ledger_avg_tx_per_block", "ledger_recent_block_interval_avg_s",
              "ledger_recent_tx_per_block_max"):
        print(f"  {k:<40}{RESULTS[k]}")
    print(f"  {'ledger_tx_by_org':<40}{RESULTS['ledger_tx_by_org']}")
    print(f"  {'ledger_chaincode_tx':<40}{RESULTS['ledger_chaincode_tx']}")


def main():
    print(f"FPAIF blockchain metrics - {datetime.now():%Y-%m-%d %H:%M:%S}")
    caliper_section()
    explorer_section()
    if not RESULTS:
        print("\nNo data collected.")
        sys.exit(1)
    RESULTS["generated_at"] = datetime.now().isoformat(timespec="seconds")
    Path(args.out).write_text(json.dumps(RESULTS, indent=2))
    sep()
    print(f"  Saved: {args.out}")


if __name__ == "__main__":
    main()
