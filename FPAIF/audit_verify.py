"""
Audit chain verification — recomputes the HMAC-SHA256 audit chain from raw
audit_logs rows and compares the result against the root hash anchored on
the Fabric ledger for a given batch.

Design note: verification NEVER trusts a stored intermediate hash. It always
walks the raw event columns (agent_did, action, result, details, timestamp)
from genesis forward. If any row was edited after the fact, the recomputed
chain will diverge from the anchored root — that divergence IS the tamper
detection.
"""

import hmac
import hashlib
import os
from typing import Dict, List, Optional

AUDIT_KEY = os.environ.get("FPAIF_AUDIT_KEY", "dev-only-change-me").encode()


def _event_bytes(row: Dict) -> bytes:
    parts = [
        row.get("agent_did") or "",
        row["action"],
        row["result"],
        row.get("details") or "",
    ]
    return "|".join(parts).encode()


def compute_chain_tip(rows: List[Dict]) -> str:
    tip = hmac.new(AUDIT_KEY, b"GENESIS", hashlib.sha256).digest()
    for row in rows:
        message = tip + _event_bytes(row) + str(row["timestamp"]).encode()
        tip = hmac.new(AUDIT_KEY, message, hashlib.sha256).digest()
    return tip.hex()


def verify_batch(db, fabric_client, batch_id: str) -> Dict:
    anchor = fabric_client.get_audit_anchor(batch_id)
    if not anchor:
        return {"batch_id": batch_id, "match": False,
                "reason": "No anchor found on ledger for this batch_id."}

    rows = db.get_audit_logs_up_to(anchor["periodEnd"])
    if not rows:
        return {"batch_id": batch_id, "match": False,
                "reason": "No local audit_logs rows found up to periodEnd."}

    computed_root = compute_chain_tip(rows)
    anchored_root = anchor["rootHash"]
    match = hmac.compare_digest(computed_root, anchored_root)

    result = {
        "batch_id": batch_id, "match": match,
        "computed_root": computed_root, "anchored_root": anchored_root,
        "events_checked": len(rows), "period_end": anchor["periodEnd"],
    }
    if not match:
        result["reason"] = ("Computed chain tip does not match the on-chain "
                             "root. One or more audit_logs rows have been "
                             "altered, reordered, or deleted since this "
                             "batch was anchored.")
    return result
