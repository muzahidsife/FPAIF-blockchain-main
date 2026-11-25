"""
Audit chain verification — recomputes the HMAC-SHA256 audit chain from raw
audit_logs rows and compares the result against the root hash anchored on
the Fabric ledger for a given batch.

Chain versions
  v1 (legacy anchors, root is bare hex): covers agent_did, action, result, details, timestamp.
  v2 (current, root is "v2:<hex>"):      v1 + auth_time_ms and log_time_ms, so the latency
                                         evidence in the audit log is tamper-evident too.
The version is read from the ANCHORED root (held by the ledger), never from the local
database, so an attacker cannot downgrade a v2 batch to the weaker v1 check.

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

CURRENT_VERSION = 2
V2_PREFIX = "v2:"


def _num(value) -> str:
    """Canonical text for a REAL column. repr() of a float round-trips exactly through SQLite."""
    return "" if value is None else repr(float(value))


def _event_bytes(row: Dict, version: int = CURRENT_VERSION) -> bytes:
    parts = [
        row.get("agent_did") or "",
        row["action"],
        row["result"],
        row.get("details") or "",
    ]
    if version >= 2:
        parts += [_num(row.get("auth_time_ms")), _num(row.get("log_time_ms"))]
    return "|".join(parts).encode()


def compute_chain_tip(rows: List[Dict], version: int = CURRENT_VERSION) -> str:
    genesis = b"GENESIS" if version == 1 else b"GENESIS-v2"
    tip = hmac.new(AUDIT_KEY, genesis, hashlib.sha256).digest()
    for row in rows:
        message = tip + _event_bytes(row, version) + str(row["timestamp"]).encode()
        tip = hmac.new(AUDIT_KEY, message, hashlib.sha256).digest()
    return tip.hex()


def anchor_root(rows: List[Dict]) -> str:
    """The value to anchor on the ledger for these rows: a version-labelled chain tip."""
    return V2_PREFIX + compute_chain_tip(rows, CURRENT_VERSION)


def parse_root(root: str):
    """(version, hex_tip) from an anchored root. Unlabelled roots are legacy v1."""
    if root.startswith(V2_PREFIX):
        return 2, root[len(V2_PREFIX):]
    return 1, root


def verify_batch(db, fabric_client, batch_id: str) -> Dict:
    anchor = fabric_client.get_audit_anchor(batch_id)
    if not anchor:
        return {"batch_id": batch_id, "match": False,
                "reason": "No anchor found on ledger for this batch_id."}

    rows = db.get_audit_logs_up_to(anchor["periodEnd"])
    if not rows:
        return {"batch_id": batch_id, "match": False,
                "reason": "No local audit_logs rows found up to periodEnd."}

    anchored_root = anchor["rootHash"]
    version, anchored_tip = parse_root(anchored_root)
    computed_tip = compute_chain_tip(rows, version)
    computed_root = V2_PREFIX + computed_tip if version >= 2 else computed_tip
    match = hmac.compare_digest(computed_tip, anchored_tip)

    result = {
        "batch_id": batch_id, "match": match,
        "computed_root": computed_root, "anchored_root": anchored_root,
        "events_checked": len(rows), "period_end": anchor["periodEnd"],
        "chain_version": version, "covers_timing_columns": version >= 2,
    }
    if version == 1:
        result["warning"] = ("Legacy v1 anchor: auth_time_ms and log_time_ms are not "
                             "covered by this batch's integrity check.")
    if not match:
        result["reason"] = ("Computed chain tip does not match the on-chain "
                             "root. One or more audit_logs rows have been "
                             "altered, reordered, or deleted since this "
                             "batch was anchored.")
    return result
