"""Unit tests for audit_verify (run: python test_audit_verify.py)."""
import hashlib, hmac
import audit_verify as av

ROWS = [
    {"id": 1, "agent_did": "did:a", "action": "register", "result": "success", "details": '{"x": 1}',
     "auth_time_ms": 1.25, "log_time_ms": 0.004, "timestamp": "2026-11-25 10:00:00"},
    {"id": 2, "agent_did": "did:a", "action": "authenticate", "result": "failed", "details": None,
     "auth_time_ms": 2.5, "log_time_ms": 0.0, "timestamp": "2026-11-25 10:00:01"},
]


def legacy_v1_tip(rows):
    """Verbatim copy of the pre-change algorithm - guards backwards compatibility."""
    tip = hmac.new(av.AUDIT_KEY, b"GENESIS", hashlib.sha256).digest()
    for row in rows:
        parts = [row.get("agent_did") or "", row["action"], row["result"], row.get("details") or ""]
        tip = hmac.new(av.AUDIT_KEY, tip + "|".join(parts).encode() + str(row["timestamp"]).encode(),
                       hashlib.sha256).digest()
    return tip.hex()


class FakeDB:
    def __init__(self, rows): self.rows = rows
    def get_audit_logs_up_to(self, end): return [r for r in self.rows if r["timestamp"] <= end]


class FakeFabric:
    def __init__(self, root): self.root = root
    def get_audit_anchor(self, batch_id): return {"rootHash": self.root, "periodEnd": "2026-11-25 10:00:01"}


def mutated(**changes):
    rows = [dict(r) for r in ROWS]
    rows[0].update(changes)
    return rows


def test_v1_unchanged():
    assert av.compute_chain_tip(ROWS, version=1) == legacy_v1_tip(ROWS)


def test_v2_covers_timing_columns():
    base = av.anchor_root(ROWS)
    assert base.startswith("v2:")
    assert av.anchor_root(mutated(auth_time_ms=999.0)) != base
    assert av.anchor_root(mutated(log_time_ms=999.0)) != base
    assert av.anchor_root(mutated(auth_time_ms=None)) != base


def test_v1_ignores_timing_columns():
    assert av.compute_chain_tip(mutated(auth_time_ms=999.0), 1) == av.compute_chain_tip(ROWS, 1)


def test_v2_still_covers_original_fields():
    base = av.anchor_root(ROWS)
    for change in ({"result": "failed"}, {"details": "x"}, {"agent_did": "did:z"}, {"timestamp": "2026-11-25 10:00:00.5"}):
        assert av.anchor_root(mutated(**change)) != base


def test_verify_batch_v2_detects_timing_tamper():
    anchored = av.anchor_root(ROWS)
    assert av.verify_batch(FakeDB(ROWS), FakeFabric(anchored), "b")["match"] is True
    res = av.verify_batch(FakeDB(mutated(auth_time_ms=5.0)), FakeFabric(anchored), "b")
    assert res["match"] is False and res["chain_version"] == 2 and res["covers_timing_columns"]


def test_legacy_anchor_still_verifies_and_warns():
    res = av.verify_batch(FakeDB(ROWS), FakeFabric(legacy_v1_tip(ROWS)), "b")
    assert res["match"] is True and res["chain_version"] == 1 and "warning" in res


def test_no_downgrade_via_database():
    # an attacker edits the DB; the version still comes from the anchor, so v2 strictness applies
    anchored = av.anchor_root(ROWS)
    res = av.verify_batch(FakeDB(mutated(log_time_ms=1.0)), FakeFabric(anchored), "b")
    assert res["match"] is False


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("ok  ", t.__name__)
    print(f"{len(tests)} passed")
