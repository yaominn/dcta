"""
Hash-chained audit log tests. (brief Section 4.5 acceptance test)

"Editing one byte of an old audit entry makes verify_chain() report the break
at exactly that entry." Covers: intact chain, content tamper at exact index,
earliest-break-wins, hash-field tamper, and linkage break from deletion.
"""
from __future__ import annotations

from backend.audit.log import AuditLog, AuditEntryType
from backend.data.db import connect


def _log(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.db")


def test_empty_chain_ok(tmp_path):
    assert _log(tmp_path).verify_chain() == {"ok": True, "break_at": None, "reason": None}


def test_chain_intact_after_appends(tmp_path):
    log = _log(tmp_path)
    for i in range(3):
        log.append(AuditEntryType.DRAFT, {"i": i})
    assert log.verify_chain()["ok"] is True


def test_tamper_payload_detected_at_exact_index(tmp_path):
    log = _log(tmp_path)
    log.append(AuditEntryType.DRAFT, {"v": "a"})        # index 0 (id 1)
    log.append(AuditEntryType.SIGNATURE, {"v": "b"})    # index 1 (id 2) <- tamper this
    log.append(AuditEntryType.EXECUTION, {"v": "c"})    # index 2 (id 3)

    log._raw_update_payload(2, '{"v":"HACKED"}')        # edit one byte of an old entry

    r = log.verify_chain()
    assert r["ok"] is False
    assert r["break_at"] == 1                            # exact entry, 0-based
    assert "tampered" in r["reason"]


def test_earliest_break_is_reported(tmp_path):
    log = _log(tmp_path)
    log.append(AuditEntryType.DRAFT, {"v": "a"})
    log.append(AuditEntryType.DRAFT, {"v": "b"})
    log.append(AuditEntryType.DRAFT, {"v": "c"})
    log._raw_update_payload(2, '{"v":"X"}')   # index 1
    log._raw_update_payload(3, '{"v":"Y"}')   # index 2

    assert log.verify_chain()["break_at"] == 1           # earliest, not 2


def test_tamper_hash_field_detected(tmp_path):
    log = _log(tmp_path)
    log.append(AuditEntryType.DRAFT, {"v": "a"})
    log.append(AuditEntryType.DRAFT, {"v": "b"})

    conn = connect(tmp_path / "audit.db")
    conn.execute("UPDATE audit_log SET hash='deadbeef' WHERE id=1")
    conn.commit(); conn.close()

    r = log.verify_chain()
    assert r["ok"] is False
    assert r["break_at"] == 0


def test_linkage_break_from_deletion_detected(tmp_path):
    log = _log(tmp_path)
    log.append(AuditEntryType.DRAFT, {"v": "a"})
    log.append(AuditEntryType.DRAFT, {"v": "b"})
    log.append(AuditEntryType.DRAFT, {"v": "c"})

    conn = connect(tmp_path / "audit.db")
    conn.execute("DELETE FROM audit_log WHERE id=2")    # remove the middle entry
    conn.commit(); conn.close()

    r = log.verify_chain()
    assert r["ok"] is False
    assert r["break_at"] is not None                     # the gap surfaces as a linkage break


def test_tamper_demo_catches_the_edit_and_leaves_the_log_alone(tmp_path):
    """The audit page's Tamper button: an amount changed in a copy of the
    chain is caught at that entry; the real rows are byte-for-byte unchanged."""
    log = _log(tmp_path)
    log.append(AuditEntryType.DRAFT, {"v": "a"})
    log.append(AuditEntryType.EXECUTION, {"amount_cents": 5000, "ok": True})   # id 2
    log.append(AuditEntryType.SIGNATURE, {"v": "c"})
    before = log.all_entries()

    r = log.simulate_tamper(2)

    assert r["ok"] is False and r["break_at"] == 1 and "tampered" in r["reason"]
    assert r["broken_id"] == 2 and r["live_ok"] is True
    assert (r["field"], r["old"], r["new"]) == ("amount_cents", 5000, 500000)
    assert log.all_entries() == before
    assert log.verify_chain()["ok"] is True


def test_tamper_demo_changes_something_in_any_payload(tmp_path):
    log = _log(tmp_path)
    log.append(AuditEntryType.POLICY, {"verified": True})
    log.append(AuditEntryType.TRANSCRIPT, {"chars": 12, "hash": "ab"})
    log.append(AuditEntryType.DRAFT, {"draft_id": "d1"})
    log.append(AuditEntryType.DRAFT, {})
    assert log.simulate_tamper(1)["new"] is False
    assert log.simulate_tamper(2)["new"] == 13
    assert log.simulate_tamper(3)["new"] == "d2"
    assert [log.simulate_tamper(i)["break_at"] for i in (1, 2, 3, 4)] == [0, 1, 2, 3]
    assert log.simulate_tamper(99) is None


def test_tamper_demo_endpoint_never_writes_the_live_log(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import backend.main as main

    log = _log(tmp_path)
    log.append(AuditEntryType.DRAFT, {"v": "a"})
    log.append(AuditEntryType.EXECUTION, {"amount_cents": 5000})
    before = log.all_entries()
    monkeypatch.setattr(main, "_audit", log)
    client = TestClient(main.app)

    r = client.post("/api/audit/tamper-demo", json={"entry_id": 2})
    assert r.status_code == 200 and r.json()["break_at"] == 1
    assert client.post("/api/audit/tamper-demo", json={"entry_id": 9}).status_code == 404
    assert log.all_entries() == before
    assert client.get("/api/audit/verify").json()["ok"] is True
    assert client.get("/audit").status_code == 200


def test_tamper_demo_reports_a_real_break_as_real(tmp_path):
    """If the live log is already broken earlier, the demo must not claim to
    have caught its own edit."""
    log = _log(tmp_path)
    for v in "abc":
        log.append(AuditEntryType.DRAFT, {"v": v})
    log._raw_update_payload(1, '{"v":"HACKED"}')
    r = log.simulate_tamper(3)
    assert r["live_ok"] is False and r["broken_id"] == 1


def test_tamper_demo_adds_a_field_when_there_is_nothing_to_edit(tmp_path):
    log = _log(tmp_path)
    log.append(AuditEntryType.DRAFT, {"note": "", "tampered": None})
    r = log.simulate_tamper(1)
    assert (r["field"], r["old"], r["new"]) == ("tampered", None, "yes") and r["ok"] is False
