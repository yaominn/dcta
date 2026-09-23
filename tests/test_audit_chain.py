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
