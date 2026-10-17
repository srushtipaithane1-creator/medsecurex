"""
Audit.py : Tamper-Evident Audit Logging

Provides the HMAC key and convenience wrappers for audit log operations.
GDPR Article 5(2) requires controllers to be able to demonstrate compliance
('accountability') - a tamper-evident log fulfils this by making post-hoc
modification detectable.

The HMAC key is derived from AUDIT_HMAC_SEED, read from the environment at
import time. The module refuses to load if that variable is unset, so the
audit log is never written with a predictable key. In production this seed
would live in an HSM or a secrets vault (e.g. HashiCorp Vault).

KNOWN LIMITATION: each entry's tag covers only its own fields, so this
detects modification of an entry but not deletion of a whole entry, nor
reordering. A hash chain (including the previous entry's tag in each payload)
would close that. See the Known Limitations section of the README.
"""

import os
from Database import append_audit_log, get_audit_log
from CoreCrypto import hmac_verify, b64decode, b64encode, hmac_sign

# The seed is the secret; "audit-sub-key" is the public label derived from it.
_seed = os.environ.get("AUDIT_HMAC_SEED")
if not _seed:
    raise RuntimeError(
        "AUDIT_HMAC_SEED is not set. The audit log cannot be made "
        "tamper-evident without it. Copy .env.example and set a value, "
        "then export it before running. See README."
    )
AUDIT_HMAC_KEY = hmac_sign(b"audit-sub-key", _seed.encode("utf-8"))

def log_event(actor: str, role: str, action: str,
              target: str = "", outcome: str = "SUCCESS",
              details: str = "") -> int:
    """
    Append a tamper-evident entry to the audit log.
    Returns the new log_id.
    """
    return append_audit_log(
        actor=actor, role=role, action=action,
        target=target, outcome=outcome, details=details,
        hmac_key=AUDIT_HMAC_KEY
    )

def verify_audit_log_integrity() -> dict:
    """
    Re-compute the HMAC over each log entry and compare with the stored tag.
    Returns a report dict: {total, passed, failed, tampered_ids}.

    The payload string below must match the one built in
    Database.append_audit_log() character for character.
    """
    entries   = get_audit_log()
    passed    = 0
    failed    = 0
    tampered  = []

    for entry in entries:
        payload = (f"{entry['timestamp']}|{entry['actor']}|{entry['role']}|"
                   f"{entry['action']}|{entry['target']}|{entry['outcome']}|"
                   f"{entry['details']}")
        stored_tag = b64decode(entry['hmac_tag'])
        if hmac_verify(payload.encode('utf-8'), AUDIT_HMAC_KEY, stored_tag):
            passed += 1
        else:
            failed += 1
            tampered.append(entry['log_id'])

    return {
        "total":        len(entries),
        "passed":       passed,
        "failed":       failed,
        "tampered_ids": tampered
    }

def display_audit_log() -> None:
    """Print audit log entries in a formatted table."""
    entries = get_audit_log()
    if not entries:
        print("  [Audit Log is empty]")
        return
    print(f"\n  {'ID':>4}  {'Timestamp':<26}  {'Actor':<18}  {'Role':<12}  "
          f"{'Action':<22}  {'Outcome':<8}  Details")
    print("  " + "-" * 120)
    for e in entries:
        print(f"  {e['log_id']:>4}  {e['timestamp'][:26]:<26}  {e['actor']:<18}  "
              f"{e['role']:<12}  {e['action']:<22}  {e['outcome']:<8}  "
              f"{e['details'][:60]}")
