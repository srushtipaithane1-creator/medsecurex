"""
Role.py : Role-Specific Data Operations

Implements all role-specific operations, enforcing RBAC at every entry point.
Sequence (Data Pipeline): Clinician -> Researcher -> Auditor
  1. Clinicians upload encrypted patient datasets
  2. Researchers encrypt, sign, and analyse research findings
  3. Auditors verify signatures, check integrity proofs, and review logs

Every operation calls require_permission() before executing, so no role can
perform actions outside its permitted set (ANSI INCITS 359-2012 RBAC), and
every operation calls log_event() afterwards.
"""

from CoreCrypto import (
    generate_aes_key, aes_encrypt, aes_decrypt,
    rsa_encrypt_key, rsa_decrypt_key,
    ecdsa_sign, ecdsa_verify,
    sha384_hash, b64encode, b64decode,
    load_public_key, load_private_key, serialise_public_key
)
from Database import (
    insert_patient_record, get_patient_records_by_clinician,
    get_all_patient_records, get_patient_record_by_id,
    update_patient_record, soft_delete_patient_record,
    insert_research_finding, get_all_research_findings,
    get_research_finding_by_id, update_research_finding,
    soft_delete_research_finding, get_user, get_audit_log
)
from Auth import require_permission
from Audit import log_event, verify_audit_log_integrity, display_audit_log


# Clinical Operations::
# Domain: Patient dataset management (upload, retrieve, update, delete)
# Cryptography: AES-256-GCM (data), RSA-4096-OAEP (key wrap), SHA-384 (integrity)
# Rationale: AES-GCM provides authenticated encryption for patient data.
#            RSA-OAEP wraps the AES key under the uploading clinician's own
#            public key, so no other user can decrypt the record.
#            SHA-384 fingerprints the plaintext for auditor integrity checks.

def _read_multiline(prompt: str) -> bytes:
    """Read lines from stdin until a line containing only END."""
    print(prompt)
    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)
    return "\n".join(lines).encode('utf-8')


def c_upload_patient_record(session: dict) -> None:
    """
    Clinician uploads an encrypted patient dataset.
    Workflow:
      a. Generate fresh AES-256 key
      b. AES-GCM encrypt the patient data
      c. RSA-OAEP wrap the AES key with the clinician's RSA public key
      d. Compute SHA-384 digest of plaintext
      e. Store ciphertext, wrapped key, and digest in DB
    """
    require_permission(session["role"], "upload_patient_record")

    print("\n ::: Upload Patient Record :::")
    patient_id  = input("  Patient ID (de-identified token): ").strip()
    record_type = input("  Record type (e.g. blood_results / imaging / notes): ").strip()
    description = input("  Short description: ").strip()
    plaintext   = _read_multiline("  Enter patient data (type END on a new line to finish):")

    # Encrypt
    aes_key        = generate_aes_key()                                  # Fresh AES-256 key
    encrypted_data = aes_encrypt(plaintext, aes_key)                     # AES-256-GCM
    encrypted_key  = rsa_encrypt_key(aes_key, session["rsa_public"])     # RSA-4096-OAEP
    digest         = sha384_hash(plaintext)                              # SHA-384 fingerprint

    record_id = insert_patient_record(
        patient_id=patient_id,
        uploaded_by=session["username"],
        encrypted_data=b64encode(encrypted_data),
        encrypted_aes_key=b64encode(encrypted_key),
        sha384_digest=digest,
        record_type=record_type,
        description=description
    )

    log_event(actor=session["username"], role=session["role"],
              action="UPLOAD_PATIENT_RECORD", target=f"record_id={record_id}",
              outcome="SUCCESS",
              details=f"patient_id={patient_id}, type={record_type}")
    print(f"\n  :) Patient record uploaded successfully. Record ID: {record_id}")

def c_retrieve_patient_record(session: dict) -> None:
    """
    Clinician retrieves and decrypts one of their own patient records.
    The RSA private key (held in session) unwraps the AES key, which then
    decrypts the ciphertext. Integrity is confirmed via SHA-384.
    """
    require_permission(session["role"], "retrieve_patient_record")

    records = get_patient_records_by_clinician(session["username"])
    if not records:
        print("\n  :( No patient records found.")
        return

    print("\n  ::: Your Patient Records :::")
    for r in records:
        print(f"  ID:{r['record_id']:>4}  Patient:{r['patient_id']:<16}  "
              f"Type:{r['record_type']:<15}  {r['created_at'][:10]}")

    try:
        rid = int(input("\n  Enter Record ID to decrypt: "))
    except ValueError:
        print("  Invalid ID !"); return

    record = get_patient_record_by_id(rid)
    if record is None or record["uploaded_by"] != session["username"]:
        print("   Record not found or access denied.")
        log_event(actor=session["username"], role=session["role"],
                  action="RETRIEVE_PATIENT_RECORD", target=f"record_id={rid}",
                  outcome="FAILURE", details="Unauthorised access attempt")
        return

    try:
        enc_data  = b64decode(record["encrypted_data"])
        enc_key   = b64decode(record["encrypted_aes_key"])
        aes_key   = rsa_decrypt_key(enc_key, session["rsa_private"])
        plaintext = aes_decrypt(enc_data, aes_key)

        # Verify SHA-384 integrity
        digest = sha384_hash(plaintext)
        integrity_ok = (digest == record["sha384_digest"])
    except Exception as e:
        print(f"  Decryption failed: {e}")
        log_event(actor=session["username"], role=session["role"],
                  action="RETRIEVE_PATIENT_RECORD", target=f"record_id={rid}",
                  outcome="FAILURE", details=str(e))
        return

    log_event(actor=session["username"], role=session["role"],
              action="RETRIEVE_PATIENT_RECORD", target=f"record_id={rid}",
              outcome="SUCCESS",
              details=f"integrity_ok={integrity_ok}")

    print(f"\n  ::: Decrypted Patient Data :::")
    print(f"  Patient ID : {record['patient_id']}")
    print(f"  Type       : {record['record_type']}")
    print(f"  Integrity  : {':) VERIFIED' if integrity_ok else '! TAMPERED'}")
    print(f"  Data:\n{plaintext.decode('utf-8')}")

def c_update_patient_record(session: dict) -> None:
    """
    Update an existing patient record with new encrypted content.
    A completely fresh AES key is generated, so no key ever encrypts two
    different plaintexts.
    """
    require_permission(session["role"], "update_patient_record")

    records = get_patient_records_by_clinician(session["username"])
    if not records:
        print("\n   No records to update."); return

    for r in records:
        print(f"  ID:{r['record_id']:>4}  Patient:{r['patient_id']:<16}  {r['record_type']}")
    try:
        rid = int(input("\n  Enter Record ID to update: "))
    except ValueError:
        print("   Invalid ID ! "); return

    record = get_patient_record_by_id(rid)
    if record is None or record["uploaded_by"] != session["username"]:
        print("   Record not found or access denied."); return

    plaintext = _read_multiline("  Enter new patient data (type END on a new line to finish):")

    aes_key        = generate_aes_key()
    encrypted_data = aes_encrypt(plaintext, aes_key)
    encrypted_key  = rsa_encrypt_key(aes_key, session["rsa_public"])
    digest         = sha384_hash(plaintext)

    success = update_patient_record(
        record_id=rid, clinician=session["username"],
        encrypted_data=b64encode(encrypted_data),
        encrypted_aes_key=b64encode(encrypted_key),
        sha384_digest=digest
    )
    log_event(actor=session["username"], role=session["role"],
              action="UPDATE_PATIENT_RECORD", target=f"record_id={rid}",
              outcome="SUCCESS" if success else "FAILURE")
    print(f"  {':) Record updated.' if success else '! Update failed.'}")

def c_delete_patient_record(session: dict) -> None:
    """Soft-delete a patient record (GDPR Art. 17 right to erasure)."""
    require_permission(session["role"], "delete_patient_record")

    records = get_patient_records_by_clinician(session["username"])
    if not records:
        print("\n   No records to delete."); return
    for r in records:
        print(f"  ID:{r['record_id']:>4}  Patient:{r['patient_id']}")
    try:
        rid = int(input("\n  Enter Record ID to delete: "))
    except ValueError:
        print("   Invalid ID !."); return

    confirm = input(f"  Confirm deletion of Record {rid}? (yes/no): ")
    if confirm.lower() != "yes":
        print("  Cancelled."); return

    success = soft_delete_patient_record(rid, session["username"])
    log_event(actor=session["username"], role=session["role"],
              action="DELETE_PATIENT_RECORD", target=f"record_id={rid}",
              outcome="SUCCESS" if success else "FAILURE",
              details="Soft-delete (GDPR Art.17)")
    print(f"  {':) Record deleted (soft).' if success else '! Delete failed.'}")

def c_list_own_records(session: dict) -> None:
    """List the clinician's own records. Permission-checked like every other operation."""
    require_permission(session["role"], "list_own_records")
    records = get_patient_records_by_clinician(session["username"])
    print(f"\n  You have {len(records)} active record(s).")
    for r in records:
        print(f"  ID:{r['record_id']:>4}  Patient:{r['patient_id']:<16}  "
              f"{r['record_type']:<15}  {r['created_at'][:10]}")


# Researcher Operations::
# Domain: Research findings - encrypt, sign, update, delete, cross-researcher share
# Cryptography: AES-256-GCM (data), RSA-4096-OAEP (key wrap), ECDSA P-384 (signature)
# Rationale: Signing with ECDSA P-384 provides non-repudiation - the researcher
#            cannot later deny authorship of a finding (FIPS 186-5). Cross-
#            researcher sharing re-wraps the AES key with the target
#            researcher's RSA public key.
#
# All three signature call sites (create, update, verify) operate on the
# SHA-384 hex digest, never the raw plaintext. This lets the auditor verify a
# signature without ever decrypting the data.

def r_encrypt_and_sign(session: dict) -> None:
    """
    Researcher encrypts a research finding and signs it.
    Workflow:
      a. Generate AES-256 key
      b. AES-GCM encrypt the finding content
      c. RSA-OAEP wrap AES key
      d. SHA-384 fingerprint the plaintext
      e. ECDSA P-384 sign that digest
      f. Store all in DB
    """
    require_permission(session["role"], "sign_research_finding")

    print("\n  Encrypt & Sign Research Finding ")
    title     = input("  Finding title: ").strip()
    plaintext = _read_multiline("  Enter finding content (type END on a new line to finish):")

    aes_key        = generate_aes_key()
    encrypted_data = aes_encrypt(plaintext, aes_key)
    encrypted_key  = rsa_encrypt_key(aes_key, session["rsa_public"])
    digest         = sha384_hash(plaintext)
    signature      = ecdsa_sign(digest.encode(), session["ecdsa_private"])   # ECDSA P-384

    finding_id = insert_research_finding(
        title=title,
        authored_by=session["username"],
        encrypted_data=b64encode(encrypted_data),
        encrypted_aes_key=b64encode(encrypted_key),
        ecdsa_signature=b64encode(signature),
        sha384_digest=digest,
        signed_by=session["username"]
    )
    log_event(actor=session["username"], role=session["role"],
              action="ENCRYPT_SIGN_FINDING", target=f"finding_id={finding_id}",
              outcome="SUCCESS", details=f"title={title}")
    print(f"\n  :) Finding encrypted and signed. Finding ID: {finding_id}")

def r_decrypt_finding(session: dict) -> None:
    """
    Researcher decrypts one of their own findings (or a copy shared with them,
    whose AES key was re-wrapped under their public key).
    """
    require_permission(session["role"], "decrypt_research_data")

    findings = get_all_research_findings()
    if not findings:
        print("\n   No findings available."); return

    print("\n   Research Findings:")
    for f in findings:
        print(f"  ID:{f['finding_id']:>4}  Author:{f['authored_by']:<18}  {f['title'][:40]}")

    try:
        fid = int(input("\n  Enter Finding ID to decrypt: "))
    except ValueError:
        print("Invalid ID!"); return

    finding = get_research_finding_by_id(fid)
    if finding is None:
        print("Finding not found."); return

    try:
        enc_data  = b64decode(finding["encrypted_data"])
        enc_key   = b64decode(finding["encrypted_aes_key"])
        aes_key   = rsa_decrypt_key(enc_key, session["rsa_private"])
        plaintext = aes_decrypt(enc_data, aes_key)
        digest_ok = (sha384_hash(plaintext) == finding["sha384_digest"])
    except Exception as e:
        print(f"\n   Decryption failed (you may not hold the key for this finding): {e}")
        log_event(actor=session["username"], role=session["role"],
                  action="DECRYPT_FINDING", target=f"finding_id={fid}",
                  outcome="FAILURE", details="Key not held by this user")
        return

    log_event(actor=session["username"], role=session["role"],
              action="DECRYPT_FINDING", target=f"finding_id={fid}",
              outcome="SUCCESS", details=f"integrity_ok={digest_ok}")
    print(f"\n  Decrypted Finding :")
    print(f"  Title     : {finding['title']}")
    print(f"  Author    : {finding['authored_by']}")
    print(f"  Integrity : {':) VERIFIED' if digest_ok else ' ! TAMPERED'}")
    print(f"  Content:\n{plaintext.decode('utf-8')}")

def r_cross_share(session: dict) -> None:
    """
    Cross-researcher sharing: Researcher A re-wraps a finding's AES key so that
    Researcher B can decrypt it with their own RSA private key.
    Workflow:
      a. A unwraps the AES key with their private key
      b. A fetches B's RSA public key from the DB
      c. A re-wraps the AES key under B's public key
      d. A new row is stored, owned by B but still SIGNED BY A

    The signed_by column is what keeps signature verification correct on the
    shared copy: ownership moves to B, authorship of the signature stays with A.
    """
    require_permission(session["role"], "cross_decrypt")

    findings = [f for f in get_all_research_findings()
                if f["authored_by"] == session["username"]]
    if not findings:
        print("\n You have no findings to share."); return

    for f in findings:
        print(f" ID:{f['finding_id']:>4}  {f['title']}")
    try:
        fid = int(input("\n Enter Finding ID to share: "))
    except ValueError:
        print("  Invalid ID!"); return

    target_user = input(" Username of target researcher: ").strip()
    target_row  = get_user(target_user)
    if target_row is None or target_row["role"] != "researcher":
        print("   Target researcher not found."); return

    finding = get_research_finding_by_id(fid)
    if finding is None or finding["authored_by"] != session["username"]:
        print("   Finding not found or not yours."); return

    try:
        enc_key = b64decode(finding["encrypted_aes_key"])
        aes_key = rsa_decrypt_key(enc_key, session["rsa_private"])

        # Load target researcher's RSA public key and re-wrap
        target_pub  = load_public_key(target_row["rsa_public_key"].encode())
        new_enc_key = rsa_encrypt_key(aes_key, target_pub)

        new_fid = insert_research_finding(
            title=f"[SHARED from {session['username']}] {finding['title']}",
            authored_by=target_user,
            encrypted_data=finding["encrypted_data"],
            encrypted_aes_key=b64encode(new_enc_key),
            ecdsa_signature=finding["ecdsa_signature"],   # Original signature preserved
            sha384_digest=finding["sha384_digest"],
            signed_by=finding["signed_by"]                # ...and so is its author
        )
        log_event(actor=session["username"], role=session["role"],
                  action="CROSS_SHARE_FINDING", target=f"finding_id={fid}=>{new_fid}",
                  outcome="SUCCESS", details=f"shared_with={target_user}")
        print(f"\n  ^^ Finding re-encrypted for {target_user}. New Finding ID: {new_fid}")
    except Exception as e:
        print(f"   Sharing failed: {e}")
        log_event(actor=session["username"], role=session["role"],
                  action="CROSS_SHARE_FINDING", target=f"finding_id={fid}",
                  outcome="FAILURE", details=str(e))

def r_update_finding(session: dict) -> None:
    """
    Update and re-sign an existing research finding.
    The digest is computed BEFORE signing, and the signature is taken over the
    digest - matching r_encrypt_and_sign and a_verify_signature.
    """
    require_permission(session["role"], "update_research_finding")

    findings = [f for f in get_all_research_findings()
                if f["authored_by"] == session["username"]]
    if not findings:
        print("\n   No findings to update."); return
    for f in findings:
        print(f"  ID:{f['finding_id']:>4}  v{f['version']}  {f['title'][:50]}")
    try:
        fid = int(input("\n  Enter Finding ID to update: "))
    except ValueError:
        print("  Invalid ID!"); return

    plaintext = _read_multiline("  Enter revised content (type END to finish):")

    aes_key        = generate_aes_key()
    encrypted_data = aes_encrypt(plaintext, aes_key)
    encrypted_key  = rsa_encrypt_key(aes_key, session["rsa_public"])
    digest         = sha384_hash(plaintext)
    signature      = ecdsa_sign(digest.encode(), session["ecdsa_private"])

    success = update_research_finding(
        finding_id=fid, researcher=session["username"],
        encrypted_data=b64encode(encrypted_data),
        encrypted_aes_key=b64encode(encrypted_key),
        ecdsa_signature=b64encode(signature),
        sha384_digest=digest
    )
    log_event(actor=session["username"], role=session["role"],
              action="UPDATE_FINDING", target=f"finding_id={fid}",
              outcome="SUCCESS" if success else "FAILURE")
    print(f"  {':) Finding updated and re-signed.' if success else 'Update failed.'}")

def r_delete_finding(session: dict) -> None:
    """Soft-delete a research finding."""
    require_permission(session["role"], "delete_research_finding")

    findings = [f for f in get_all_research_findings()
                if f["authored_by"] == session["username"]]
    if not findings:
        print("\n   No findings to delete."); return
    for f in findings:
        print(f"  ID:{f['finding_id']:>4}  {f['title'][:50]}")
    try:
        fid = int(input("\n  Enter Finding ID to delete: "))
    except ValueError:
        print("   Invalid ID!"); return

    confirm = input(f"  Confirm deletion of Finding {fid}? (yes/no): ")
    if confirm.lower() != "yes":
        print("  Cancelled."); return

    success = soft_delete_research_finding(fid, session["username"])
    log_event(actor=session["username"], role=session["role"],
              action="DELETE_FINDING", target=f"finding_id={fid}",
              outcome="SUCCESS" if success else "FAILURE",
              details="Soft-delete")
    print(f"  {'^^ Finding deleted.' if success else '! Delete failed.'}")

def r_list_findings(session: dict) -> None:
    """List all research findings. Permission-checked like every other operation."""
    require_permission(session["role"], "list_research_findings")
    findings = get_all_research_findings()
    print(f"\n  {len(findings)} research finding(s) on record.")
    for f in findings:
        print(f"  ID:{f['finding_id']:>4}  v{f['version']}  "
              f"Author:{f['authored_by']:<18}  {f['title'][:40]}")


# Auditor Operations:::
# Domain: Cross-domain read-only verification and compliance reporting
# Cryptography: ECDSA P-384 verify, HMAC-SHA-256 verify
# Rationale: Auditors have NO encryption/decryption capability - they were
#            never issued the keys. They verify signatures and integrity
#            proofs without plaintext access. This embodies least privilege
#            and separation of duties.

def a_verify_signature(session: dict) -> None:
    """
    Auditor verifies the ECDSA P-384 signature on a research finding.
    The signature is over the SHA-384 digest, so the auditor can verify it
    while holding only the digest - no decryption is required at any point.

    The public key is looked up by signed_by, not authored_by, so a finding
    that was shared to another researcher still verifies against the key of
    whoever actually signed it.
    """
    require_permission(session["role"], "verify_signature")

    findings = get_all_research_findings()
    if not findings:
        print("\n   No findings to verify."); return

    print("\n Research Findings ")
    for f in findings:
        print(f"  ID:{f['finding_id']:>4}  Author:{f['authored_by']:<18}  "
              f"Signed by:{f['signed_by']:<18}  {f['title'][:34]}")

    try:
        fid = int(input("\n  Enter Finding ID to verify signature: "))
    except ValueError:
        print("   Invalid ID!"); return

    finding = get_research_finding_by_id(fid)
    if finding is None:
        print("   Finding not found."); return

    signer_row = get_user(finding["signed_by"])
    if signer_row is None or not signer_row["ecdsa_public_key"]:
        print(f"   No ECDSA public key found for signer '{finding['signed_by']}'.")
        return

    try:
        ec_pub       = load_public_key(signer_row["ecdsa_public_key"].encode())
        signature    = b64decode(finding["ecdsa_signature"])
        digest_bytes = finding["sha384_digest"].encode('utf-8')
        valid        = ecdsa_verify(digest_bytes, signature, ec_pub)
    except Exception as e:
        print(f"   Verification error !: {e}")
        log_event(actor=session["username"], role=session["role"],
                  action="VERIFY_SIGNATURE", target=f"finding_id={fid}",
                  outcome="FAILURE", details=str(e))
        return

    outcome = "SUCCESS" if valid else "FAILURE"
    log_event(actor=session["username"], role=session["role"],
              action="VERIFY_SIGNATURE", target=f"finding_id={fid}",
              outcome=outcome,
              details=f"signer={finding['signed_by']}, valid={valid}")
    print(f"\n  Signature verification: {' :) VALID' if valid else '! INVALID'}")
    print(f"  Finding  : {finding['title']}")
    print(f"  Owned by : {finding['authored_by']}")
    print(f"  Signed by: {finding['signed_by']}")
    print(f"  Signed at: {finding['signed_at']}")

def a_check_digest_format(session: dict) -> None:
    """
    Auditor checks that every patient record carries a well-formed SHA-384
    digest (96 lowercase hex characters).

    This is a FORMAT check, not a cryptographic verification. Confirming that
    a digest matches its record would require decrypting the record, and the
    auditor holds no decryption key by design. Stated plainly here so the
    function is not mistaken for proof of record integrity.
    """
    require_permission(session["role"], "validate_integrity")

    records = get_all_patient_records()
    if not records:
        print("\n No patient records to check."); return

    print("\n  Patient Record Digest Format Check (not cryptographic verification):")
    valid_count = 0
    for r in records:
        digest_ok = (len(r["sha384_digest"]) == 96 and
                     all(c in '0123456789abcdef' for c in r["sha384_digest"]))
        status = " :) WELL-FORMED" if digest_ok else " :( MALFORMED DIGEST"
        if digest_ok: valid_count += 1
        print(f"  Record {r['record_id']:>4} | Patient {r['patient_id']:<14} | "
              f"Clinician {r['uploaded_by']:<16} | {status}")

    log_event(actor=session["username"], role=session["role"],
              action="CHECK_DIGEST_FORMAT", target="patient_records",
              outcome="SUCCESS",
              details=f"checked={len(records)}, well_formed={valid_count}")
    print(f"\n  {valid_count}/{len(records)} digests well-formed.")

def a_view_audit_log(session: dict) -> None:
    """Auditor views the tamper-evident audit log."""
    require_permission(session["role"], "view_audit_log")
    print("\n  Audit Log ")
    display_audit_log()
    log_event(actor=session["username"], role=session["role"],
              action="VIEW_AUDIT_LOG", outcome="SUCCESS")

def a_verify_log_integrity(session: dict) -> None:
    """
    Auditor verifies HMAC-SHA-256 tags on all audit log entries.
    Any modified entry fails verification. Note that deletion of a whole
    entry is NOT detected - see Known Limitations in the README.
    """
    require_permission(session["role"], "verify_log_integrity")
    print("\n  Verifying Audit Log Integrity ")
    report = verify_audit_log_integrity()
    print(f"  Total entries    : {report['total']}")
    print(f"  Passed           : {report['passed']}")
    print(f"  Failed (tampered): {report['failed']}")
    if report["tampered_ids"]:
        print(f" ! TAMPERED log IDs: {report['tampered_ids']}")
    else:
        print("  :) All entries intact - no modification detected.")
    log_event(actor=session["username"], role=session["role"],
              action="VERIFY_LOG_INTEGRITY", outcome="SUCCESS",
              details=f"total={report['total']}, failed={report['failed']}")

def a_view_all_records(session: dict) -> None:
    """Auditor has a read-only view of all records - metadata only, never ciphertext."""
    require_permission(session["role"], "view_all_records")
    records  = get_all_patient_records()
    findings = get_all_research_findings()
    print("\n All Patient Records (metadata) ")
    for r in records:
        print(f"  Record {r['record_id']:>4} | Patient {r['patient_id']:<14} | "
              f"Clinician {r['uploaded_by']:<16} | {r['record_type']}")
    print(f"\n   All Research Findings ")
    for f in findings:
        print(f"  Finding {f['finding_id']:>4} | Owner {f['authored_by']:<18} | "
              f"v{f['version']} | {f['title'][:40]}")
    log_event(actor=session["username"], role=session["role"],
              action="VIEW_ALL_RECORDS", outcome="SUCCESS",
              details=f"records={len(records)}, findings={len(findings)}")

def a_compliance_report(session: dict) -> None:
    """
    Print a GDPR compliance summary mapping system features to articles.
    This is static documentation, not a report generated from live data.
    """
    require_permission(session["role"], "generate_compliance_report")
    print("""
  GDPR Compliance Report (static mapping, not generated from live data) ::
  Article 5(1)(f)  Integrity & Confidentiality - AES-256-GCM + HMAC-SHA-256
  Article 9        Special Category Data       - RBAC limits access to clinical data
  Article 17       Right to Erasure            - Soft-delete; see README on Art.17(3)(b)
  Article 25       Privacy by Design           - Encryption at rest, least privilege RBAC
  Article 30       Records of Processing       - Tamper-evident audit log
  Article 32       Security of Processing      - AES-256-GCM, Argon2id, ECDSA P-384
  Article 5(2)     Accountability              - HMAC-protected audit log
    """)
    log_event(actor=session["username"], role=session["role"],
              action="COMPLIANCE_REPORT", outcome="SUCCESS")
