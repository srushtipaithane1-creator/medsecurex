"""
MedSecureX - Cross-Border Clinical Research Collaboration Platform
WM9PC-15 Applied Cryptography

Demo accounts are created from environment variables - no credential appears
anywhere in this repository.

  1. Copy .env.example to .env and set a password for each account,
     plus a value for AUDIT_HMAC_SEED.
  2. Export those variables in your shell (see README).
  3. python Main.py --setup     creates the database and the demo accounts
     python Main.py --test      runs the automated test suite
     python Main.py             starts the interactive application

Usage sequence:
  1. Clinician  -> uploads encrypted patient records
  2. Researcher -> encrypts, signs, and shares research findings
  3. Auditor    -> verifies signatures, checks integrity proofs, reviews logs
"""

import os
import sys
from Database import initialise_database
from Auth import login, initial_accounts
from Role import (
    # Clinician
    c_upload_patient_record,
    c_retrieve_patient_record,
    c_update_patient_record,
    c_delete_patient_record,
    c_list_own_records,
    # Researcher
    r_encrypt_and_sign,
    r_decrypt_finding,
    r_cross_share,
    r_update_finding,
    r_delete_finding,
    r_list_findings,
    # Auditor
    a_verify_signature,
    a_check_digest_format,
    a_view_audit_log,
    a_verify_log_integrity,
    a_view_all_records,
    a_compliance_report,
)

BANNER = """
----------------------------------------------------------------------------
 MedSecureX: Cross-Border Clinical Research Collaboration Platform
 WM9PC-15 Applied Cryptography
 Cryptographic Stack: AES-256-GCM / RSA-4096-OAEP / ECDSA P-384
                      Argon2id / PBKDF2-SHA-256 / HMAC-SHA-256
----------------------------------------------------------------------------
"""

# Role Specific Menus :

CLINICIAN_MENU = """
   Clinician Menu:
   |  1. Upload patient record (AES-256-GCM encrypt)   |
   |  2. Retrieve & decrypt patient record             |
   |  3. Update patient record                         |
   |  4. Delete patient record (GDPR Art.17)           |
   |  5. List my records                               |
   |  0. Logout                                        |
"""

RESEARCHER_MENU = """
   Researcher Menu
   |  1. Encrypt & sign research finding (AES-GCM + ECDSA P-384)   |
   |  2. Decrypt research finding                                  |
   |  3. Cross-share finding with another researcher               |
   |  4. Update & re-sign finding                                  |
   |  5. Delete finding                                            |
   |  6. List all research findings                                |
   |  0. Logout                                                    |
"""

AUDITOR_MENU = """
   Auditor Menu
   |  1. Verify ECDSA signature on research finding            |
   |  2. Check patient record digest format (SHA-384)          |
   |  3. View audit log                                        |
   |  4. Verify audit log HMAC integrity                       |
   |  5. View all records (metadata, read-only)                |
   |  6. Generate GDPR compliance report                       |
   |  0. Logout                                                |
"""

#  Session loop Helpers :

def run_clinician_session(session: dict) -> None:
    while True:
        print(CLINICIAN_MENU)
        choice = input("  Choice: ").strip()
        if choice == "1":
            c_upload_patient_record(session)
        elif choice == "2":
            c_retrieve_patient_record(session)
        elif choice == "3":
            c_update_patient_record(session)
        elif choice == "4":
            c_delete_patient_record(session)
        elif choice == "5":
            c_list_own_records(session)
        elif choice == "0":
            print("\n  Logged out.")
            break
        else:
            print(" Invalid option.")

def run_researcher_session(session: dict) -> None:
    while True:
        print(RESEARCHER_MENU)
        choice = input("  Choice: ").strip()
        if choice == "1":
            r_encrypt_and_sign(session)
        elif choice == "2":
            r_decrypt_finding(session)
        elif choice == "3":
            r_cross_share(session)
        elif choice == "4":
            r_update_finding(session)
        elif choice == "5":
            r_delete_finding(session)
        elif choice == "6":
            r_list_findings(session)
        elif choice == "0":
            print("\n  Logged out.")
            break
        else:
            print("  Invalid option !")

def run_auditor_session(session: dict) -> None:
    while True:
        print(AUDITOR_MENU)
        choice = input("  Choice: ").strip()
        if choice == "1":
            a_verify_signature(session)
        elif choice == "2":
            a_check_digest_format(session)
        elif choice == "3":
            a_view_audit_log(session)
        elif choice == "4":
            a_verify_log_integrity(session)
        elif choice == "5":
            a_view_all_records(session)
        elif choice == "6":
            a_compliance_report(session)
        elif choice == "0":
            print("\n  Logged out.")
            break
        else:
            print(" Invalid option !")

#  Main application Loop

def main() -> None:
    print(BANNER)
    while True:
        print(":::Login:::")
        username = input("  Username (or 'quit' to exit): ").strip()
        if username.lower() in ("quit", "exit", "q"):
            print("  Exited.")
            break

        password = input("  Password: ").strip()
        session  = login(username, password)

        if session is None:
            print("\n  Authentication failed. Please check credentials.\n")
            continue

        role = session["role"]
        print(f"\n  ^^ Authenticated as {username} [{role.upper()}]")

        if role == "clinician":
            run_clinician_session(session)
        elif role == "researcher":
            run_researcher_session(session)
        elif role == "auditor":
            run_auditor_session(session)
        else:
            print(f" Unknown role: {role}. Contact administrator.")

        print()

#  Automated Test Suite:

def run_tests() -> None:
    """
    Automated tests for all major system functions.
    Run with: python Main.py --test
    """
    print("\n:::AUTOMATED TEST SUITE :::\n")
    passed = 0; failed = 0

    def test(name: str, fn):
        nonlocal passed, failed
        try:
            result = fn()
            if result is True or result is None:
                print(f"   PASS  {name}")
                passed += 1
            else:
                print(f"   FAIL  {name}  ->  {result}")
                failed += 1
        except Exception as e:
            print(f"   FAIL  {name}  ->  {e}")
            failed += 1

    #  Crypto Core Tests:
    from CoreCrypto import (
        hash_password, verify_password, generate_aes_key, aes_encrypt,
        aes_decrypt, generate_rsa_keypair, rsa_encrypt_key, rsa_decrypt_key,
        generate_ecdsa_keypair, ecdsa_sign, ecdsa_verify,
        derive_key_from_password, hmac_sign, hmac_verify, sha384_hash,
        b64encode, b64decode
    )

    test("Argon2id hash + verify",
         lambda: verify_password(hash_password("TestPass!"), "TestPass!"))
    test("Argon2id rejects wrong password",
         lambda: not verify_password(hash_password("TestPass!"), "WrongPass"))
    test("AES-256-GCM round-trip",
         lambda: aes_decrypt(aes_encrypt(b"secret data", k := generate_aes_key()), k) == b"secret data")
    test("AES-GCM detects tamper",
         lambda: _test_aes_tamper())
    test("AES-GCM uses a fresh nonce each call",
         lambda: _test_aes_nonce_unique())
    test("RSA-4096-OAEP key wrap/unwrap",
         lambda: _test_rsa())
    test("ECDSA P-384 sign + verify",
         lambda: _test_ecdsa())
    test("ECDSA rejects tampered data",
         lambda: _test_ecdsa_tamper())
    test("PBKDF2 deterministic with same salt",
         lambda: _test_pbkdf2())
    test("HMAC-SHA-256 sign + verify",
         lambda: _test_hmac())
    test("SHA-384 digest consistency",
         lambda: sha384_hash(b"hello") == sha384_hash(b"hello"))

    #  Auth Tests - credentials come from the environment, never from source:
    _clin_pw = os.environ.get("DEMO_CLINICIAN_A_PW")
    _res_pw  = os.environ.get("DEMO_RESEARCHER_A_PW")
    _aud_pw  = os.environ.get("DEMO_AUDITOR_PW")

    test("Login clinician_roxanne",
         lambda: login("clinician_roxanne", _clin_pw) is not None)
    test("Login researcher_nate",
         lambda: login("researcher_nate", _res_pw) is not None)
    test("Login auditor_aria",
         lambda: login("auditor_aria", _aud_pw) is not None)
    test("Reject bad password",
         lambda: login("clinician_roxanne", "wrongpassword") is None)
    test("Reject unknown user",
         lambda: login("no_such_user", "anything") is None)

    #  RBAC Permission Tests - the negatives matter most :
    from Auth import has_permission
    test("Clinician can upload",
         lambda: has_permission("clinician", "upload_patient_record"))
    test("Clinician cannot sign findings",
         lambda: not has_permission("clinician", "sign_research_finding"))
    test("Researcher cannot view audit log",
         lambda: not has_permission("researcher", "view_audit_log"))
    test("Auditor cannot upload records",
         lambda: not has_permission("auditor", "upload_patient_record"))
    test("Auditor can verify signature",
         lambda: has_permission("auditor", "verify_signature"))
    test("Unknown role has no permissions",
         lambda: not has_permission("administrator", "view_audit_log"))

    #  End-to-end signature test - create, update, verify :
    test("Signature verifies after create AND after update",
         lambda: _test_sign_update_verify())

    #  Cross-share keeps the signature verifiable :
    test("Cross-shared finding still verifies against original signer",
         lambda: _test_cross_share_verify())

    #  Audit log Integrity Test :
    from Audit import verify_audit_log_integrity
    test("Audit log HMAC integrity",
         lambda: verify_audit_log_integrity()["failed"] == 0)
    test("Audit log detects a modified entry",
         lambda: _test_audit_tamper())

    print(f"\nResults: {passed} passed, {failed} failed\n")
    return failed

def _test_aes_tamper():
    from CoreCrypto import generate_aes_key, aes_encrypt, aes_decrypt
    from cryptography.exceptions import InvalidTag
    key = generate_aes_key()
    ct  = bytearray(aes_encrypt(b"hello", key))
    ct[-1] ^= 0xFF   # Flip last byte of the authentication tag
    try:
        aes_decrypt(bytes(ct), key)
        return False
    except InvalidTag:
        return True

def _test_aes_nonce_unique():
    from CoreCrypto import generate_aes_key, aes_encrypt, AES_NONCE_BYTES
    key = generate_aes_key()
    a = aes_encrypt(b"same plaintext", key)[:AES_NONCE_BYTES]
    b = aes_encrypt(b"same plaintext", key)[:AES_NONCE_BYTES]
    return a != b

def _test_rsa():
    from CoreCrypto import (generate_rsa_keypair, rsa_encrypt_key,
                            rsa_decrypt_key, generate_aes_key)
    priv, pub = generate_rsa_keypair()
    k = generate_aes_key()
    return rsa_decrypt_key(rsa_encrypt_key(k, pub), priv) == k

def _test_ecdsa():
    from CoreCrypto import generate_ecdsa_keypair, ecdsa_sign, ecdsa_verify
    priv, pub = generate_ecdsa_keypair()
    data = b"research finding content"
    sig  = ecdsa_sign(data, priv)
    return ecdsa_verify(data, sig, pub)

def _test_ecdsa_tamper():
    from CoreCrypto import generate_ecdsa_keypair, ecdsa_sign, ecdsa_verify
    priv, pub = generate_ecdsa_keypair()
    sig = ecdsa_sign(b"original", priv)
    return not ecdsa_verify(b"tampered", sig, pub)

def _test_pbkdf2():
    from CoreCrypto import derive_key_from_password
    k1, salt = derive_key_from_password("password123")
    k2, _    = derive_key_from_password("password123", salt)
    return k1 == k2

def _test_hmac():
    from CoreCrypto import hmac_sign, hmac_verify
    key  = b"test-hmac-key-32-bytes!!!!!!!!!!!"
    data = b"audit log entry"
    mac  = hmac_sign(data, key)
    return hmac_verify(data, key, mac) and not hmac_verify(b"tampered", key, mac)

def _test_sign_update_verify():
    """
    Walks the real create -> update -> verify path through the database.
    This is the sequence that the old code got wrong: it signed the digest on
    create but the raw plaintext on update, so an updated finding failed
    verification.
    """
    from CoreCrypto import (generate_aes_key, aes_encrypt, rsa_encrypt_key,
                            ecdsa_sign, ecdsa_verify, sha384_hash,
                            b64encode, b64decode, load_public_key)
    from Database import (insert_research_finding, update_research_finding,
                          get_research_finding_by_id, get_user,
                          soft_delete_research_finding)

    sess = login("researcher_nate", os.environ.get("DEMO_RESEARCHER_A_PW"))
    if sess is None:
        return "could not log in as researcher_nate"

    def store(text: bytes):
        key = generate_aes_key()
        return (b64encode(aes_encrypt(text, key)),
                b64encode(rsa_encrypt_key(key, sess["rsa_public"])),
                sha384_hash(text))

    def verify(fid):
        f   = get_research_finding_by_id(fid)
        row = get_user(f["signed_by"])
        pub = load_public_key(row["ecdsa_public_key"].encode())
        return ecdsa_verify(f["sha384_digest"].encode('utf-8'),
                            b64decode(f["ecdsa_signature"]), pub)

    # create
    data, wrapped, digest = store(b"original finding v1")
    fid = insert_research_finding(
        title="TEST signature lifecycle", authored_by="researcher_nate",
        encrypted_data=data, encrypted_aes_key=wrapped,
        ecdsa_signature=b64encode(ecdsa_sign(digest.encode(), sess["ecdsa_private"])),
        sha384_digest=digest, signed_by="researcher_nate")
    if not verify(fid):
        soft_delete_research_finding(fid, "researcher_nate")
        return "signature failed immediately after create"

    # update
    data, wrapped, digest = store(b"revised finding v2")
    update_research_finding(
        finding_id=fid, researcher="researcher_nate",
        encrypted_data=data, encrypted_aes_key=wrapped,
        ecdsa_signature=b64encode(ecdsa_sign(digest.encode(), sess["ecdsa_private"])),
        sha384_digest=digest)
    ok = verify(fid)
    soft_delete_research_finding(fid, "researcher_nate")
    return True if ok else "signature failed after update"

def _test_cross_share_verify():
    """
    A shared copy is owned by the recipient but signed by the original author.
    Verification must look up signed_by, not authored_by.
    """
    from CoreCrypto import (generate_aes_key, aes_encrypt, rsa_encrypt_key,
                            rsa_decrypt_key, ecdsa_sign, ecdsa_verify,
                            sha384_hash, b64encode, b64decode,
                            load_public_key)
    from Database import (insert_research_finding, get_research_finding_by_id,
                          get_user, soft_delete_research_finding)

    nate = login("researcher_nate", os.environ.get("DEMO_RESEARCHER_A_PW"))
    if nate is None:
        return "could not log in as researcher_nate"

    key    = generate_aes_key()
    text   = b"shared finding body"
    digest = sha384_hash(text)
    fid = insert_research_finding(
        title="TEST cross share", authored_by="researcher_nate",
        encrypted_data=b64encode(aes_encrypt(text, key)),
        encrypted_aes_key=b64encode(rsa_encrypt_key(key, nate["rsa_public"])),
        ecdsa_signature=b64encode(ecdsa_sign(digest.encode(), nate["ecdsa_private"])),
        sha384_digest=digest, signed_by="researcher_nate")

    src     = get_research_finding_by_id(fid)
    zeeva   = get_user("researcher_zeeva")
    aes_key = rsa_decrypt_key(b64decode(src["encrypted_aes_key"]), nate["rsa_private"])
    new_fid = insert_research_finding(
        title="[SHARED from researcher_nate] TEST cross share",
        authored_by="researcher_zeeva",
        encrypted_data=src["encrypted_data"],
        encrypted_aes_key=b64encode(
            rsa_encrypt_key(aes_key, load_public_key(zeeva["rsa_public_key"].encode()))),
        ecdsa_signature=src["ecdsa_signature"],
        sha384_digest=src["sha384_digest"],
        signed_by=src["signed_by"])

    shared = get_research_finding_by_id(new_fid)
    signer = get_user(shared["signed_by"])
    ok = ecdsa_verify(shared["sha384_digest"].encode('utf-8'),
                      b64decode(shared["ecdsa_signature"]),
                      load_public_key(signer["ecdsa_public_key"].encode()))

    soft_delete_research_finding(fid, "researcher_nate")
    soft_delete_research_finding(new_fid, "researcher_zeeva")
    return True if ok else "shared copy failed signature verification"

def _test_audit_tamper():
    """
    Write an entry, edit it behind the application's back with raw SQL, and
    confirm the verifier flags exactly that entry.
    """
    from Audit import log_event, verify_audit_log_integrity
    from Database import get_connection

    lid = log_event(actor="test_harness", role="auditor",
                    action="TAMPER_PROBE", outcome="SUCCESS",
                    details="about to be modified")

    conn = get_connection()
    conn.execute("UPDATE audit_log SET outcome='FAILURE' WHERE log_id=?", (lid,))
    conn.commit(); conn.close()

    report = verify_audit_log_integrity()
    detected = lid in report["tampered_ids"]

    # Put it back so the suite can be re-run and later checks stay clean
    conn = get_connection()
    conn.execute("UPDATE audit_log SET outcome='SUCCESS' WHERE log_id=?", (lid,))
    conn.commit(); conn.close()

    return True if detected else "verifier did not flag the modified entry"

#  Entry Point:

if __name__ == "__main__":
    initialise_database()

    if "--setup" in sys.argv:
        print("Setting up database and seeding accounts")
        initial_accounts()
        print("Setup complete. Run: python Main.py")

    elif "--test" in sys.argv:
        initial_accounts()            # Ensure accounts exist
        sys.exit(1 if run_tests() else 0)

    else:
        initial_accounts()            # Silently skips accounts that already exist
        main()
