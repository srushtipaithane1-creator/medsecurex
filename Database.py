"""
Database.py : SQLite Persistence Layer

Stores all system entities in a local SQLite database (justified as a
prototype-appropriate storage back-end - OWASP notes that file/DB storage
is acceptable when encryption and access controls are applied at the application
layer, which this system does via AES-256-GCM and RBAC).

Tables:
  users             - credentials, roles, ECDSA/RSA public keys, derived-key salts
  patient_records   - AES-GCM encrypted patient datasets (clinician-uploaded)
  research_findings - encrypted + signed researcher outputs
  audit_log         - HMAC-protected tamper-evident event log

Every statement uses parameterised queries. Ownership checks live inside the
WHERE clause rather than in Python, so there is no time-of-check-to-time-of-use
window between authorising a write and performing it.
"""

import sqlite3
import os
from datetime import datetime, timezone

DB_PATH = "clinical_platform.db"

def get_connection() -> sqlite3.Connection:
    """Return a DB connection with foreign keys enforced and dict-style rows."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row   # Dict-style access to rows
    return conn

def initialise_database() -> None:
    """Create all tables if they do not already exist."""
    conn = get_connection()
    cur  = conn.cursor()

    #  Users table ::
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id           INTEGER  PRIMARY KEY AUTOINCREMENT,
            username          TEXT     NOT NULL UNIQUE,
            password_hash     TEXT     NOT NULL,           -- Argon2id PHC string
            role              TEXT     NOT NULL CHECK(role IN ('clinician','researcher','auditor')),
            ecdsa_public_key  TEXT,                  -- PEM: researcher signing key
            ecdsa_private_key TEXT,                  -- PEM: researcher signing key (unencrypted - see README)
            rsa_public_key    TEXT,                  -- PEM: per-user RSA public key
            rsa_private_key   TEXT,                  -- PEM: per-user RSA private key (unencrypted - see README)
            pbkdf2_salt       TEXT,                  -- base64 salt, reserved for future key derivation
            created_at        TEXT     NOT NULL DEFAULT (datetime('now')),
            last_login        TEXT,
            is_active         INTEGER  NOT NULL DEFAULT 1  -- soft-delete / account suspension
        )
    """)

    #  Patient records (Clinician domain) :
    cur.execute("""
        CREATE TABLE IF NOT EXISTS patient_records (
            record_id         INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id        TEXT    NOT NULL,         -- de-identified patient token
            uploaded_by       TEXT    NOT NULL,         -- username of clinician
            encrypted_data    TEXT    NOT NULL,         -- base64 AES-256-GCM ciphertext
            encrypted_aes_key TEXT    NOT NULL,         -- base64 RSA-OAEP wrapped AES key
            sha384_digest     TEXT    NOT NULL,         -- SHA-384 of plaintext for integrity
            record_type       TEXT    NOT NULL,         -- e.g. "blood_results", "imaging"
            description       TEXT,
            created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at        TEXT,
            is_deleted        INTEGER NOT NULL DEFAULT 0  -- soft-delete (GDPR Art.17)
        )
    """)

    #  Research findings (Researcher domain) ::
    cur.execute("""
        CREATE TABLE IF NOT EXISTS research_findings (
            finding_id        INTEGER PRIMARY KEY AUTOINCREMENT,
            title             TEXT    NOT NULL,
            authored_by       TEXT    NOT NULL,         -- researcher who owns this copy
            signed_by         TEXT    NOT NULL,         -- researcher whose key made the signature
            encrypted_data    TEXT    NOT NULL,         -- base64 AES-256-GCM ciphertext
            encrypted_aes_key TEXT    NOT NULL,         -- base64 RSA-OAEP wrapped AES key
            ecdsa_signature   TEXT    NOT NULL,         -- base64 ECDSA P-384 signature
            sha384_digest     TEXT    NOT NULL,         -- SHA-384 of plaintext
            signed_at         TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at        TEXT,
            version           INTEGER NOT NULL DEFAULT 1,
            is_deleted        INTEGER NOT NULL DEFAULT 0
        )
    """)

    # Tamper-evident audit log (Auditor domain) :
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            log_id     INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT    NOT NULL DEFAULT (datetime('now')),
            actor      TEXT    NOT NULL,    -- username performing action
            role       TEXT    NOT NULL,    -- actor's role at time of event
            action     TEXT    NOT NULL,    -- e.g. ENCRYPT, SIGN, VERIFY
            target     TEXT,               -- record/finding ID or description
            outcome    TEXT    NOT NULL,    -- SUCCESS / FAILURE
            details    TEXT,               -- additional context
            hmac_tag   TEXT    NOT NULL    -- base64 HMAC-SHA-256 of all other fields
        )
    """)

    conn.commit()
    conn.close()

#  User operations

def create_user(username, password_hash, role,
                ecdsa_pub=None, ecdsa_priv=None,
                rsa_pub=None, rsa_priv=None,
                pbkdf2_salt=None) -> int:
    """Insert a new user. Returns new user_id."""
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO users (username, password_hash, role,
                           ecdsa_public_key, ecdsa_private_key,
                           rsa_public_key, rsa_private_key, pbkdf2_salt)
        VALUES (?,?,?,?,?,?,?,?)
    """, (username, password_hash, role,
          ecdsa_pub, ecdsa_priv, rsa_pub, rsa_priv, pbkdf2_salt))
    uid = cur.lastrowid
    conn.commit(); conn.close()
    return uid

def get_user(username):
    """Fetch an active user row by username. Returns sqlite3.Row or None."""
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=? AND is_active=1", (username,))
    row = cur.fetchone()
    conn.close()
    return row

def update_last_login(username: str) -> None:
    conn = get_connection()
    conn.execute("UPDATE users SET last_login=datetime('now') WHERE username=?", (username,))
    conn.commit(); conn.close()

#  Patient record operations :

def insert_patient_record(patient_id, uploaded_by, encrypted_data,
                          encrypted_aes_key, sha384_digest,
                          record_type, description="") -> int:
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO patient_records
          (patient_id, uploaded_by, encrypted_data, encrypted_aes_key,
           sha384_digest, record_type, description)
        VALUES (?,?,?,?,?,?,?)
    """, (patient_id, uploaded_by, encrypted_data, encrypted_aes_key,
          sha384_digest, record_type, description))
    rid = cur.lastrowid
    conn.commit(); conn.close()
    return rid

def get_patient_records_by_clinician(username: str) -> list:
    """Clinician can only see their own records (least privilege)."""
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        SELECT * FROM patient_records
        WHERE uploaded_by=? AND is_deleted=0
        ORDER BY created_at DESC
    """, (username,))
    rows = cur.fetchall()
    conn.close()
    return rows

def get_all_patient_records() -> list:
    """Auditors can view all non-deleted records (read-only, metadata)."""
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM patient_records WHERE is_deleted=0 ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return rows

def update_patient_record(record_id: int, clinician: str,
                           encrypted_data: str, encrypted_aes_key: str,
                           sha384_digest: str) -> bool:
    """
    Update an existing patient record. Ownership is enforced in the WHERE
    clause: a non-owner matches zero rows and the function returns False.
    """
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        UPDATE patient_records
        SET encrypted_data=?, encrypted_aes_key=?, sha384_digest=?,
            updated_at=datetime('now')
        WHERE record_id=? AND uploaded_by=? AND is_deleted=0
    """, (encrypted_data, encrypted_aes_key, sha384_digest, record_id, clinician))
    updated = cur.rowcount > 0
    conn.commit(); conn.close()
    return updated

def soft_delete_patient_record(record_id: int, clinician: str) -> bool:
    """Soft-delete (GDPR Art. 17 right to erasure - audit trail preserved)."""
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        UPDATE patient_records SET is_deleted=1, updated_at=datetime('now')
        WHERE record_id=? AND uploaded_by=? AND is_deleted=0
    """, (record_id, clinician))
    deleted = cur.rowcount > 0
    conn.commit(); conn.close()
    return deleted

def get_patient_record_by_id(record_id: int):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM patient_records WHERE record_id=? AND is_deleted=0",
                (record_id,))
    row = cur.fetchone()
    conn.close()
    return row

#  Research finding operations :

def insert_research_finding(title, authored_by, encrypted_data,
                             encrypted_aes_key, ecdsa_signature,
                             sha384_digest, signed_by=None) -> int:
    """
    Insert a research finding. `signed_by` names the researcher whose ECDSA
    key produced the signature; it defaults to the author, and differs only
    for a cross-shared copy, where ownership moves but authorship of the
    signature does not.
    """
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO research_findings
          (title, authored_by, signed_by, encrypted_data, encrypted_aes_key,
           ecdsa_signature, sha384_digest)
        VALUES (?,?,?,?,?,?,?)
    """, (title, authored_by, signed_by or authored_by, encrypted_data,
          encrypted_aes_key, ecdsa_signature, sha384_digest))
    fid = cur.lastrowid
    conn.commit(); conn.close()
    return fid

def get_all_research_findings() -> list:
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM research_findings WHERE is_deleted=0 ORDER BY signed_at DESC")
    rows = cur.fetchall()
    conn.close()
    return rows

def get_research_finding_by_id(finding_id: int):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM research_findings WHERE finding_id=? AND is_deleted=0",
                (finding_id,))
    row = cur.fetchone()
    conn.close()
    return row

def update_research_finding(finding_id: int, researcher: str,
                             encrypted_data: str, encrypted_aes_key: str,
                             ecdsa_signature: str, sha384_digest: str) -> bool:
    """
    Update and re-sign a finding. The updating researcher becomes signed_by,
    because the new signature was made with their key.
    """
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        UPDATE research_findings
        SET encrypted_data=?, encrypted_aes_key=?, ecdsa_signature=?,
            sha384_digest=?, signed_by=?, updated_at=datetime('now'),
            version=version+1
        WHERE finding_id=? AND authored_by=? AND is_deleted=0
    """, (encrypted_data, encrypted_aes_key, ecdsa_signature,
          sha384_digest, researcher, finding_id, researcher))
    updated = cur.rowcount > 0
    conn.commit(); conn.close()
    return updated

def soft_delete_research_finding(finding_id: int, researcher: str) -> bool:
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        UPDATE research_findings SET is_deleted=1, updated_at=datetime('now')
        WHERE finding_id=? AND authored_by=? AND is_deleted=0
    """, (finding_id, researcher))
    deleted = cur.rowcount > 0
    conn.commit(); conn.close()
    return deleted

#  Audit log operations :

def append_audit_log(actor: str, role: str, action: str,
                     target: str, outcome: str, details: str,
                     hmac_key: bytes) -> int:
    """
    Insert a tamper-evident log entry. The HMAC is computed over all fields
    before insertion, so any post-hoc SQL modification invalidates the tag.

    Audit.verify_audit_log_integrity() rebuilds this exact payload string, so
    if a field is ever added here it must be added there in the same commit.
    """
    from CoreCrypto import hmac_sign, b64encode
    timestamp = datetime.now(timezone.utc).isoformat()
    payload   = f"{timestamp}|{actor}|{role}|{action}|{target}|{outcome}|{details}"
    tag       = b64encode(hmac_sign(payload.encode('utf-8'), hmac_key))

    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO audit_log (timestamp, actor, role, action, target, outcome, details, hmac_tag)
        VALUES (?,?,?,?,?,?,?,?)
    """, (timestamp, actor, role, action, target or '', outcome, details or '', tag))
    lid = cur.lastrowid
    conn.commit(); conn.close()
    return lid

def get_audit_log() -> list:
    """Return all audit log entries ordered chronologically."""
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM audit_log ORDER BY timestamp ASC")
    rows = cur.fetchall()
    conn.close()
    return rows
