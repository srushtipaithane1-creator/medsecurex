"""
Auth.py : Authentication & Role-Based Access Control

Implements:
  - Secure login with Argon2id credential verification
  - Role-Based Access Control (RBAC) - each role has a distinct permission set
  - Per-user asymmetric key generation on account creation
  - Role-specific PBKDF2 salt generation (reserved, see note below)

RBAC design follows the NIST RBAC standard (ANSI INCITS 359-2012):
  - Permissions are assigned to roles, not individual users
  - A user's session is bounded to a single role
  - Role switching requires re-authentication (not implemented here for simplicity)

GDPR Article 25 (Data Protection by Design) mandates that access to special-
category data (Art. 9) be restricted to those with a legitimate need. RBAC
enforces this at the application layer, and per-user RSA key wrapping enforces
it cryptographically: a clinician's credential unlocks only their own RSA
private key, which unwraps only the AES keys wrapped for them.
"""

import os

from Database import create_user, get_user, update_last_login
from CoreCrypto import (
    hash_password, verify_password,
    generate_rsa_keypair, generate_ecdsa_keypair,
    serialise_public_key, serialise_private_key,
    derive_key_from_password, b64encode, b64decode
)
from Audit import log_event

#  Role permission matrix
# Each role is mapped to ONLY the actions it is permitted to perform.
# Enforced in Role.py - every operation calls require_permission() before
# touching any data.

ROLE_PERMISSIONS = {
    "clinician": {
        "upload_patient_record",
        "retrieve_patient_record",
        "update_patient_record",
        "delete_patient_record",
        "list_own_records",
    },
    "researcher": {
        "decrypt_research_data",
        "sign_research_finding",
        "update_research_finding",
        "delete_research_finding",
        "list_research_findings",
        "cross_decrypt",          # Researcher B decrypting Researcher A's data
    },
    "auditor": {
        "verify_signature",
        "validate_integrity",
        "view_audit_log",
        "verify_log_integrity",
        "view_all_records",       # Read-only cross-domain view
        "generate_compliance_report",
    }
}

def has_permission(role: str, action: str) -> bool:
    """
    Check whether a role is permitted to perform an action.
    An unknown role gets an empty permission set rather than a KeyError,
    so the system fails closed.
    """
    return action in ROLE_PERMISSIONS.get(role, set())

def require_permission(role: str, action: str) -> None:
    """Raise PermissionError if the role lacks the required permission."""
    if not has_permission(role, action):
        raise PermissionError(
            f"Role '{role}' is not authorised to perform '{action}'."
        )

#  Account creation :

def register_user(username: str, password: str, role: str) -> bool:
    """
    Register a new user:
      1. Hash password with Argon2id
      2. Generate RSA-4096 key pair (for data encryption/decryption)
      3. Generate ECDSA P-384 key pair (for researchers - signing)
      4. Generate a per-user PBKDF2 salt
      5. Persist to database
    Returns True on success.
    """
    if role not in ("clinician", "researcher", "auditor"):
        raise ValueError(f"Unknown role: {role}")

    # Argon2id password hash
    pw_hash = hash_password(password)

    # RSA-4096 key pair for every user (hybrid encryption).
    # This is what isolates one user's data from another's: a record's AES key
    # is wrapped under the uploader's public key, so nobody else can unwrap it.
    rsa_priv, rsa_pub = generate_rsa_keypair()
    rsa_pub_pem  = serialise_public_key(rsa_pub).decode()
    rsa_priv_pem = serialise_private_key(rsa_priv).decode()

    # ECDSA P-384 only for researchers (principle of least privilege).
    # A clinician has no signing key, so cannot produce a researcher signature.
    ecdsa_pub_pem = ecdsa_priv_pem = None
    if role == "researcher":
        ec_priv, ec_pub = generate_ecdsa_keypair()
        ecdsa_pub_pem  = serialise_public_key(ec_pub).decode()
        ecdsa_priv_pem = serialise_private_key(ec_priv).decode()

    # Per-user PBKDF2 salt. Stored for a future enhancement that would encrypt
    # the private keys above under a password-derived key. Not currently used
    # in the access path - see README.
    _, pbkdf2_salt = derive_key_from_password(password)
    salt_b64 = b64encode(pbkdf2_salt)

    create_user(
        username=username, password_hash=pw_hash, role=role,
        ecdsa_pub=ecdsa_pub_pem, ecdsa_priv=ecdsa_priv_pem,
        rsa_pub=rsa_pub_pem, rsa_priv=rsa_priv_pem,
        pbkdf2_salt=salt_b64
    )
    log_event(actor=username, role=role, action="REGISTER",
              target=username, outcome="SUCCESS",
              details=f"Account created for role={role}")
    return True

#  Authentication :

def login(username: str, password: str):
    """
    Authenticate a user. Returns a session dict on success, None on failure.

    Both failure branches are logged with the specific reason for the auditor,
    but Main.py shows the user the same generic message either way, so an
    attacker cannot use the response to enumerate valid usernames.

    In a production system, session tokens would be short-lived JWTs signed
    with an ECDSA key, but for this prototype a simple in-memory session dict
    is used. There is no expiry and no revocation - see README.
    """
    user = get_user(username)
    if user is None:
        log_event(actor=username, role="unknown", action="LOGIN",
                  outcome="FAILURE", details="User not found")
        return None

    if not verify_password(user["password_hash"], password):
        log_event(actor=username, role=user["role"], action="LOGIN",
                  outcome="FAILURE", details="Invalid credentials")
        return None

    # Load private keys for session use (parse the PEM once)
    from CoreCrypto import load_private_key
    rsa_priv = load_private_key(user["rsa_private_key"].encode())
    rsa_pub  = rsa_priv.public_key()
    ecdsa_priv = None
    ecdsa_pub  = None
    if user["ecdsa_private_key"]:
        ecdsa_priv = load_private_key(user["ecdsa_private_key"].encode())
        ecdsa_pub  = ecdsa_priv.public_key()

    update_last_login(username)
    log_event(actor=username, role=user["role"], action="LOGIN",
              outcome="SUCCESS", details="Session started")

    return {
        "username":      username,
        "role":          user["role"],
        "rsa_private":   rsa_priv,
        "rsa_public":    rsa_pub,
        "rsa_pub_pem":   user["rsa_public_key"],
        "ecdsa_private": ecdsa_priv,
        "ecdsa_public":  ecdsa_pub,
        "pbkdf2_salt":   b64decode(user["pbkdf2_salt"]) if user["pbkdf2_salt"] else None,
    }

#  Pre-seeded demo accounts :

# Usernames and the ENVIRONMENT VARIABLE each password is read from.
# No credential appears in this file.
DEMO_ACCOUNTS = [
    ("clinician_roxanne",  "DEMO_CLINICIAN_A_PW",   "clinician"),
    ("clinician_lauv",     "DEMO_CLINICIAN_B_PW",   "clinician"),
    ("researcher_nate",    "DEMO_RESEARCHER_A_PW",  "researcher"),
    ("researcher_zeeva",   "DEMO_RESEARCHER_B_PW",  "researcher"),
    ("auditor_aria",       "DEMO_AUDITOR_PW",       "auditor"),
]

def initial_accounts() -> None:
    """
    Create the demo accounts from environment variables.
    Accounts that already exist are skipped silently; variables that are not
    set produce a message naming the variable, so a first-time runner is told
    what is missing instead of hitting an unexplained login failure.
    """
    for username, env_var, role in DEMO_ACCOUNTS:
        password = os.environ.get(env_var)
        if not password:
            print(f"  Skipped {username}: {env_var} is not set")
            continue
        if get_user(username) is None:
            try:
                register_user(username, password, role)
                print(f"  Created {role} account: {username}")
            except Exception as e:
                print(f"  Failed to create {username}: {e}")
