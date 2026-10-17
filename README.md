# MedSecureX

A cross-border clinical research collaboration platform demonstrating applied
cryptography and role-based access control, built for WM9PC-15 Applied
Cryptography (MSc Cybersecurity Management, University of Warwick).

Three roles share one encrypted datastore without being able to read each
other's data:

- **Clinicians** upload patient records, encrypted under keys only they can unwrap
- **Researchers** encrypt, sign and share research findings
- **Auditors** verify signatures and log integrity *without ever decrypting anything*

## Cryptographic design

| Primitive | Used for | Standard |
| --- | --- | --- |
| AES-256-GCM | Record and finding contents | NIST SP 800-38D |
| RSA-4096-OAEP | Wrapping each record's AES key | RFC 8017 |
| ECDSA P-384 | Signing research findings | FIPS 186-5 |
| Argon2id (64 MiB, t=3, p=4) | Password hashing | OWASP Password Storage |
| PBKDF2-HMAC-SHA-256 (600k) | Password-based key derivation | NIST SP 800-132 |
| HMAC-SHA-256 | Tamper-evident audit log | FIPS 198-1 |
| SHA-384 | Plaintext fingerprinting | FIPS 180-4 |

**Hybrid encryption.** Every record gets a freshly generated AES-256 key. That
key is wrapped under the owning user's RSA-4096 public key. Because each key
encrypts exactly one message, GCM nonce reuse is structurally impossible.

**Isolation by key distribution, not by flags.** A clinician's credential
unlocks only their own RSA private key, which unwraps only the AES keys wrapped
for them. A compromised clinician account cannot decrypt researcher data —
not because a permission check forbids it, but because the key does not exist.

**Signatures over digests.** Findings are signed over their SHA-384 digest
rather than their plaintext, so an auditor can verify authorship while holding
no decryption key at all. Separation of duties falls out of the cryptography.

**Authorisation inside the SQL.** Ownership checks live in the `WHERE` clause
(`WHERE record_id=? AND uploaded_by=?`), so there is no window between
authorising a write and performing it.

## Setup

Requires Python 3.9+.

```bash
pip install argon2-cffi cryptography

cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # paste into AUDIT_HMAC_SEED
# set a password for each demo account in .env

set -a && source .env && set +a      # macOS / Linux
python Main.py --setup
```

On Windows PowerShell, load `.env` with:

```powershell
Get-Content .env | Where-Object {$_ -match '='} | ForEach-Object {
    $k,$v = $_ -split '=',2; [Environment]::SetEnvironmentVariable($k,$v)
}
```

No credential appears anywhere in this repository. `Audit.py` refuses to import
if `AUDIT_HMAC_SEED` is unset, so the audit log can never be written with a
predictable key.

## Running

```bash
python Main.py --setup    # create the database and seed demo accounts
python Main.py --test     # 26 automated tests
python Main.py            # interactive application
```

## Known limitations

This is a prototype. These are deliberate, and documented rather than hidden:

| Limitation | What production would do |
| --- | --- |
| Private keys stored unencrypted in SQLite | Encrypt under a password-derived key, or hold them in an HSM |
| Audit log detects modification but not deletion of a whole entry | Hash-chain each entry to the previous tag, or use append-only storage |
| No session expiry or revocation | Short-lived signed tokens with a refresh flow |
| No lockout on repeated failed logins | Failed-attempt counter with backoff |
| Soft delete is not true erasure | Crypto-shredding: destroy the wrapped AES key so the ciphertext is unrecoverable |
| Auditors cannot cryptographically verify patient-record digests | Clinician-signed digests the auditor verifies without decrypting |
| One HMAC key, never rotated | Versioned keys, with the key id stored beside each tag |
| PBKDF2 is implemented and tested but not in the access path | Use the derived key to encrypt stored private keys |

The GDPR compliance report in the auditor menu is a static mapping of features
to articles, not a report generated from live data.

On Article 17: the soft delete preserves the audit trail, which is justified
under Article 17(3)(b). It is not erasure, and is listed above as a limitation
rather than claimed as compliance.

## Project structure

```
CoreCrypto.py   Seven primitives. Imports nothing else in the project.
Database.py     SQLite layer: four tables, parameterised queries.
Audit.py        HMAC key, log writer, integrity verifier.
Auth.py         Permission matrix, registration, login.
Role.py         The role operations, each permission-checked.
Main.py         Menus, dispatch, test suite, entry point.
```

Every import points downward — no module depends on one above it.
