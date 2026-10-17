"""
CoreCrypto.py : Cryptographic Primitives Module

Cryptographic stack:
  • AES-256-GCM          AEAD symmetric encryption            FIPS 197 / NIST SP 800-38D
  • RSA-4096-OAEP        Asymmetric key encapsulation         PKCS #1 v2.2 / RFC 8017
  • ECDSA P-384          Digital signatures                   FIPS 186-5
  • Argon2id             Password hashing                     OWASP Password Storage 2024
  • PBKDF2-HMAC-SHA-256  Password-based key derivation        NIST SP 800-132
  • HMAC-SHA-256         Tamper-evident MACs on audit logs    FIPS 198-1
  • SHA-384              Dataset fingerprinting               FIPS 180-4

This module imports nothing else from the project, so every other module can
depend on it without creating an import cycle.
"""

import os, hmac, hashlib, base64
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

#  Constants :
AES_KEY_BYTES   = 32       # 256-bit AES key (FIPS 197)
AES_NONCE_BYTES = 12       # 96-bit GCM nonce (NIST SP 800-38D recommendation)
RSA_KEY_BITS    = 4096     # Exceeds the 128-bit strength of RSA-3072 (NIST SP 800-57 Pt 1 Rev 5)
PBKDF2_ITERS    = 600_000  # OWASP 2023 minimum for PBKDF2-HMAC-SHA-256
PBKDF2_KEY_LEN  = 32       # 256-bit derived key

# Argon2id: 64 MiB memory, 3 time, 4 threads (OWASP Password Storage Cheat Sheet)
_ph = PasswordHasher(memory_cost=65536, time_cost=3, parallelism=4,
                     hash_len=32, salt_len=16)

#  Argon2id Password Hashing

def hash_password(password: str) -> str:
    """
    Hash password with Argon2id. Returns a self-describing PHC string of the
    form $argon2id$v=19$m=65536,t=3,p=4$<salt>$<digest> - the salt and all
    three cost parameters are embedded, so no separate salt column is needed.
    """
    return _ph.hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    """Verify password against Argon2id hash. Returns True on match."""
    try:
        return _ph.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False

#  AES-256-GCM Symmetric AEAD Encryption

def generate_aes_key() -> bytes:
    """Generate 256-bit random AES key via OS CSPRNG."""
    return os.urandom(AES_KEY_BYTES)

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt with AES-256-GCM. Output: nonce(12B) || ciphertext || tag(16B).
    GCM provides confidentiality AND integrity - any bit-flip in the ciphertext
    raises InvalidTag, eliminating the need for a separate MAC (SP 800-38D).

    Nonce reuse under the same key breaks GCM completely. This system avoids it
    structurally: callers generate a fresh AES key per record, so every key
    encrypts exactly one message.
    """
    aesgcm = AESGCM(key)
    nonce  = os.urandom(AES_NONCE_BYTES)
    return nonce + aesgcm.encrypt(nonce, plaintext, None)

def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM. Raises InvalidTag if authentication fails."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(ciphertext[:AES_NONCE_BYTES],
                          ciphertext[AES_NONCE_BYTES:], None)

#  RSA-4096-OAEP Hybrid Key Encapsulation :

def generate_rsa_keypair():
    """
    Generate RSA-4096 key pair.
    RSA-4096 exceeds the 128-bit security strength NIST assigns to RSA-3072
    (SP 800-57 Part 1 Rev 5, Table 2). OAEP padding prevents chosen-ciphertext
    attacks (RFC 8017). Used to wrap per-record AES keys - hybrid encryption
    combines symmetric performance with asymmetric key distribution.
    """
    priv = rsa.generate_private_key(public_exponent=65537,
                                    key_size=RSA_KEY_BITS,
                                    backend=default_backend())
    return priv, priv.public_key()

def rsa_encrypt_key(aes_key: bytes, public_key) -> bytes:
    """Encrypt AES key with RSA-OAEP/SHA-256 (RFC 8017 section 7.1)."""
    return public_key.encrypt(
        aes_key,
        asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=None))

def rsa_decrypt_key(encrypted_key: bytes, private_key) -> bytes:
    """Decrypt RSA-OAEP wrapped AES key."""
    return private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=None))

def serialise_public_key(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)

def serialise_private_key(priv, password: bytes = None) -> bytes:
    """
    Serialise a private key to PKCS#8 PEM. Passing a password encrypts it.
    KNOWN LIMITATION: callers in this prototype do not pass one, so private
    keys are stored unencrypted. See the Known Limitations section of README.
    """
    enc = (serialization.BestAvailableEncryption(password)
           if password else serialization.NoEncryption())
    return priv.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8, enc)

def load_public_key(pem: bytes):
    return serialization.load_pem_public_key(pem, backend=default_backend())

def load_private_key(pem: bytes, password: bytes = None):
    return serialization.load_pem_private_key(pem, password=password,
                                               backend=default_backend())

#  ECDSA P-384 Digital Signatures

def generate_ecdsa_keypair():
    """
    Generate ECDSA key pair on NIST P-384 curve.
    P-384 (~192-bit security) surpasses RSA-3072 at smaller key and signature
    sizes (FIPS 186-5). SHA-384 aligns the hash strength with the curve
    (FIPS 180-4). Faster verification than RSA - relevant to auditor workflows.
    """
    priv = ec.generate_private_key(ec.SECP384R1(), default_backend())
    return priv, priv.public_key()

def ecdsa_sign(data: bytes, private_key) -> bytes:
    """
    Sign data with ECDSA P-384 / SHA-384. Returns a DER-encoded signature.
    The library hashes `data` with SHA-384 internally before signing.
    """
    return private_key.sign(data, ec.ECDSA(hashes.SHA384()))

def ecdsa_verify(data: bytes, signature: bytes, public_key) -> bool:
    """Verify ECDSA P-384 signature. Returns True if valid, False otherwise."""
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA384()))
        return True
    except InvalidSignature:
        return False

#  PBKDF2-HMAC-SHA-256 Key Derivation

def derive_key_from_password(password: str, salt: bytes = None):
    """
    Derive a 256-bit key from a password using PBKDF2-HMAC-SHA-256
    (NIST SP 800-132), 600,000 iterations per OWASP 2023 guidance.
    Returns (key_bytes, salt_bytes); a fresh 32-byte salt is generated when
    none is supplied.

    NOTE: role-based data isolation in this system is provided by per-record
    AES keys wrapped under per-user RSA-4096 public keys, not by this
    function. It is implemented and tested, but not currently wired into the
    access path. See README.
    """
    if salt is None:
        salt = os.urandom(32)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=PBKDF2_KEY_LEN,
                     salt=salt, iterations=PBKDF2_ITERS,
                     backend=default_backend())
    return kdf.derive(password.encode('utf-8')), salt

#  HMAC-SHA-256 Tamper Detection

def hmac_sign(data: bytes, key: bytes) -> bytes:
    """
    Compute HMAC-SHA-256 (FIPS 198-1). Used to protect audit log entries.
    A keyed MAC prevents an attacker with database access from rewriting log
    entries without knowledge of the key.

    Argument order is (data, key) - the message first, then the key.
    """
    h = crypto_hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def hmac_verify(data: bytes, key: bytes, expected: bytes) -> bool:
    """
    Constant-time HMAC verification. Uses hmac.compare_digest so the
    comparison takes the same time regardless of where the first mismatching
    byte falls, preventing a timing side-channel that would let an attacker
    forge a tag one byte at a time.
    """
    return hmac.compare_digest(hmac_sign(data, key), expected)

#  SHA-384 Dataset Fingerprinting

def sha384_hash(data: bytes) -> str:
    """SHA-384 digest as 96 lowercase hex characters (FIPS 180-4)."""
    return hashlib.sha384(data).hexdigest()

#  Base64 helpers :

def b64encode(data: bytes) -> str:
    """URL-safe base64, so ciphertext survives storage in SQLite TEXT columns."""
    return base64.urlsafe_b64encode(data).decode('ascii')

def b64decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode('ascii'))
