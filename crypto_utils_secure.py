# crypto_utils.py (secure version)
import os
import base64
import json
import secrets
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_DIR = "keys"

# ---------------- Helpers ----------------
def ensure_key_dir() -> None:
    os.makedirs(KEY_DIR, exist_ok=True)

# ---------------- RSA Key Handling ----------------
def generate_rsa_keypair(key_size: int = 3072):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key, filename: str, password: Optional[bytes] = None) -> None:
    ensure_key_dir()
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password else serialization.NoEncryption()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    with open(filename, "wb") as f:
        f.write(pem)
    try:
        os.chmod(filename, 0o600)
    except Exception:
        pass


def save_public_key(public_key, filename: str) -> None:
    ensure_key_dir()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(filename, "wb") as f:
        f.write(pem)
    try:
        os.chmod(filename, 0o644)
    except Exception:
        pass


def load_private_key(filename: str, password: Optional[bytes] = None):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)


def load_public_key_from_pem_bytes(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)


def public_key_fingerprint(public_key) -> str:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pem)
    return digest.finalize().hex()[:32]

# ---------------- RSA Encrypt/Decrypt ----------------
def rsa_encrypt(public_key, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

# ---------------- AES-GCM Encrypt/Decrypt ----------------
def aesgcm_encrypt(key: bytes, plaintext: bytes) -> dict:
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }


def aesgcm_decrypt(key: bytes, nonce_b64: str, ct_b64: str) -> bytes:
    aes = AESGCM(key)
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ct_b64)
    return aes.decrypt(nonce, ct, None)

# ---------------- Session Blob ----------------
def make_session_blob(key: bytes) -> str:
    return json.dumps({"aes_key": base64.b64encode(key).decode()})


def parse_session_blob(blob: str) -> bytes:
    obj = json.loads(blob)
    return base64.b64decode(obj["aes_key"])
