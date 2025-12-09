import os
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# -----------------------------------------------------------------------------
# Utility: Base64 helpers
# -----------------------------------------------------------------------------
def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode())

# -----------------------------------------------------------------------------
# RSA key generation, loading, and saving
# -----------------------------------------------------------------------------
def generate_rsa_keypair(bits: int = 3072):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(path: str, private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, 'wb') as f:
        f.write(pem)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def save_public_key(path: str, public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, 'wb') as f:
        f.write(pem)


def load_private_key(path: str):
    with open(path, 'rb') as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=None)

def load_public_key(path: str):
    with open(path, 'rb') as f:
        data = f.read()
    return serialization.load_pem_public_key(data)

# -----------------------------------------------------------------------------
# RSA-OAEP encryption/decryption
# -----------------------------------------------------------------------------
def rsa_encrypt(public_key, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_decrypt(private_key, data: bytes) -> bytes:
    return private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

# -----------------------------------------------------------------------------
# RSA-PSS signatures
# -----------------------------------------------------------------------------
def rsa_sign(private_key, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

def rsa_verify(public_key, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False

# -----------------------------------------------------------------------------
# AES-GCM encryption/decryption
# -----------------------------------------------------------------------------
def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> dict:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, plaintext, aad)
    return {
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
    }

def aes_decrypt(key: bytes, nonce_b64: str, ciphertext_b64: str, aad: bytes = b"") -> bytes:
    aes = AESGCM(key)
    nonce = b64d(nonce_b64)
    ciphertext = b64d(ciphertext_b64)
    return aes.decrypt(nonce, ciphertext, aad)

# -----------------------------------------------------------------------------
# Key derivation (if needed for future extensions)
# -----------------------------------------------------------------------------
def derivation_key(key_material: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b"secure-peer-hkdf",
        backend=default_backend(),
    )
    return hkdf.derive(key_material)

# -----------------------------------------------------------------------------
# JSON wrappers
# -----------------------------------------------------------------------------
def json_dumps(obj: dict) -> str:
    return json.dumps(obj, separators=(",", ":"))

def json_loads(s: str) -> dict:
    return json.loads(s)
