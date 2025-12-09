#!/usr/bin/env python3
"""
secure_peer.py

A single-file, improved and secure version of your encrypted messaging peer
(server/client) using RSA (2048+) and AES-GCM. Fixes syntax bugs, completes
missing helper functions, and strengthens the key-exchange by signing the
session blob so the receiver can verify the origin of the AES session key.

Usage:
  - First run: python secure_peer.py --generate-keys   # writes keys/ (my_private.pem, my_public.pem)
  - Run server: python secure_peer.py --mode server --host 0.0.0.0 --port 5000
  - Run client: python secure_peer.py --mode client --host <server-ip> --port 5000

Security notes (summary):
  - Uses OAEP (SHA256) for RSA encryption and PSS (SHA256) for signatures.
  - AES-GCM provides confidentiality + integrity for message payloads.
  - Session blob (AES key) is encrypted to the peer and signed by the sender's private key
    so the receiver verifies the signature using the sender's public key.
  - Fingerprint is shown for out-of-band verification to mitigate MITM.
  - Keys are stored with conservative filesystem permissions (600 for private key).

This file intentionally keeps the same newline-delimited JSON wire format
for ease of interop with your existing code while fixing logic and security bugs.
"""

import argparse
import base64
import json
import os
import secrets
import socket
import threading
import time
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_DIR = "keys"
KEY_PRIV_FILE = os.path.join(KEY_DIR, "my_private.pem")
KEY_PUB_FILE = os.path.join(KEY_DIR, "my_public.pem")


# -------------------- utility / key helpers --------------------

def ensure_key_dir() -> None:
    os.makedirs(KEY_DIR, exist_ok=True)


def generate_rsa_keypair(key_size: int = 3072):
    # 3072-bit for better security margin; you can use 2048 for compatibility
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def save_private_key(private_key, filename: str, password: Optional[bytes] = None) -> None:
    ensure_key_dir()
    enc = BestAvailableEncryption(password) if password else NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    with open(filename, "wb") as f:
        f.write(pem)
    try:
        os.chmod(filename, 0o600)
    except Exception:
        # not fatal on platforms that don't support chmod the same way
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
        data = f.read()
    return serialization.load_pem_private_key(data, password=password)


def load_public_key_from_pem_bytes(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)


def public_key_fingerprint(public_key) -> str:
    """Return a short hex fingerprint for manual verification (SHA-256 truncated)."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pem)
    fp = digest.finalize().hex()
    return fp[:32]


# -------------------- RSA helpers (OAEP, PSS) --------------------

def rsa_encrypt(public_key, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def sign_data(private_key, data: bytes) -> bytes:
    sig = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return sig


def verify_signature(public_key, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# -------------------- AES-GCM helpers --------------------

def aesgcm_encrypt(key: bytes, plaintext: bytes) -> dict:
    # AESGCM uses 12-byte nonces by convention
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def aesgcm_decrypt(key: bytes, nonce_b64: str, ciphertext_b64: str) -> bytes:
    nonce = base64.b64decode(nonce_b64.encode())
    ciphertext = base64.b64decode(ciphertext_b64.encode())
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


# -------------------- session blob helpers --------------------

def make_session_blob(aes_key: bytes) -> str:
    # The session blob is a simple JSON containing the key (B64) and a timestamp.
    blob = {"k": base64.b64encode(aes_key).decode(), "t": int(time.time())}
    return json.dumps(blob)


def parse_session_blob(blob_text: str) -> bytes:
    obj = json.loads(blob_text)
    k_b64 = obj.get("k")
    if not k_b64:
        raise ValueError("Missing key in session blob")
    key = base64.b64decode(k_b64.encode())
    if len(key) not in (16, 24, 32):
        raise ValueError("Invalid AES key size in blob")
    return key


# -------------------- wire helpers --------------------

def send_json(sock: socket.socket, obj: dict) -> None:
    data = (json.dumps(obj) + "\n").encode()
    sock.sendall(data)


class SocketLineReader:
    """Simple newline-delimited JSON reader with internal buffer."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""

    def recv_json_line(self) -> dict:
        while True:
            if b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                return json.loads(line.decode())
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("socket closed")
            self.buf += chunk


# -------------------- application logic --------------------

def ensure_keys() -> tuple:
    if not os.path.exists(KEY_PRIV_FILE) or not os.path.exists(KEY_PUB_FILE):
        priv, pub = generate_rsa_keypair()
        save_private_key(priv, KEY_PRIV_FILE)
        save_public_key(pub, KEY_PUB_FILE)
        print("[keys] Generated new RSA keypair and saved to keys/")
        return priv, pub
    priv = load_private_key(KEY_PRIV_FILE)
    with open(KEY_PUB_FILE, "rb") as f:
        pem = f.read()
    pub = load_public_key_from_pem_bytes(pem)
    print("[keys] Loaded existing RSA keypair")
    return priv, pub


def handle_receive(sock: socket.socket, reader: SocketLineReader, aes_key: Optional[bytes]) -> None:
    try:
        while True:
            obj = reader.recv_json_line()
            if obj.get("type") == "message":
                payload = obj["payload"]
                if aes_key is None:
                    print("\n[peer] Received message but no AES key established.\n> ", end="", flush=True)
                    continue
                try:
                    pt = aesgcm_decrypt(aes_key, payload["nonce"], payload["ciphertext"])
                    print(f"\n[peer] {pt.decode()}\n> ", end="", flush=True)
                except Exception as e:
                    print(f"\n[peer] Failed to decrypt message: {e}\n> ", end="", flush=True)
            else:
                print(f"\n[peer] Received control message: {obj}\n> ", end="", flush=True)
    except Exception as e:
        print(f"\n[recv] connection closed or error: {e}")


def run_peer(is_server: bool, host: str, port: int) -> None:
    priv, pub = ensure_keys()

    if is_server:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        print(f"[server] Listening on {host}:{port} — waiting for connection...")
        conn, addr = s.accept()
        print("[server] Connection from", addr)
        sock = conn
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        print("[client] Connected to", (host, port))

    reader = SocketLineReader(sock)

    # Exchange public keys
    with open(KEY_PUB_FILE, "rb") as f:
        my_pub_pem = f.read().decode()

    send_json(sock, {"type": "pubkey", "pem": my_pub_pem})

    # receive peer pubkey
    peer_pub = None
    while True:
        obj = reader.recv_json_line()
        if obj.get("type") == "pubkey":
            try:
                peer_pub = load_public_key_from_pem_bytes(obj["pem"].encode())
                break
            except Exception as e:
                print("[warn] Received invalid peer pubkey, ignoring:", e)
        else:
            print("[warn] Ignoring unexpected message during key exchange:", obj)

    if peer_pub is None:
        raise RuntimeError("Failed to obtain peer public key")

    print("[keys] Peer public key fingerprint:", public_key_fingerprint(peer_pub))
    print("[info] Verify this fingerprint out-of-band if you want to avoid MITM")

    # establish AES session key: client initiates
    aes_key: Optional[bytes] = None
    if not is_server:
        # client -> create AES key, sign it with client's private key, encrypt to server
        aes_key = secrets.token_bytes(32)  # AES-256
        blob = make_session_blob(aes_key).encode()
        sig = sign_data(priv, blob)
        enc = rsa_encrypt(peer_pub, blob)
        send_json(
            sock,
            {
                "type": "session",
                "enc": base64.b64encode(enc).decode(),
                "sig": base64.b64encode(sig).decode(),
            },
        )
        print("[session] Sent encrypted-and-signed session blob to peer")
    else:
        # server receives session blob, decrypts and verifies signature using client's pubkey
        obj = reader.recv_json_line()
        if obj.get("type") == "session":
            try:
                enc = base64.b64decode(obj["enc"].encode())
                sig = base64.b64decode(obj["sig"].encode())
                blob_text = rsa_decrypt(priv, enc).decode()
                # verify signature using peer_pub (the client's public key)
                if not verify_signature(peer_pub, sig, blob_text.encode()):
                    raise ValueError("Invalid signature on session blob — aborting")
                aes_key = parse_session_blob(blob_text)
                print("[session] Received, decrypted and verified session key")
            except Exception as e:
                print("[session] Failed to process session blob:", e)
                raise

    # start receiving thread
    recv_thread = threading.Thread(target=handle_receive, args=(sock, reader, aes_key), daemon=True)
    recv_thread.start()

    try:
        while True:
            msg = input("> ")
            if not msg:
                continue
            if aes_key is None:
                print("[error] AES key not established yet.")
                continue
            payload = aesgcm_encrypt(aes_key, msg.encode())
            send_json(sock, {"type": "message", "payload": payload})
    except KeyboardInterrupt:
        print("\n[peer] Exiting")
    finally:
        sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("server", "client"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--generate-keys", action="store_true", help="Generate RSA keypair and exit")
    args = parser.parse_args()

    if args.generate_keys:
        priv, pub = generate_rsa_keypair()
        save_private_key(priv, KEY_PRIV_FILE)
        save_public_key(pub, KEY_PUB_FILE)
        print("[keys] Generated and saved keypair to keys/")
        raise SystemExit(0)

    if args.mode is None:
        parser.print_help()
        raise SystemExit(1)

    run_peer(args.mode == "server", args.host, args.port)
