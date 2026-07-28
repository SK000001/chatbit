"""Low-level cryptographic primitives.

Everything in this module is a deliberately boring wrapper around
``cryptography``. That is the point: the interesting parts of chatbit (the
Noise XX handshake and the Double Ratchet) are standard designs assembled out
of standard parts, so there is nothing novel here for an attacker to attack.

Primitive suite, fixed for protocol v1:

    DH      X25519
    Sign    Ed25519
    AEAD    ChaCha20-Poly1305
    Hash    SHA-256
    KDF     HKDF-SHA-256
"""

from __future__ import annotations

import hmac as _hmac
import os
from hashlib import sha256

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization

__all__ = [
    "HASHLEN",
    "DHLEN",
    "KEYLEN",
    "TAGLEN",
    "AEADError",
    "hash_sha256",
    "hmac_sha256",
    "hkdf",
    "noise_hkdf",
    "aead_encrypt",
    "aead_decrypt",
    "generate_x25519",
    "x25519_public_bytes",
    "x25519_private_bytes",
    "load_x25519_public",
    "load_x25519_private",
    "dh",
    "generate_ed25519",
    "ed25519_public_bytes",
    "ed25519_private_bytes",
    "load_ed25519_public",
    "load_ed25519_private",
    "sign",
    "verify",
    "scrypt_derive",
    "constant_time_eq",
    "random_bytes",
]

HASHLEN = 32
DHLEN = 32
KEYLEN = 32
TAGLEN = 16

# All-zero X25519 output means the peer sent a low-order point and the shared
# secret is degenerate. RFC 7748 says implementations *may* reject this; for a
# key-agreement protocol carrying authentication we always do.
_ZERO_DH = b"\x00" * DHLEN


class AEADError(Exception):
    """AEAD decryption failed: wrong key, wrong nonce, or forged ciphertext."""


# --------------------------------------------------------------------------
# hashing / KDF
# --------------------------------------------------------------------------


def hash_sha256(*chunks: bytes) -> bytes:
    h = sha256()
    for chunk in chunks:
        h.update(chunk)
    return h.digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, sha256).digest()


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Standard HKDF-SHA256 (extract-then-expand)."""
    return HKDF(
        algorithm=SHA256(), length=length, salt=salt, info=info
    ).derive(ikm)


def noise_hkdf(
    chaining_key: bytes, input_key_material: bytes, num_outputs: int
) -> tuple[bytes, ...]:
    """The HKDF variant specified by the Noise Protocol Framework (section 4.3).

    Noise defines its own expand step rather than reusing HKDF's ``info``
    parameter, so this cannot be expressed with :func:`hkdf`. The chaining key
    is the salt and the expansion info is empty.
    """
    if num_outputs not in (2, 3):
        raise ValueError("Noise HKDF produces 2 or 3 outputs")
    temp_key = hmac_sha256(chaining_key, input_key_material)
    out1 = hmac_sha256(temp_key, b"\x01")
    out2 = hmac_sha256(temp_key, out1 + b"\x02")
    if num_outputs == 2:
        return out1, out2
    out3 = hmac_sha256(temp_key, out2 + b"\x03")
    return out1, out2, out3


def scrypt_derive(passphrase: bytes, salt: bytes, length: int = 32) -> bytes:
    """Password-based KDF for the on-disk keystore.

    n=2**15 keeps unlocking under ~100 ms on a laptop while costing an attacker
    32 MiB of memory per guess.
    """
    return Scrypt(salt=salt, length=length, n=2**15, r=8, p=1).derive(passphrase)


# --------------------------------------------------------------------------
# AEAD
# --------------------------------------------------------------------------


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, ad: bytes) -> bytes:
    if len(key) != KEYLEN:
        raise ValueError("ChaCha20-Poly1305 needs a 32-byte key")
    if len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 needs a 12-byte nonce")
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, ad)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, ad: bytes) -> bytes:
    if len(key) != KEYLEN:
        raise ValueError("ChaCha20-Poly1305 needs a 32-byte key")
    if len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 needs a 12-byte nonce")
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, ad)
    except InvalidTag as exc:
        raise AEADError("AEAD authentication failed") from exc


# --------------------------------------------------------------------------
# X25519
# --------------------------------------------------------------------------


def generate_x25519() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def x25519_public_bytes(key: X25519PublicKey | X25519PrivateKey) -> bytes:
    if isinstance(key, X25519PrivateKey):
        key = key.public_key()
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_private_bytes(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_x25519_public(raw: bytes) -> X25519PublicKey:
    if len(raw) != DHLEN:
        raise ValueError(f"X25519 public key must be {DHLEN} bytes, got {len(raw)}")
    return X25519PublicKey.from_public_bytes(raw)


def load_x25519_private(raw: bytes) -> X25519PrivateKey:
    if len(raw) != DHLEN:
        raise ValueError(f"X25519 private key must be {DHLEN} bytes, got {len(raw)}")
    return X25519PrivateKey.from_private_bytes(raw)


def dh(private: X25519PrivateKey, peer_public: X25519PublicKey | bytes) -> bytes:
    """X25519 with contributory-behaviour checking.

    Rejecting the all-zero output stops a peer from forcing a known shared
    secret by sending a low-order point.
    """
    if isinstance(peer_public, (bytes, bytearray)):
        peer_public = load_x25519_public(bytes(peer_public))
    shared = private.exchange(peer_public)
    if constant_time_eq(shared, _ZERO_DH):
        raise ValueError("X25519 produced an all-zero shared secret (low-order point)")
    return shared


# --------------------------------------------------------------------------
# Ed25519
# --------------------------------------------------------------------------


def generate_ed25519() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def ed25519_public_bytes(key: Ed25519PublicKey | Ed25519PrivateKey) -> bytes:
    if isinstance(key, Ed25519PrivateKey):
        key = key.public_key()
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def ed25519_private_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_ed25519_public(raw: bytes) -> Ed25519PublicKey:
    if len(raw) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


def load_ed25519_private(raw: bytes) -> Ed25519PrivateKey:
    if len(raw) != 32:
        raise ValueError(f"Ed25519 private key must be 32 bytes, got {len(raw)}")
    return Ed25519PrivateKey.from_private_bytes(raw)


def sign(private: Ed25519PrivateKey, message: bytes) -> bytes:
    return private.sign(message)


def verify(public: Ed25519PublicKey | bytes, signature: bytes, message: bytes) -> bool:
    if isinstance(public, (bytes, bytearray)):
        try:
            public = load_ed25519_public(bytes(public))
        except ValueError:
            return False
    try:
        public.verify(signature, message)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# misc
# --------------------------------------------------------------------------


def constant_time_eq(a: bytes, b: bytes) -> bool:
    return _hmac.compare_digest(a, b)


def random_bytes(n: int) -> bytes:
    return os.urandom(n)
