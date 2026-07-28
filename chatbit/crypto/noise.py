"""Noise_XX_25519_ChaChaPoly_SHA256.

An implementation of the Noise Protocol Framework's XX handshake pattern,
following revision 34 of the specification.

    XX:
      -> e
      <- e, ee, s, es
      -> s, se

XX gives mutual authentication and forward secrecy without either side needing
to know the other's static key in advance, which is what a mesh where peers
meet opportunistically requires.

Handshake payloads
------------------
chatbit carries an identity proof in the handshake payloads. Message 2 and
message 3 each contain::

    ed25519_public_key (32) || signature (64) [|| ratchet_public_key (32)]

where the signature is over ``DOMAIN || h``, and ``h`` is the Noise handshake
hash *at the moment the payload is written*, before it is encrypted.

This is the fix for the class of bug that bit bitchat: a long-term identity is
only meaningful if it is cryptographically bound to the session it is claiming.
Because ``h`` commits to the whole transcript so far -- both ephemerals and the
encrypted static keys -- a signature over it cannot be replayed into a
different handshake, and a relay cannot substitute its own static key while
keeping someone else's identity. Nothing in this protocol accepts an identity
that did not arrive with a valid signature over the live transcript.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .primitives import (
    DHLEN,
    HASHLEN,
    KEYLEN,
    TAGLEN,
    AEADError,
    aead_decrypt,
    aead_encrypt,
    dh,
    generate_x25519,
    hash_sha256,
    load_x25519_public,
    noise_hkdf,
    x25519_public_bytes,
)

PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
MAX_NONCE = 2**64 - 1

__all__ = [
    "CipherState",
    "SymmetricState",
    "HandshakeState",
    "NoiseError",
    "PROTOCOL_NAME",
]


class NoiseError(Exception):
    """A Noise handshake or transport operation failed."""


def _nonce_bytes(n: int) -> bytes:
    """Noise formats the nonce as 4 zero bytes then n little-endian (64-bit)."""
    return b"\x00\x00\x00\x00" + n.to_bytes(8, "little")


class CipherState:
    """A key plus a nonce counter. Section 5.1."""

    __slots__ = ("k", "n")

    def __init__(self, key: bytes | None = None) -> None:
        self.k = key
        self.n = 0

    def has_key(self) -> bool:
        return self.k is not None

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        if self.k is None:
            return plaintext
        if self.n > MAX_NONCE:
            raise NoiseError("nonce exhausted; rekey or start a new session")
        ct = aead_encrypt(self.k, _nonce_bytes(self.n), plaintext, ad)
        self.n += 1
        return ct

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        if self.k is None:
            return ciphertext
        if self.n > MAX_NONCE:
            raise NoiseError("nonce exhausted; rekey or start a new session")
        try:
            pt = aead_decrypt(self.k, _nonce_bytes(self.n), ciphertext, ad)
        except AEADError as exc:
            # Do not advance n on failure: a forged packet must not be able to
            # desynchronise a healthy session.
            raise NoiseError("handshake/transport decryption failed") from exc
        self.n += 1
        return pt


class SymmetricState:
    """Chaining key + transcript hash. Section 5.2."""

    __slots__ = ("ck", "h", "cipher")

    def __init__(self, protocol_name: bytes) -> None:
        if len(protocol_name) <= HASHLEN:
            self.h = protocol_name + b"\x00" * (HASHLEN - len(protocol_name))
        else:
            self.h = hash_sha256(protocol_name)
        self.ck = self.h
        self.cipher = CipherState()

    def mix_key(self, input_key_material: bytes) -> None:
        self.ck, temp_k = noise_hkdf(self.ck, input_key_material, 2)
        self.cipher = CipherState(temp_k[:KEYLEN])

    def mix_hash(self, data: bytes) -> None:
        self.h = hash_sha256(self.h, data)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self.cipher.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self.cipher.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> tuple[CipherState, CipherState]:
        temp_k1, temp_k2 = noise_hkdf(self.ck, b"", 2)
        return CipherState(temp_k1[:KEYLEN]), CipherState(temp_k2[:KEYLEN])


@dataclass
class HandshakeState:
    """Drives the XX pattern. Section 5.3.

    ``payloads`` are supplied by the caller for each write and returned for
    each read, which is how the identity proof rides along.
    """

    initiator: bool
    static_private: object  # X25519PrivateKey
    prologue: bytes = b""

    #: Ephemeral key source. Defaults to a fresh random keypair, which is what
    #: production must use. Test vectors override it to pin the ephemeral and
    #: make a handshake transcript reproducible across implementations.
    ephemeral_factory: object = generate_x25519

    symmetric: SymmetricState = field(init=False)
    e: object | None = field(default=None, init=False)
    re: bytes | None = field(default=None, init=False)
    rs: bytes | None = field(default=None, init=False)
    _msg_index: int = field(default=0, init=False)
    _split: tuple[CipherState, CipherState] | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self.symmetric = SymmetricState(PROTOCOL_NAME)
        self.symmetric.mix_hash(self.prologue)
        # XX has no pre-message keys, so there is nothing else to mix in here.

    # -- introspection ----------------------------------------------------

    @property
    def handshake_hash(self) -> bytes:
        """The current transcript hash. Signed to bind identities to this run."""
        return self.symmetric.h

    @property
    def remote_static(self) -> bytes | None:
        return self.rs

    @property
    def complete(self) -> bool:
        return self._split is not None

    # -- message 1: -> e --------------------------------------------------

    def write_message_1(self) -> bytes:
        if not self.initiator or self._msg_index != 0:
            raise NoiseError("write_message_1 out of order")
        self.e = self.ephemeral_factory()
        epub = x25519_public_bytes(self.e)
        self.symmetric.mix_hash(epub)
        self._msg_index = 1
        return epub

    def read_message_1(self, message: bytes) -> None:
        if self.initiator or self._msg_index != 0:
            raise NoiseError("read_message_1 out of order")
        if len(message) != DHLEN:
            raise NoiseError("malformed handshake message 1")
        self.re = message
        load_x25519_public(self.re)  # reject wrong-length / unusable keys early
        self.symmetric.mix_hash(self.re)
        self._msg_index = 1

    # -- message 2: <- e, ee, s, es ---------------------------------------

    def write_message_2(self, payload_builder) -> bytes:
        """``payload_builder(handshake_hash) -> bytes``.

        The builder is called with ``h`` *before* the payload is encrypted, so
        the caller can sign exactly the value the reader will reconstruct.
        """
        if self.initiator or self._msg_index != 1:
            raise NoiseError("write_message_2 out of order")
        self.e = self.ephemeral_factory()
        epub = x25519_public_bytes(self.e)
        self.symmetric.mix_hash(epub)

        self.symmetric.mix_key(dh(self.e, self.re))  # ee

        spub = x25519_public_bytes(self.static_private)
        enc_s = self.symmetric.encrypt_and_hash(spub)  # s

        self.symmetric.mix_key(dh(self.static_private, self.re))  # es

        payload = payload_builder(self.symmetric.h)
        enc_payload = self.symmetric.encrypt_and_hash(payload)

        self._msg_index = 2
        return epub + enc_s + enc_payload

    def read_message_2(self, message: bytes) -> tuple[bytes, bytes, bytes]:
        """Returns ``(remote_static, signed_hash, payload)``.

        ``signed_hash`` is the transcript hash the writer signed over, so the
        caller can verify the identity proof carried in ``payload``.
        """
        if not self.initiator or self._msg_index != 1:
            raise NoiseError("read_message_2 out of order")
        if len(message) < DHLEN + DHLEN + TAGLEN:
            raise NoiseError("malformed handshake message 2")

        self.re = message[:DHLEN]
        load_x25519_public(self.re)
        self.symmetric.mix_hash(self.re)

        self.symmetric.mix_key(dh(self.e, self.re))  # ee

        enc_s = message[DHLEN : DHLEN + DHLEN + TAGLEN]
        self.rs = self.symmetric.decrypt_and_hash(enc_s)  # s
        load_x25519_public(self.rs)

        self.symmetric.mix_key(dh(self.e, self.rs))  # es

        signed_h = self.symmetric.h
        payload = self.symmetric.decrypt_and_hash(message[DHLEN + DHLEN + TAGLEN :])

        self._msg_index = 2
        return self.rs, signed_h, payload

    # -- message 3: -> s, se ----------------------------------------------

    def write_message_3(self, payload_builder) -> bytes:
        if not self.initiator or self._msg_index != 2:
            raise NoiseError("write_message_3 out of order")

        spub = x25519_public_bytes(self.static_private)
        enc_s = self.symmetric.encrypt_and_hash(spub)  # s

        self.symmetric.mix_key(dh(self.static_private, self.re))  # se

        payload = payload_builder(self.symmetric.h)
        enc_payload = self.symmetric.encrypt_and_hash(payload)

        self._split = self.symmetric.split()
        self._msg_index = 3
        return enc_s + enc_payload

    def read_message_3(self, message: bytes) -> tuple[bytes, bytes, bytes]:
        """Returns ``(remote_static, signed_hash, payload)``."""
        if self.initiator or self._msg_index != 2:
            raise NoiseError("read_message_3 out of order")
        if len(message) < DHLEN + TAGLEN:
            raise NoiseError("malformed handshake message 3")

        enc_s = message[: DHLEN + TAGLEN]
        self.rs = self.symmetric.decrypt_and_hash(enc_s)  # s
        load_x25519_public(self.rs)

        self.symmetric.mix_key(dh(self.e, self.rs))  # se

        signed_h = self.symmetric.h
        payload = self.symmetric.decrypt_and_hash(message[DHLEN + TAGLEN :])

        self._split = self.symmetric.split()
        self._msg_index = 3
        return self.rs, signed_h, payload

    # -- completion -------------------------------------------------------

    def split(self) -> tuple[CipherState, CipherState]:
        """``(send, recv)`` transport keys from the initiator's point of view."""
        if self._split is None:
            raise NoiseError("handshake is not complete")
        c1, c2 = self._split
        return (c1, c2) if self.initiator else (c2, c1)

    def chaining_key(self) -> bytes:
        if self._split is None:
            raise NoiseError("handshake is not complete")
        return self.symmetric.ck
