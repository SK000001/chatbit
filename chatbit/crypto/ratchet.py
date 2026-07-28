"""The Double Ratchet.

An implementation of Signal's Double Ratchet algorithm (Perrin & Marlinspike,
revision 1) over X25519 + HKDF-SHA256 + ChaCha20-Poly1305.

Why this exists
---------------
A Noise XX handshake gives *forward secrecy*: keys derived today do not help an
attacker read yesterday's traffic. It does not give *post-compromise security*:
if a device is seized or a session key leaks, every later message in that
session is readable, forever, with no way to recover.

For a protocol whose whole premise is operating in places where devices get
seized, that is the wrong failure mode. The Double Ratchet fixes it. Every time
the conversation changes direction a fresh X25519 exchange is folded into the
root key, so an attacker who learns the state at time T loses the ability to
decrypt as soon as one round trip completes after T. Sessions heal.

Two ratchets are in play:

* The **symmetric ratchet** advances a chain key per message, so each message
  gets a unique key that is deleted after use.
* The **DH ratchet** advances the root key per direction change, which is what
  provides the healing property.

Out-of-order and dropped messages are expected on a lossy radio link, so
skipped message keys are retained (bounded, see :data:`MAX_SKIP` and
:data:`MAX_SKIPPED_KEYS`) until they are used or evicted.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

from .primitives import (
    KEYLEN,
    AEADError,
    aead_decrypt,
    aead_encrypt,
    dh,
    generate_x25519,
    hkdf,
    hmac_sha256,
    load_x25519_private,
    load_x25519_public,
    x25519_private_bytes,
    x25519_public_bytes,
)

__all__ = ["DoubleRatchet", "RatchetError", "MessageHeader", "MAX_SKIP"]

# How far ahead of the expected counter we will jump within a single chain.
# Bounds the work a single forged header can force us to do.
MAX_SKIP = 256

# Total retained out-of-order keys across all chains. Oldest are evicted first.
MAX_SKIPPED_KEYS = 1024

_ROOT_INFO = b"chatbit/v1 ratchet-root"
_MSG_INFO = b"chatbit/v1 message-key"
_CHAIN_MSG = b"\x01"
_CHAIN_NEXT = b"\x02"

HEADER_LEN = 32 + 4 + 4  # ratchet pubkey || PN (u32) || N (u32)


class RatchetError(Exception):
    """A ratchet operation failed."""


class SkippedKeyLimit(RatchetError):
    """A message asked us to skip more keys than the policy allows."""


@dataclass(frozen=True)
class MessageHeader:
    """Plaintext-but-authenticated per-message header.

    The header travels in the clear (the transport layer encrypts the whole
    frame separately) but is bound into the AEAD's associated data, so it
    cannot be tampered with without breaking decryption.
    """

    ratchet_pub: bytes
    pn: int
    n: int

    def encode(self) -> bytes:
        return (
            self.ratchet_pub
            + self.pn.to_bytes(4, "big")
            + self.n.to_bytes(4, "big")
        )

    @classmethod
    def decode(cls, raw: bytes) -> "MessageHeader":
        if len(raw) != HEADER_LEN:
            raise RatchetError(f"ratchet header must be {HEADER_LEN} bytes")
        return cls(
            ratchet_pub=raw[:32],
            pn=int.from_bytes(raw[32:36], "big"),
            n=int.from_bytes(raw[36:40], "big"),
        )


def _kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """Root KDF: (root key, DH output) -> (new root key, new chain key)."""
    out = hkdf(ikm=dh_out, salt=rk, info=_ROOT_INFO, length=64)
    return out[:32], out[32:]


def _kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """Chain KDF: chain key -> (next chain key, message key)."""
    mk = hmac_sha256(ck, _CHAIN_MSG)
    next_ck = hmac_sha256(ck, _CHAIN_NEXT)
    return next_ck, mk


def _message_keys(mk: bytes) -> tuple[bytes, bytes]:
    """Expand a message key into an AEAD key and nonce."""
    out = hkdf(ikm=mk, salt=b"\x00" * 32, info=_MSG_INFO, length=KEYLEN + 12)
    return out[:KEYLEN], out[KEYLEN:]


@dataclass
class DoubleRatchet:
    """Ratchet state for one peer session.

    Construct with :meth:`init_sender` or :meth:`init_receiver` rather than
    directly; which one you use depends on who moves first, and only the sender
    side needs the peer's initial ratchet public key.
    """

    dhs_priv: object  # X25519PrivateKey -- our current ratchet keypair
    dhr_pub: bytes | None  # their current ratchet public key
    rk: bytes
    cks: bytes | None = None  # sending chain key
    ckr: bytes | None = None  # receiving chain key
    ns: int = 0  # messages sent in current sending chain
    nr: int = 0  # messages received in current receiving chain
    pn: int = 0  # messages sent in the *previous* sending chain
    skipped: "OrderedDict[tuple[bytes, int], bytes]" = field(
        default_factory=OrderedDict
    )

    #: Ratchet key source. Defaults to a fresh random keypair, which is what
    #: production must use. Test vectors override it so that a ratchet chain --
    #: including its DH steps -- is reproducible across implementations.
    #: Deliberately excluded from serialize()/deserialize(): it is a policy
    #: knob, not session state.
    keygen: object = field(default=generate_x25519, compare=False, repr=False)

    # -- construction -----------------------------------------------------

    @classmethod
    def init_sender(
        cls,
        shared_key: bytes,
        peer_ratchet_pub: bytes,
        keygen: object = generate_x25519,
    ) -> "DoubleRatchet":
        """For the side that will send first (the handshake initiator)."""
        if len(shared_key) != 32:
            raise RatchetError("shared key must be 32 bytes")
        load_x25519_public(peer_ratchet_pub)
        dhs = keygen()
        rk, cks = _kdf_rk(shared_key, dh(dhs, peer_ratchet_pub))
        return cls(
            dhs_priv=dhs, dhr_pub=peer_ratchet_pub, rk=rk, cks=cks, keygen=keygen
        )

    @classmethod
    def init_receiver(
        cls,
        shared_key: bytes,
        ratchet_private: object,
        keygen: object = generate_x25519,
    ) -> "DoubleRatchet":
        """For the side whose ratchet public key was published in the handshake."""
        if len(shared_key) != 32:
            raise RatchetError("shared key must be 32 bytes")
        return cls(
            dhs_priv=ratchet_private, dhr_pub=None, rk=shared_key, keygen=keygen
        )

    @property
    def ratchet_public(self) -> bytes:
        return x25519_public_bytes(self.dhs_priv)

    # -- sending ----------------------------------------------------------

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> tuple[MessageHeader, bytes]:
        if self.cks is None:
            raise RatchetError(
                "no sending chain yet: this side must receive a message first"
            )
        self.cks, mk = _kdf_ck(self.cks)
        header = MessageHeader(self.ratchet_public, self.pn, self.ns)
        self.ns += 1
        key, nonce = _message_keys(mk)
        ct = aead_encrypt(key, nonce, plaintext, associated_data + header.encode())
        return header, ct

    # -- receiving --------------------------------------------------------

    def decrypt(
        self, header: MessageHeader, ciphertext: bytes, associated_data: bytes = b""
    ) -> bytes:
        """Decrypt one message, advancing the ratchet as required.

        Every state change here is destructive -- advancing a chain key
        discards the old one by design. So the whole operation runs against a
        copy and is only committed once the message has actually
        authenticated. Anyone can transmit on an open radio channel, and a
        forged frame must not be able to desynchronise a healthy session.
        """
        plaintext = self._try_skipped(header, ciphertext, associated_data)
        if plaintext is not None:
            return plaintext

        trial = self._clone_state()
        try:
            if header.ratchet_pub != trial.dhr_pub:
                # The peer began a new sending chain. Retain keys for anything
                # still in flight on the old chain, then step the DH ratchet.
                trial._skip_message_keys(header.pn)
                trial._dh_ratchet(header)
            trial._skip_message_keys(header.n)
            plaintext = trial._decrypt_current(header, ciphertext, associated_data)
        except (RatchetError, AEADError, ValueError) as exc:
            raise RatchetError(f"message failed to authenticate: {exc}") from exc

        self._adopt(trial)
        return plaintext

    def _decrypt_current(
        self, header: MessageHeader, ciphertext: bytes, associated_data: bytes
    ) -> bytes:
        if self.ckr is None:
            raise RatchetError("no receiving chain established")
        next_ckr, mk = _kdf_ck(self.ckr)
        key, nonce = _message_keys(mk)
        plaintext = aead_decrypt(
            key, nonce, ciphertext, associated_data + header.encode()
        )
        self.ckr = next_ckr
        self.nr += 1
        return plaintext

    def _try_skipped(
        self, header: MessageHeader, ciphertext: bytes, associated_data: bytes
    ) -> bytes | None:
        key_id = (header.ratchet_pub, header.n)
        mk = self.skipped.get(key_id)
        if mk is None:
            return None
        key, nonce = _message_keys(mk)
        try:
            pt = aead_decrypt(
                key, nonce, ciphertext, associated_data + header.encode()
            )
        except AEADError:
            # A stored key that does not authenticate means a forgery, not a
            # reason to discard the key -- the real message may still arrive.
            raise RatchetError("skipped-key decryption failed")
        del self.skipped[key_id]
        return pt

    def _skip_message_keys(self, until: int) -> None:
        if self.ckr is None:
            if until > 0:
                raise SkippedKeyLimit("cannot skip keys with no receiving chain")
            return
        if until - self.nr > MAX_SKIP:
            raise SkippedKeyLimit(
                f"message claims to skip {until - self.nr} keys (limit {MAX_SKIP})"
            )
        assert self.dhr_pub is not None
        while self.nr < until:
            self.ckr, mk = _kdf_ck(self.ckr)
            self.skipped[(self.dhr_pub, self.nr)] = mk
            self.nr += 1
            while len(self.skipped) > MAX_SKIPPED_KEYS:
                self.skipped.popitem(last=False)

    def _dh_ratchet(self, header: MessageHeader) -> None:
        load_x25519_public(header.ratchet_pub)
        self.pn = self.ns
        self.ns = 0
        self.nr = 0
        self.dhr_pub = header.ratchet_pub
        self.rk, self.ckr = _kdf_rk(self.rk, dh(self.dhs_priv, self.dhr_pub))
        self.dhs_priv = self.keygen()
        self.rk, self.cks = _kdf_rk(self.rk, dh(self.dhs_priv, self.dhr_pub))

    # -- state juggling ---------------------------------------------------

    def _clone_state(self) -> "DoubleRatchet":
        return DoubleRatchet(
            dhs_priv=self.dhs_priv,
            dhr_pub=self.dhr_pub,
            rk=self.rk,
            cks=self.cks,
            ckr=self.ckr,
            ns=self.ns,
            nr=self.nr,
            pn=self.pn,
            skipped=OrderedDict(self.skipped),
            keygen=self.keygen,
        )

    def _adopt(self, other: "DoubleRatchet") -> None:
        self.dhs_priv = other.dhs_priv
        self.dhr_pub = other.dhr_pub
        self.rk = other.rk
        self.cks = other.cks
        self.ckr = other.ckr
        self.ns = other.ns
        self.nr = other.nr
        self.pn = other.pn
        self.skipped = other.skipped

    # -- persistence ------------------------------------------------------

    def serialize(self) -> dict:
        """Plain-dict state, for storage inside the encrypted session store."""
        return {
            "dhs_priv": x25519_private_bytes(self.dhs_priv).hex(),
            "dhr_pub": self.dhr_pub.hex() if self.dhr_pub else None,
            "rk": self.rk.hex(),
            "cks": self.cks.hex() if self.cks else None,
            "ckr": self.ckr.hex() if self.ckr else None,
            "ns": self.ns,
            "nr": self.nr,
            "pn": self.pn,
            "skipped": [
                [pub.hex(), n, mk.hex()] for (pub, n), mk in self.skipped.items()
            ],
        }

    @classmethod
    def deserialize(cls, data: dict) -> "DoubleRatchet":
        skipped: OrderedDict[tuple[bytes, int], bytes] = OrderedDict()
        for pub_hex, n, mk_hex in data.get("skipped", []):
            skipped[(bytes.fromhex(pub_hex), n)] = bytes.fromhex(mk_hex)
        return cls(
            dhs_priv=load_x25519_private(bytes.fromhex(data["dhs_priv"])),
            dhr_pub=bytes.fromhex(data["dhr_pub"]) if data["dhr_pub"] else None,
            rk=bytes.fromhex(data["rk"]),
            cks=bytes.fromhex(data["cks"]) if data["cks"] else None,
            ckr=bytes.fromhex(data["ckr"]) if data["ckr"] else None,
            ns=data["ns"],
            nr=data["nr"],
            pn=data["pn"],
            skipped=skipped,
        )
