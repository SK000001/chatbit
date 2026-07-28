"""Peer sessions: handshake, identity verification, and the message ratchet.

A session goes through three states::

    NONE  --(Noise XX, 3 messages)-->  ESTABLISHED  --> (Double Ratchet)

The Noise handshake authenticates both parties and produces a shared secret.
That secret seeds a Double Ratchet, and every application message from then on
rides the ratchet. Noise gives forward secrecy and mutual authentication; the
ratchet adds post-compromise security on top.

Identity handling is the part written in direct response to how bitchat's
identity system was broken. Three rules, enforced here and not left to callers:

1. A handshake that does not carry a valid Ed25519 signature over the live
   transcript is aborted. An unsigned or badly signed identity claim is not
   downgraded to "unverified" -- it is refused.
2. Peers are keyed by their identity public key. Nicknames are display data and
   are never used to look up, match, or authorise anything.
3. A known peer presenting a different static key aborts the handshake with
   :class:`~chatbit.crypto.identity.KeyChangedError`. Re-pinning is an explicit
   user action, never automatic.

Key derivation
--------------
From the completed handshake's chaining key and transcript hash::

    okm            = HKDF(ikm=ck, salt=h, info="chatbit/v1 session", len=96)
    root_key       = okm[0:32]    -- seeds the Double Ratchet
    i2r_tag_key    = okm[32:64]   -- initiator->responder frame tags
    r2i_tag_key    = okm[64:96]   -- responder->initiator frame tags

The tag keys are directional so that the tag on a frame identifies the
*direction* as well as the session, and neither side can generate frames that
appear to come from the other.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum

from .crypto.identity import Identity, KeyChangedError, PeerIdentity, TrustStore
from .crypto.noise import HandshakeState, NoiseError
from .crypto.primitives import (
    generate_x25519,
    hkdf,
    random_bytes,
    x25519_public_bytes,
)
from .crypto.ratchet import DoubleRatchet, MessageHeader, RatchetError
from .crypto.ratchet import HEADER_LEN as RATCHET_HEADER_LEN
from .wire import tags

__all__ = [
    "Session",
    "SessionManager",
    "SessionState",
    "SessionError",
    "PROLOGUE",
]

PROLOGUE = b"chatbit/v1"
_SESSION_INFO = b"chatbit/v1 session"

HS_ID_LEN = 4
SIG_LEN = 64
PUBKEY_LEN = 32

# A handshake that never completes must not pin memory forever.
HANDSHAKE_TIMEOUT = 120.0
MAX_PENDING_HANDSHAKES = 32


class SessionError(Exception):
    """A session operation failed."""


class SessionState(str, Enum):
    NONE = "none"
    HANDSHAKE_SENT = "handshake_sent"
    HANDSHAKE_RECEIVED = "handshake_received"
    ESTABLISHED = "established"


def _encode_identity_payload(
    identity: Identity, handshake_hash: bytes, ratchet_pub: bytes | None
) -> bytes:
    """``signing_pub || sig(transcript) [|| ratchet_pub] || len(nick) || nick``"""
    nickname = identity.nickname.encode()[:64]
    body = identity.signing_public + identity.sign_transcript(handshake_hash)
    if ratchet_pub is not None:
        body += ratchet_pub
    return body + bytes([len(nickname)]) + nickname


def _decode_identity_payload(
    payload: bytes, expect_ratchet: bool
) -> tuple[bytes, bytes, bytes | None, str]:
    """Returns ``(signing_pub, signature, ratchet_pub, nickname)``."""
    need = PUBKEY_LEN + SIG_LEN + (PUBKEY_LEN if expect_ratchet else 0) + 1
    if len(payload) < need:
        raise SessionError("handshake identity payload is truncated")

    offset = 0
    signing_pub = payload[offset : offset + PUBKEY_LEN]
    offset += PUBKEY_LEN
    signature = payload[offset : offset + SIG_LEN]
    offset += SIG_LEN

    ratchet_pub = None
    if expect_ratchet:
        ratchet_pub = payload[offset : offset + PUBKEY_LEN]
        offset += PUBKEY_LEN

    nick_len = payload[offset]
    offset += 1
    nickname = payload[offset : offset + nick_len].decode("utf-8", errors="replace")
    return signing_pub, signature, ratchet_pub, nickname


def _derive_session_keys(chaining_key: bytes, handshake_hash: bytes) -> tuple[bytes, bytes, bytes]:
    okm = hkdf(ikm=chaining_key, salt=handshake_hash, info=_SESSION_INFO, length=96)
    return okm[0:32], okm[32:64], okm[64:96]


@dataclass
class Session:
    """An established, authenticated channel to one peer."""

    peer: PeerIdentity
    ratchet: DoubleRatchet
    send_tag_key: bytes
    recv_tag_key: bytes
    initiator: bool
    established_at: float = field(default_factory=time.time)
    messages_sent: int = 0
    messages_received: int = 0

    @property
    def state(self) -> SessionState:
        return SessionState.ESTABLISHED

    def current_send_tag(self, now: float | None = None) -> bytes:
        return tags.compute_tag(self.send_tag_key, now=now)

    def owns_tag(self, tag: bytes, now: float | None = None) -> bool:
        return tags.matches(tag, self.recv_tag_key, now=now)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Ratchet-encrypt one message into ``header || ciphertext``."""
        header, ciphertext = self.ratchet.encrypt(plaintext)
        self.messages_sent += 1
        return header.encode() + ciphertext

    def decrypt(self, blob: bytes) -> bytes:
        if len(blob) < RATCHET_HEADER_LEN:
            raise SessionError("data frame is too short to contain a ratchet header")
        header = MessageHeader.decode(blob[:RATCHET_HEADER_LEN])
        try:
            plaintext = self.ratchet.decrypt(header, blob[RATCHET_HEADER_LEN:])
        except RatchetError as exc:
            raise SessionError(f"decryption failed: {exc}") from exc
        self.messages_received += 1
        return plaintext


@dataclass
class _PendingHandshake:
    handshake: HandshakeState
    hs_id: bytes
    started_at: float
    initiator: bool
    ratchet_private: object | None = None  # responder's fresh ratchet key
    peer_static: bytes | None = None


class SessionManager:
    """Drives handshakes and owns the set of established sessions."""

    def __init__(self, identity: Identity, trust: TrustStore) -> None:
        self.identity = identity
        self.trust = trust
        self._sessions: dict[bytes, Session] = {}  # keyed by peer signing pubkey
        self._pending: dict[bytes, _PendingHandshake] = {}  # keyed by hs_id

    # -- lookup -----------------------------------------------------------

    def session_for(self, signing_public: bytes) -> Session | None:
        return self._sessions.get(signing_public)

    def session_by_tag(self, tag: bytes, now: float | None = None) -> Session | None:
        for session in self._sessions.values():
            if session.owns_tag(tag, now=now):
                return session
        return None

    def sessions(self) -> list[Session]:
        return list(self._sessions.values())

    def drop(self, signing_public: bytes) -> None:
        self._sessions.pop(signing_public, None)

    # -- initiator side ---------------------------------------------------

    def start_handshake(self, peer_static_public: bytes) -> tuple[bytes, bytes]:
        """Begin a handshake. Returns ``(payload, dst_tag)`` for a HANDSHAKE_INIT."""
        self._expire_pending()
        hs_id = random_bytes(HS_ID_LEN)
        handshake = HandshakeState(
            initiator=True,
            static_private=self.identity.static_private,
            prologue=PROLOGUE,
        )
        message = handshake.write_message_1()
        self._pending[hs_id] = _PendingHandshake(
            handshake=handshake,
            hs_id=hs_id,
            started_at=time.monotonic(),
            initiator=True,
            peer_static=peer_static_public,
        )
        # Addressed with a tag only the intended responder can recognise
        # cheaply. See chatbit.wire.tags for what this does and does not hide.
        return hs_id + message, tags.handshake_tag(peer_static_public)

    def handle_response(self, payload: bytes) -> tuple[bytes, Session] | None:
        """Process a HANDSHAKE_RESP. Returns ``(fin_payload, session)``."""
        hs_id, body = payload[:HS_ID_LEN], payload[HS_ID_LEN:]
        pending = self._pending.get(hs_id)
        if pending is None or not pending.initiator:
            return None  # not ours, or already completed

        try:
            peer_static, signed_hash, identity_payload = (
                pending.handshake.read_message_2(body)
            )
        except (NoiseError, ValueError) as exc:
            del self._pending[hs_id]
            raise SessionError(f"handshake response rejected: {exc}") from exc

        signing_pub, signature, ratchet_pub, nickname = _decode_identity_payload(
            identity_payload, expect_ratchet=True
        )
        peer = PeerIdentity(signing_pub, peer_static, nickname)
        if not peer.verify_transcript(signed_hash, signature):
            del self._pending[hs_id]
            raise SessionError(
                "responder's identity signature is invalid -- aborting. "
                "Someone is either broken or lying about who they are."
            )

        # Pin or check the identity *before* completing the handshake, so a
        # changed key aborts rather than silently establishing a session.
        peer = self._pin(peer)

        fin = pending.handshake.write_message_3(
            lambda h: _encode_identity_payload(self.identity, h, None)
        )
        session = self._finalise(pending, peer, ratchet_pub=ratchet_pub)
        del self._pending[hs_id]
        return hs_id + fin, session

    # -- responder side ---------------------------------------------------

    def handle_init(self, payload: bytes) -> bytes | None:
        """Process a HANDSHAKE_INIT. Returns the HANDSHAKE_RESP payload."""
        self._expire_pending()
        if len(self._pending) >= MAX_PENDING_HANDSHAKES:
            # Under a handshake flood, serve who we can and drop the rest
            # rather than letting state grow without bound.
            return None

        hs_id, body = payload[:HS_ID_LEN], payload[HS_ID_LEN:]
        if hs_id in self._pending:
            return None  # replay of an in-flight handshake

        handshake = HandshakeState(
            initiator=False,
            static_private=self.identity.static_private,
            prologue=PROLOGUE,
        )
        try:
            handshake.read_message_1(body)
        except (NoiseError, ValueError):
            return None

        ratchet_private = generate_x25519()
        ratchet_pub = x25519_public_bytes(ratchet_private)
        try:
            message = handshake.write_message_2(
                lambda h: _encode_identity_payload(self.identity, h, ratchet_pub)
            )
        except (NoiseError, ValueError):
            # ValueError covers a degenerate DH: a peer that sends a low-order
            # point gets its handshake dropped, not an exception out of here.
            return None

        self._pending[hs_id] = _PendingHandshake(
            handshake=handshake,
            hs_id=hs_id,
            started_at=time.monotonic(),
            initiator=False,
            ratchet_private=ratchet_private,
        )
        return hs_id + message

    def handle_fin(self, payload: bytes) -> Session | None:
        """Process a HANDSHAKE_FIN, completing the session."""
        hs_id, body = payload[:HS_ID_LEN], payload[HS_ID_LEN:]
        pending = self._pending.get(hs_id)
        if pending is None or pending.initiator:
            return None

        try:
            peer_static, signed_hash, identity_payload = (
                pending.handshake.read_message_3(body)
            )
        except (NoiseError, ValueError) as exc:
            del self._pending[hs_id]
            raise SessionError(f"handshake completion rejected: {exc}") from exc

        signing_pub, signature, _, nickname = _decode_identity_payload(
            identity_payload, expect_ratchet=False
        )
        peer = PeerIdentity(signing_pub, peer_static, nickname)
        if not peer.verify_transcript(signed_hash, signature):
            del self._pending[hs_id]
            raise SessionError("initiator's identity signature is invalid -- aborting")

        peer = self._pin(peer)
        session = self._finalise(pending, peer, ratchet_pub=None)
        del self._pending[hs_id]
        return session

    # -- shared -----------------------------------------------------------

    def _pin(self, peer: PeerIdentity) -> PeerIdentity:
        try:
            return self.trust.observe(
                peer.signing_public,
                peer.static_public,
                peer.nickname,
                now=time.time(),
            )
        except KeyChangedError:
            # Deliberately not caught here. A changed key is a decision for the
            # user, and the only safe default is to stop.
            raise

    def _finalise(
        self,
        pending: _PendingHandshake,
        peer: PeerIdentity,
        ratchet_pub: bytes | None,
    ) -> Session:
        handshake = pending.handshake
        root_key, i2r_tag_key, r2i_tag_key = _derive_session_keys(
            handshake.chaining_key(), handshake.handshake_hash
        )

        if pending.initiator:
            assert ratchet_pub is not None
            ratchet = DoubleRatchet.init_sender(root_key, ratchet_pub)
            send_tag_key, recv_tag_key = i2r_tag_key, r2i_tag_key
        else:
            assert pending.ratchet_private is not None
            ratchet = DoubleRatchet.init_receiver(root_key, pending.ratchet_private)
            send_tag_key, recv_tag_key = r2i_tag_key, i2r_tag_key

        session = Session(
            peer=peer,
            ratchet=ratchet,
            send_tag_key=send_tag_key,
            recv_tag_key=recv_tag_key,
            initiator=pending.initiator,
        )
        self._sessions[peer.signing_public] = session
        return session

    def _expire_pending(self, now: float | None = None) -> None:
        now = now if now is not None else time.monotonic()
        stale = [
            hs_id
            for hs_id, p in self._pending.items()
            if now - p.started_at > HANDSHAKE_TIMEOUT
        ]
        for hs_id in stale:
            del self._pending[hs_id]

    @property
    def pending_count(self) -> int:
        return len(self._pending)
