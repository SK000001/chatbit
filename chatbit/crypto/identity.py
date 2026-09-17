"""Long-term identity, fingerprints, and trust-on-first-use pinning.

An identity is two keypairs:

* **Ed25519** -- the thing that *is* you. Signs handshake transcripts. Its
  public key is what a fingerprint commits to, and what a peer verifies
  out of band.
* **X25519** -- the static Diffie-Hellman key used by the Noise handshake.

They are separate keys rather than one converted into the other, so a signing
oracle can never be turned into a key-agreement oracle. The two are bound
together by the handshake signature (see :mod:`chatbit.crypto.noise`) and by
the fingerprint, which commits to both.

The :class:`TrustStore` is the part that matters for the attack bitchat got
hit with. Trust is pinned on first contact and any later change of key for a
known peer is surfaced as a hard error, not a silent update.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .primitives import (
    ed25519_private_bytes,
    ed25519_public_bytes,
    generate_ed25519,
    generate_x25519,
    hash_sha256,
    hkdf,
    load_ed25519_private,
    load_x25519_private,
    random_bytes,
    scrypt_derive,
    aead_decrypt,
    aead_encrypt,
    sign,
    verify,
    x25519_private_bytes,
    x25519_public_bytes,
)

__all__ = [
    "Identity",
    "PeerIdentity",
    "TrustStore",
    "TrustError",
    "KeyChangedError",
    "fingerprint",
    "safety_number",
]

SIG_DOMAIN = b"chatbit/v1 identity-binding"


class TrustError(Exception):
    """A trust-store operation failed."""


class KeyChangedError(TrustError):
    """A known peer presented a different identity key than the pinned one.

    This is either the peer reinstalling, or an active impersonation attempt.
    The protocol cannot tell the difference, so it refuses to guess: the user
    must re-verify out of band.
    """

    def __init__(self, name: str, pinned: bytes, presented: bytes) -> None:
        self.name = name
        self.pinned = pinned
        self.presented = presented
        super().__init__(
            f"identity key for {name!r} changed\n"
            f"  pinned:    {format_fingerprint(fingerprint_from_keys(pinned, b''))}\n"
            f"  presented: {format_fingerprint(fingerprint_from_keys(presented, b''))}\n"
            "Refusing to connect. Verify out of band, then re-pin explicitly."
        )


def fingerprint_from_keys(ed25519_pub: bytes, x25519_pub: bytes) -> bytes:
    return hash_sha256(b"chatbit/v1 fingerprint", ed25519_pub, x25519_pub)


def format_fingerprint(fp: bytes, groups: int = 8) -> str:
    """Render a fingerprint as space-separated hex quads for reading aloud."""
    hexed = fp.hex()[: groups * 4]
    return " ".join(hexed[i : i + 4] for i in range(0, len(hexed), 4))


def safety_number(a_fingerprint: bytes, b_fingerprint: bytes) -> str:
    """A Signal-style 60-digit number both sides compute identically.

    Sorting the two fingerprints makes the result order-independent, so both
    parties see the same digits and can compare them over a voice call.
    """
    lo, hi = sorted([a_fingerprint, b_fingerprint])
    digest = hkdf(
        ikm=lo + hi, salt=b"", info=b"chatbit/v1 safety-number", length=30
    )
    digits = "".join(f"{b:03d}"[-2:] for b in digest)[:60].ljust(60, "0")
    return " ".join(digits[i : i + 5] for i in range(0, 60, 5))


@dataclass
class Identity:
    """Our own long-term identity."""

    signing_private: object  # Ed25519PrivateKey
    static_private: object  # X25519PrivateKey
    nickname: str = "anon"

    @classmethod
    def generate(cls, nickname: str = "anon") -> "Identity":
        return cls(generate_ed25519(), generate_x25519(), nickname)

    @property
    def signing_public(self) -> bytes:
        return ed25519_public_bytes(self.signing_private)

    @property
    def static_public(self) -> bytes:
        return x25519_public_bytes(self.static_private)

    @property
    def fingerprint(self) -> bytes:
        return fingerprint_from_keys(self.signing_public, self.static_public)

    @property
    def short_id(self) -> str:
        return self.fingerprint[:4].hex()

    def sign_transcript(self, handshake_hash: bytes) -> bytes:
        return sign(self.signing_private, SIG_DOMAIN + handshake_hash)

    # -- persistence ------------------------------------------------------

    def save(self, path: str | Path, passphrase: str | None = None) -> None:
        """Write the identity to disk, encrypted if a passphrase is given.

        An unencrypted identity file is a private key lying on disk in the
        clear, so callers are expected to pass a passphrase for anything but
        throwaway test keys.

        The file is created 0600 **on POSIX**. On Windows ``os.chmod`` can only
        toggle the read-only flag -- there are no POSIX permission bits -- so
        the request is a no-op and the file ends up world-readable, protected
        only by whatever NTFS ACLs it inherits. On Windows a passphrase is the
        only real protection for this file.
        """
        path = Path(path)
        body = json.dumps(
            {
                "nickname": self.nickname,
                "signing_private": ed25519_private_bytes(self.signing_private).hex(),
                "static_private": x25519_private_bytes(self.static_private).hex(),
            }
        ).encode()

        if passphrase:
            salt = random_bytes(16)
            nonce = random_bytes(12)
            key = scrypt_derive(passphrase.encode(), salt)
            blob = {
                "v": 1,
                "enc": "scrypt-chacha20poly1305",
                "salt": salt.hex(),
                "nonce": nonce.hex(),
                "ct": aead_encrypt(key, nonce, body, b"chatbit-identity").hex(),
            }
        else:
            blob = {"v": 1, "enc": "none", "pt": body.decode()}

        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w") as fh:
            json.dump(blob, fh)
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(tmp, path)

    @staticmethod
    def is_encrypted(path: str | Path) -> bool:
        """Whether an identity file is passphrase-protected.

        Lets a caller decide to prompt *before* attempting a load, rather than
        loading, failing, and prompting on the way back up.
        """
        try:
            with open(path) as fh:
                return json.load(fh).get("enc", "none") != "none"
        except (OSError, json.JSONDecodeError, AttributeError):
            return False

    @classmethod
    def load(cls, path: str | Path, passphrase: str | None = None) -> "Identity":
        with open(path) as fh:
            blob = json.load(fh)

        if blob.get("enc") == "none":
            body = blob["pt"].encode()
        else:
            if not passphrase:
                raise TrustError("identity file is encrypted; a passphrase is required")
            key = scrypt_derive(passphrase.encode(), bytes.fromhex(blob["salt"]))
            body = aead_decrypt(
                key,
                bytes.fromhex(blob["nonce"]),
                bytes.fromhex(blob["ct"]),
                b"chatbit-identity",
            )

        data = json.loads(body)
        return cls(
            signing_private=load_ed25519_private(
                bytes.fromhex(data["signing_private"])
            ),
            static_private=load_x25519_private(bytes.fromhex(data["static_private"])),
            nickname=data.get("nickname", "anon"),
        )

    @classmethod
    def load_or_create(
        cls, path: str | Path, nickname: str = "anon", passphrase: str | None = None
    ) -> "Identity":
        path = Path(path)
        if path.exists():
            return cls.load(path, passphrase)
        identity = cls.generate(nickname)
        identity.save(path, passphrase)
        return identity


@dataclass
class PeerIdentity:
    """A remote party's identity as we know it."""

    signing_public: bytes
    static_public: bytes
    nickname: str = ""
    verified: bool = False
    first_seen: float = 0.0

    @property
    def fingerprint(self) -> bytes:
        return fingerprint_from_keys(self.signing_public, self.static_public)

    @property
    def short_id(self) -> str:
        return self.fingerprint[:4].hex()

    def verify_transcript(self, handshake_hash: bytes, signature: bytes) -> bool:
        return verify(self.signing_public, signature, SIG_DOMAIN + handshake_hash)


class TrustStore:
    """Trust-on-first-use pinning of peer identities.

    Two rules, both of which bitchat's original ``Favorites`` implementation
    got wrong in one way or another:

    1. A peer is identified by its *key*, never by a nickname or a peer ID.
       Display names are cosmetic and are never used for lookup.
    2. Once pinned, a key never changes silently. A mismatch raises
       :class:`KeyChangedError` and the session is refused.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._peers: dict[bytes, PeerIdentity] = {}
        if self.path and self.path.exists():
            self._load()

    # -- lookup -----------------------------------------------------------

    def get(self, signing_public: bytes) -> PeerIdentity | None:
        return self._peers.get(signing_public)

    def by_short_id(self, short_id: str) -> PeerIdentity | None:
        for peer in self._peers.values():
            if peer.short_id == short_id:
                return peer
        return None

    def by_nickname(self, nickname: str) -> list[PeerIdentity]:
        """All peers using a nickname. A list, because nicknames are not unique.

        Callers must disambiguate by fingerprint. Treating a nickname as a
        unique handle is exactly the mistake that makes impersonation easy.
        """
        return [p for p in self._peers.values() if p.nickname == nickname]

    def all(self) -> list[PeerIdentity]:
        return list(self._peers.values())

    # -- pinning ----------------------------------------------------------

    def observe(
        self,
        signing_public: bytes,
        static_public: bytes,
        nickname: str = "",
        now: float = 0.0,
    ) -> PeerIdentity:
        """Record a peer seen in a completed, signature-verified handshake.

        Raises :class:`KeyChangedError` if the static key bound to a pinned
        identity key has changed.
        """
        existing = self._peers.get(signing_public)
        if existing is None:
            peer = PeerIdentity(
                signing_public=signing_public,
                static_public=static_public,
                nickname=nickname,
                verified=False,
                first_seen=now,
            )
            self._peers[signing_public] = peer
            self._save()
            return peer

        if existing.static_public != static_public:
            raise KeyChangedError(
                existing.nickname or existing.short_id,
                existing.static_public,
                static_public,
            )

        if nickname and nickname != existing.nickname:
            # A nickname change is cosmetic and allowed, but worth surfacing.
            existing.nickname = nickname
            self._save()
        return existing

    def mark_verified(self, signing_public: bytes) -> PeerIdentity:
        """Record that the user compared safety numbers out of band."""
        peer = self._peers.get(signing_public)
        if peer is None:
            raise TrustError("cannot verify an unknown peer")
        peer.verified = True
        self._save()
        return peer

    def repin(self, signing_public: bytes, static_public: bytes) -> PeerIdentity:
        """Deliberately accept a changed key, dropping verified status."""
        peer = self._peers.get(signing_public)
        if peer is None:
            raise TrustError("cannot re-pin an unknown peer")
        peer.static_public = static_public
        peer.verified = False
        self._save()
        return peer

    def forget(self, signing_public: bytes) -> None:
        self._peers.pop(signing_public, None)
        self._save()

    # -- persistence ------------------------------------------------------

    def _load(self) -> None:
        assert self.path is not None
        with open(self.path) as fh:
            for entry in json.load(fh).get("peers", []):
                peer = PeerIdentity(
                    signing_public=bytes.fromhex(entry["signing_public"]),
                    static_public=bytes.fromhex(entry["static_public"]),
                    nickname=entry.get("nickname", ""),
                    verified=entry.get("verified", False),
                    first_seen=entry.get("first_seen", 0.0),
                )
                self._peers[peer.signing_public] = peer

    def _save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        blob = {
            "v": 1,
            "peers": [
                {
                    "signing_public": p.signing_public.hex(),
                    "static_public": p.static_public.hex(),
                    "nickname": p.nickname,
                    "verified": p.verified,
                    "first_seen": p.first_seen,
                }
                for p in self._peers.values()
            ],
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "w") as fh:
            json.dump(blob, fh, indent=2)
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(tmp, self.path)


# Convenience aliases used across the codebase.
fingerprint = fingerprint_from_keys
