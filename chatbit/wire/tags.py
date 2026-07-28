"""Rotating recipient tags ("who is this for?" without saying who).

A mesh relay has to decide whether a frame is worth forwarding, and a receiver
has to decide whether a frame is worth trying to decrypt. The obvious way to
support that is a destination address in the header -- and the obvious way is
also a gift to anyone with a radio and patience, because a stable address in
the clear is a stable identifier. Log headers for a week and you have a social
graph and a movement history, without breaking any encryption at all.

Instead, each frame carries an 8-byte tag::

    dst_tag = HMAC-SHA256(tag_key, "chatbit/v1 tag" || epoch)[:8]

where ``epoch = floor(unix_time / EPOCH_SECONDS)``. Only someone holding
``tag_key`` can compute or recognise the tag, and it changes by itself every
epoch, so frames for the same recipient are unlinkable across epochs.

Two kinds of tag key are used:

* **Session tags** key off the established session's dedicated tag secret. This
  is the strong case: the tag is meaningless to anyone outside the session.
* **Handshake tags** key off the responder's static public key, because there
  is no session yet. Anyone who already knows that public key can recognise
  these -- which is an acknowledged, documented limitation, not a claim of
  anonymity. It bounds the exposure to people who already know who you are.

Receivers accept the neighbouring epochs as well as the current one, so a
minute or two of clock skew does not silently drop traffic.
"""

from __future__ import annotations

import time

from ..crypto.primitives import constant_time_eq, hmac_sha256

__all__ = [
    "EPOCH_SECONDS",
    "compute_tag",
    "handshake_tag",
    "acceptable_tags",
    "matches",
]

# 10 minutes. Short enough that a tag is not a durable identifier, long enough
# that a slow multi-hop store-and-forward delivery still lands in a window the
# receiver accepts.
EPOCH_SECONDS = 600

# How many epochs either side of "now" a receiver will accept.
EPOCH_SKEW = 1

_TAG_DOMAIN = b"chatbit/v1 tag"
_HANDSHAKE_DOMAIN = b"chatbit/v1 handshake-tag"


def current_epoch(now: float | None = None) -> int:
    return int((now if now is not None else time.time()) // EPOCH_SECONDS)


def compute_tag(tag_key: bytes, epoch: int | None = None, now: float | None = None) -> bytes:
    if epoch is None:
        epoch = current_epoch(now)
    return hmac_sha256(tag_key, _TAG_DOMAIN + epoch.to_bytes(8, "big"))[:8]


def handshake_tag(
    responder_static_pub: bytes, epoch: int | None = None, now: float | None = None
) -> bytes:
    """Tag addressed to a peer we have no session with yet."""
    if epoch is None:
        epoch = current_epoch(now)
    return hmac_sha256(
        responder_static_pub, _HANDSHAKE_DOMAIN + epoch.to_bytes(8, "big")
    )[:8]


def acceptable_tags(
    tag_key: bytes, now: float | None = None, handshake: bool = False
) -> set[bytes]:
    """Every tag we should currently recognise, allowing for clock skew."""
    epoch = current_epoch(now)
    fn = handshake_tag if handshake else compute_tag
    return {
        fn(tag_key, epoch + delta) for delta in range(-EPOCH_SKEW, EPOCH_SKEW + 1)
    }


def matches(tag: bytes, tag_key: bytes, now: float | None = None, handshake: bool = False) -> bool:
    """Constant-time check of a received tag against our accepted set."""
    hit = False
    for candidate in acceptable_tags(tag_key, now, handshake):
        # Compare all candidates rather than short-circuiting, so the time
        # taken does not reveal which epoch matched.
        hit |= constant_time_eq(tag, candidate)
    return hit
