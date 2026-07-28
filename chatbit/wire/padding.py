"""Length padding.

Ciphertext hides content. It does not hide length, and length leaks more than
people expect: "yes"/"no" replies, whether a message carries a photo, which of
two known documents was sent, the rhythm of a conversation.

bitchat's whitepaper describes frames as "fixed-size where possible". This
module makes that a policy you choose explicitly and can reason about, because
"where possible" is not a threat model.

Policies
--------

``STRICT``
    Every frame is padded to the full link MTU. On air, all frames are
    identical in size, so length carries exactly zero information. Costs
    bandwidth -- on a slow LoRa link, a lot of it. This is the default,
    because a chat protocol's frames are small and mostly padding anyway.

``BUCKET``
    Pad up to the next size in a geometric ladder. Leaks the bucket, which is
    roughly log2 of the length. A reasonable compromise when airtime is
    genuinely scarce.

``NONE``
    No padding. Only sensible over a transport where length is already
    observable at a lower layer, or for debugging.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["PaddingPolicy", "padded_size", "capacity_for"]


class PaddingPolicy(str, Enum):
    STRICT = "strict"
    BUCKET = "bucket"
    NONE = "none"


# Geometric ladder used by BUCKET, in bytes of total frame size.
_BUCKETS = (32, 64, 96, 128, 192, 256, 384, 512, 768, 1024)


def padded_size(frame_len: int, mtu: int, policy: PaddingPolicy) -> int:
    """The on-air size a frame of ``frame_len`` bytes should be padded to."""
    if frame_len > mtu:
        raise ValueError(f"frame of {frame_len} bytes exceeds MTU {mtu}")

    if policy is PaddingPolicy.NONE:
        return frame_len
    if policy is PaddingPolicy.STRICT:
        return mtu

    for bucket in _BUCKETS:
        if bucket >= frame_len:
            return min(bucket, mtu)
    return mtu


def capacity_for(mtu: int, header_len: int) -> int:
    """Payload bytes available per frame."""
    capacity = mtu - header_len
    if capacity <= 0:
        raise ValueError(f"MTU {mtu} is too small for a {header_len}-byte header")
    return capacity
