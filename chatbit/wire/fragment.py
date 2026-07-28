"""Fragmentation and reassembly.

A LoRa frame carries at most 255 bytes, and at the slow spreading factors you
need for long range, a single 255-byte frame occupies the channel for over a
second. Anything longer than a one-line message has to be split.

Relays forward fragments individually and never reassemble -- a relay has no
key material and nothing to gain from holding a partial message. Reassembly
happens only at the destination.

The reassembly buffer is the obvious denial-of-service target: an attacker can
transmit fragment 3-of-200 for thousands of random message IDs and watch memory
climb. It is bounded three ways -- a cap on in-flight messages, a cap on bytes
per message, and a timeout after which a partial message is dropped.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .packet import MAX_FRAGMENTS, Packet, PacketError, PacketType

__all__ = ["fragment", "Reassembler", "ReassemblyError"]

# Bounds on the reassembly buffer.
MAX_PENDING_MESSAGES = 64
MAX_MESSAGE_BYTES = 64 * 1024
REASSEMBLY_TIMEOUT = 300.0  # seconds


class ReassemblyError(Exception):
    """A fragment could not be accepted."""


def fragment(
    ptype: PacketType,
    payload: bytes,
    msg_id: bytes,
    capacity: int,
    dst_tag: bytes,
    ttl: int = 7,
) -> list[Packet]:
    """Split ``payload`` into packets whose payloads each fit in ``capacity``.

    ``capacity`` is the per-frame payload budget, i.e. link MTU minus
    :data:`~chatbit.wire.packet.HEADER_LEN`.
    """
    if capacity <= 0:
        raise ValueError("capacity must be positive")

    chunks = [payload[i : i + capacity] for i in range(0, len(payload), capacity)] or [b""]
    if len(chunks) > MAX_FRAGMENTS:
        raise ValueError(
            f"message needs {len(chunks)} fragments, limit is {MAX_FRAGMENTS}"
        )

    return [
        Packet(
            ptype=ptype,
            payload=chunk,
            msg_id=msg_id,
            dst_tag=dst_tag,
            ttl=ttl,
            frag_index=i,
            frag_count=len(chunks),
        )
        for i, chunk in enumerate(chunks)
    ]


@dataclass
class _Partial:
    frag_count: int
    ptype: PacketType
    fragments: dict[int, bytes] = field(default_factory=dict)
    total_bytes: int = 0
    first_seen: float = 0.0

    @property
    def complete(self) -> bool:
        return len(self.fragments) == self.frag_count

    def assemble(self) -> bytes:
        return b"".join(self.fragments[i] for i in range(self.frag_count))


class Reassembler:
    """Collects fragments until a logical message is whole."""

    def __init__(
        self,
        max_pending: int = MAX_PENDING_MESSAGES,
        max_bytes: int = MAX_MESSAGE_BYTES,
        timeout: float = REASSEMBLY_TIMEOUT,
    ) -> None:
        self.max_pending = max_pending
        self.max_bytes = max_bytes
        self.timeout = timeout
        self._pending: dict[bytes, _Partial] = {}

    def add(self, packet: Packet, now: float | None = None) -> bytes | None:
        """Feed in a fragment. Returns the full payload once complete."""
        now = now if now is not None else time.monotonic()
        self._expire(now)

        if packet.frag_count == 1:
            return packet.payload

        partial = self._pending.get(packet.msg_id)
        if partial is None:
            if len(self._pending) >= self.max_pending:
                # Drop the oldest rather than refusing new traffic outright:
                # a flood should degrade delivery, not stop it dead.
                oldest = min(self._pending, key=lambda k: self._pending[k].first_seen)
                del self._pending[oldest]
            partial = _Partial(
                frag_count=packet.frag_count,
                ptype=packet.ptype,
                first_seen=now,
            )
            self._pending[packet.msg_id] = partial

        if partial.frag_count != packet.frag_count or partial.ptype != packet.ptype:
            # Two frames sharing a msg_id but disagreeing about the message
            # they belong to. One of them is forged; we cannot tell which, so
            # discard the whole thing.
            del self._pending[packet.msg_id]
            raise ReassemblyError("inconsistent fragment metadata for msg_id")

        if packet.frag_index in partial.fragments:
            return None  # duplicate fragment, already have it

        if partial.total_bytes + len(packet.payload) > self.max_bytes:
            del self._pending[packet.msg_id]
            raise ReassemblyError("reassembled message would exceed the size limit")

        partial.fragments[packet.frag_index] = packet.payload
        partial.total_bytes += len(packet.payload)

        if partial.complete:
            del self._pending[packet.msg_id]
            return partial.assemble()
        return None

    def _expire(self, now: float) -> None:
        stale = [
            mid
            for mid, p in self._pending.items()
            if now - p.first_seen > self.timeout
        ]
        for mid in stale:
            del self._pending[mid]

    @property
    def pending_count(self) -> int:
        return len(self._pending)
