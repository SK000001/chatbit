"""On-air frame format.

Every frame that hits the radio has exactly this shape::

    offset  size  field
    ------  ----  ---------------------------------------------------------
     0       1    version        protocol version (currently 1)
     1       1    ptype          packet type, see PacketType
     2       1    ttl            hops remaining; decremented by each relay
     3       1    frag_index     0-based fragment number
     4       1    frag_count     total fragments in this logical message
     5       8    msg_id         random per logical message; used for dedup
    13       8    dst_tag        rotating recipient tag, or 8 zero bytes
    21       2    payload_len    true payload length, excluding padding
    23       N    payload        ciphertext, padded to the frame size

23 bytes of header. Everything a relay needs to do its job lives in the
header; everything else is opaque ciphertext. A relay can forward a frame
without learning who sent it, who it is for, or how big the real message is.

Two deliberate choices are worth calling out:

**No sender field.** Nothing in the header identifies the transmitter. Sender
identity lives inside the encrypted payload, where only the recipient can read
it. A passive listener sees frames appear, not who emitted them.

**`dst_tag` rotates.** Rather than addressing a stable peer ID -- which would
let anyone within radio range build a contact graph by logging headers -- the
tag is an epoch-keyed HMAC that only the intended recipient can recognise, and
which changes on its own every epoch. See :mod:`chatbit.wire.tags`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

__all__ = [
    "PacketType",
    "Packet",
    "PacketError",
    "HEADER_LEN",
    "BROADCAST_TAG",
    "MAX_TTL",
]

VERSION = 1
HEADER_LEN = 23
BROADCAST_TAG = b"\x00" * 8
MAX_TTL = 16
MAX_FRAGMENTS = 255

_HEADER = struct.Struct("!BBBBB8s8sH")


class PacketError(Exception):
    """A frame could not be parsed, or is invalid."""


class PacketType(IntEnum):
    # Noise XX, one type per handshake message so a receiver knows what to
    # feed the state machine without trial-parsing.
    HANDSHAKE_INIT = 0x01
    HANDSHAKE_RESP = 0x02
    HANDSHAKE_FIN = 0x03

    # Double-Ratchet-encrypted application data.
    DATA = 0x10

    # Unauthenticated presence announcement. Carries an identity key and a
    # signature, so it proves key possession but nothing about liveness --
    # treat it as a hint that someone is nearby, never as authentication.
    BEACON = 0x20

    # Chaff. Indistinguishable from DATA on the wire; dropped on receipt.
    COVER = 0x30

    # Delivery acknowledgement, carried inside a DATA frame's plaintext, so
    # this type only appears in tests and diagnostics.
    ACK = 0x40


@dataclass
class Packet:
    ptype: PacketType
    payload: bytes
    msg_id: bytes
    dst_tag: bytes = BROADCAST_TAG
    ttl: int = 7
    frag_index: int = 0
    frag_count: int = 1
    version: int = VERSION

    def __post_init__(self) -> None:
        if len(self.msg_id) != 8:
            raise PacketError("msg_id must be 8 bytes")
        if len(self.dst_tag) != 8:
            raise PacketError("dst_tag must be 8 bytes")
        if not 0 <= self.ttl <= MAX_TTL:
            raise PacketError(f"ttl must be 0..{MAX_TTL}")
        if not 1 <= self.frag_count <= MAX_FRAGMENTS:
            raise PacketError(f"frag_count must be 1..{MAX_FRAGMENTS}")
        if not 0 <= self.frag_index < self.frag_count:
            raise PacketError("frag_index out of range for frag_count")
        if len(self.payload) > 0xFFFF:
            raise PacketError("payload too large")

    @property
    def is_broadcast(self) -> bool:
        return self.dst_tag == BROADCAST_TAG

    @property
    def dedup_key(self) -> tuple[bytes, int]:
        return (self.msg_id, self.frag_index)

    def encode(self, pad_to: int = 0) -> bytes:
        """Serialise, optionally zero-padding the frame out to ``pad_to`` bytes.

        Padding is applied after the payload and is not covered by
        ``payload_len``, so the receiver strips it exactly.
        """
        header = _HEADER.pack(
            self.version,
            int(self.ptype),
            self.ttl,
            self.frag_index,
            self.frag_count,
            self.msg_id,
            self.dst_tag,
            len(self.payload),
        )
        frame = header + self.payload
        if pad_to:
            if len(frame) > pad_to:
                raise PacketError(
                    f"frame is {len(frame)} bytes, cannot pad down to {pad_to}"
                )
            frame += b"\x00" * (pad_to - len(frame))
        return frame

    @classmethod
    def decode(cls, raw: bytes) -> "Packet":
        if len(raw) < HEADER_LEN:
            raise PacketError(f"frame shorter than {HEADER_LEN}-byte header")
        (
            version,
            ptype,
            ttl,
            frag_index,
            frag_count,
            msg_id,
            dst_tag,
            payload_len,
        ) = _HEADER.unpack(raw[:HEADER_LEN])

        if version != VERSION:
            raise PacketError(f"unsupported protocol version {version}")
        if HEADER_LEN + payload_len > len(raw):
            raise PacketError("payload_len runs past the end of the frame")
        try:
            parsed_type = PacketType(ptype)
        except ValueError as exc:
            raise PacketError(f"unknown packet type 0x{ptype:02x}") from exc

        return cls(
            ptype=parsed_type,
            payload=raw[HEADER_LEN : HEADER_LEN + payload_len],
            msg_id=msg_id,
            dst_tag=dst_tag,
            ttl=ttl,
            frag_index=frag_index,
            frag_count=frag_count,
            version=version,
        )

    def decrement_ttl(self) -> "Packet | None":
        """Return a copy with ttl-1, or ``None`` if the frame has expired."""
        if self.ttl <= 1:
            return None
        return Packet(
            ptype=self.ptype,
            payload=self.payload,
            msg_id=self.msg_id,
            dst_tag=self.dst_tag,
            ttl=self.ttl - 1,
            frag_index=self.frag_index,
            frag_count=self.frag_count,
            version=self.version,
        )
