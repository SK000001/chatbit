"""Frame format, fragmentation, padding and tag tests."""

from __future__ import annotations

import pytest

from chatbit.crypto.primitives import random_bytes
from chatbit.wire import tags
from chatbit.wire.fragment import Reassembler, ReassemblyError, fragment
from chatbit.wire.packet import (
    BROADCAST_TAG,
    HEADER_LEN,
    Packet,
    PacketError,
    PacketType,
)
from chatbit.wire.padding import PaddingPolicy, capacity_for, padded_size


# ---------------------------------------------------------------------------
# packet
# ---------------------------------------------------------------------------


def make_packet(payload: bytes = b"hello", **kwargs) -> Packet:
    kwargs.setdefault("msg_id", random_bytes(8))
    return Packet(ptype=PacketType.DATA, payload=payload, **kwargs)


def test_round_trip():
    packet = make_packet(b"some ciphertext", ttl=5)
    decoded = Packet.decode(packet.encode())
    assert decoded.payload == b"some ciphertext"
    assert decoded.ttl == 5
    assert decoded.ptype == PacketType.DATA
    assert decoded.msg_id == packet.msg_id


def test_header_is_exactly_as_documented():
    packet = make_packet(b"")
    assert len(packet.encode()) == HEADER_LEN


def test_padding_is_stripped_exactly():
    packet = make_packet(b"short")
    decoded = Packet.decode(packet.encode(pad_to=200))
    assert decoded.payload == b"short", "padding leaked into the payload"


def test_padding_below_frame_size_is_refused():
    packet = make_packet(b"x" * 100)
    with pytest.raises(PacketError):
        packet.encode(pad_to=50)


def test_truncated_frame_is_rejected():
    with pytest.raises(PacketError):
        Packet.decode(b"\x01\x10\x07")


def test_lying_payload_length_is_rejected():
    """A frame claiming more payload than it carries must not over-read."""
    raw = bytearray(make_packet(b"abc").encode())
    raw[21:23] = (9999).to_bytes(2, "big")
    with pytest.raises(PacketError):
        Packet.decode(bytes(raw))


def test_unknown_version_is_rejected():
    raw = bytearray(make_packet().encode())
    raw[0] = 99
    with pytest.raises(PacketError):
        Packet.decode(bytes(raw))


def test_unknown_type_is_rejected():
    raw = bytearray(make_packet().encode())
    raw[1] = 0xEE
    with pytest.raises(PacketError):
        Packet.decode(bytes(raw))


def test_ttl_decrement_and_expiry():
    packet = make_packet(ttl=2)
    once = packet.decrement_ttl()
    assert once is not None and once.ttl == 1
    assert once.decrement_ttl() is None, "ttl 1 must not be forwarded again"


def test_invalid_fragment_metadata_is_rejected():
    with pytest.raises(PacketError):
        make_packet(frag_index=5, frag_count=3)


# ---------------------------------------------------------------------------
# fragmentation
# ---------------------------------------------------------------------------


def test_fragment_and_reassemble():
    payload = random_bytes(1000)
    capacity = capacity_for(200, HEADER_LEN)
    packets = fragment(
        PacketType.DATA, payload, random_bytes(8), capacity, BROADCAST_TAG
    )
    assert len(packets) > 1
    assert all(len(p.payload) <= capacity for p in packets)

    reassembler = Reassembler()
    result = None
    for packet in packets:
        result = reassembler.add(packet) or result
    assert result == payload


def test_reassembly_is_order_independent():
    payload = random_bytes(700)
    packets = fragment(
        PacketType.DATA, payload, random_bytes(8), 100, BROADCAST_TAG
    )
    reassembler = Reassembler()
    result = None
    for packet in reversed(packets):
        result = reassembler.add(packet) or result
    assert result == payload


def test_duplicate_fragments_are_tolerated():
    payload = random_bytes(300)
    packets = fragment(PacketType.DATA, payload, random_bytes(8), 100, BROADCAST_TAG)
    reassembler = Reassembler()
    result = None
    for packet in packets + packets:
        result = reassembler.add(packet) or result
    assert result == payload


def test_single_fragment_passes_straight_through():
    reassembler = Reassembler()
    packet = make_packet(b"tiny")
    assert reassembler.add(packet) == b"tiny"
    assert reassembler.pending_count == 0


def test_conflicting_fragment_metadata_is_rejected():
    msg_id = random_bytes(8)
    a = Packet(ptype=PacketType.DATA, payload=b"x", msg_id=msg_id, frag_index=0, frag_count=3)
    b = Packet(ptype=PacketType.DATA, payload=b"y", msg_id=msg_id, frag_index=1, frag_count=7)
    reassembler = Reassembler()
    reassembler.add(a)
    with pytest.raises(ReassemblyError):
        reassembler.add(b)


def test_reassembly_buffer_is_bounded():
    """A fragment flood must not grow memory without limit."""
    reassembler = Reassembler(max_pending=8)
    for _ in range(200):
        reassembler.add(
            Packet(
                ptype=PacketType.DATA,
                payload=random_bytes(50),
                msg_id=random_bytes(8),
                frag_index=0,
                frag_count=10,  # never completes
            )
        )
    assert reassembler.pending_count <= 8


def test_oversized_message_is_refused():
    reassembler = Reassembler(max_bytes=100)
    msg_id = random_bytes(8)
    with pytest.raises(ReassemblyError):
        for i in range(5):
            reassembler.add(
                Packet(
                    ptype=PacketType.DATA,
                    payload=random_bytes(50),
                    msg_id=msg_id,
                    frag_index=i,
                    frag_count=5,
                )
            )


def test_stale_partials_expire():
    reassembler = Reassembler(timeout=10.0)
    msg_id = random_bytes(8)
    reassembler.add(
        Packet(ptype=PacketType.DATA, payload=b"a", msg_id=msg_id,
               frag_index=0, frag_count=2),
        now=0.0,
    )
    assert reassembler.pending_count == 1
    reassembler.add(
        Packet(ptype=PacketType.DATA, payload=b"b", msg_id=random_bytes(8),
               frag_index=0, frag_count=2),
        now=100.0,
    )
    assert reassembler.pending_count == 1, "the stale partial should have expired"


# ---------------------------------------------------------------------------
# padding
# ---------------------------------------------------------------------------


def test_strict_padding_makes_every_frame_identical():
    assert padded_size(30, 200, PaddingPolicy.STRICT) == 200
    assert padded_size(199, 200, PaddingPolicy.STRICT) == 200


def test_bucket_padding_quantises():
    assert padded_size(30, 500, PaddingPolicy.BUCKET) == 32
    assert padded_size(33, 500, PaddingPolicy.BUCKET) == 64
    assert padded_size(200, 500, PaddingPolicy.BUCKET) == 256


def test_bucket_padding_never_exceeds_mtu():
    # 190 fits the 192 bucket, which is under the MTU.
    assert padded_size(190, 200, PaddingPolicy.BUCKET) == 192
    # 198's next bucket is 256, which overshoots, so it clamps to the MTU.
    assert padded_size(198, 200, PaddingPolicy.BUCKET) == 200


def test_no_padding_is_transparent():
    assert padded_size(37, 200, PaddingPolicy.NONE) == 37


def test_oversized_frame_is_refused():
    with pytest.raises(ValueError):
        padded_size(300, 200, PaddingPolicy.STRICT)


# ---------------------------------------------------------------------------
# tags
# ---------------------------------------------------------------------------


def test_tag_is_recognised_by_the_holder_only():
    key = random_bytes(32)
    other = random_bytes(32)
    tag = tags.compute_tag(key)
    assert tags.matches(tag, key)
    assert not tags.matches(tag, other)


def test_tag_rotates_between_epochs():
    key = random_bytes(32)
    early = tags.compute_tag(key, now=0.0)
    later = tags.compute_tag(key, now=tags.EPOCH_SECONDS * 50)
    assert early != later, "a tag that never changes is a durable identifier"


def test_clock_skew_of_one_epoch_is_tolerated():
    key = random_bytes(32)
    now = tags.EPOCH_SECONDS * 100
    previous = tags.compute_tag(key, now=now - tags.EPOCH_SECONDS)
    assert tags.matches(previous, key, now=now)


def test_distant_epochs_are_not_accepted():
    key = random_bytes(32)
    now = tags.EPOCH_SECONDS * 100
    ancient = tags.compute_tag(key, now=now - tags.EPOCH_SECONDS * 10)
    assert not tags.matches(ancient, key, now=now)


def test_handshake_tag_is_derived_from_the_public_key():
    static_pub = random_bytes(32)
    tag = tags.handshake_tag(static_pub)
    assert tags.matches(tag, static_pub, handshake=True)
    assert not tags.matches(tag, random_bytes(32), handshake=True)
