"""Store-and-forward: holding traffic for peers that are not reachable yet.

This is what makes a mesh work across a disconnected crowd rather than only
within one radio bubble. A node that cannot transmit right now -- because the
duty-cycle governor said no, or the radio is busy, or nobody is in range --
keeps the frame and replays it later.

The code existed from the start and nothing exercised it, which is its own
kind of bug: an untested recovery path is a recovery path you find out about
during the emergency.
"""

from __future__ import annotations

import asyncio

import pytest

from chatbit.config import MeshConfig
from chatbit.crypto.primitives import random_bytes
from chatbit.mesh.router import Router
from chatbit.radio.base import TransportError
from chatbit.wire.packet import BROADCAST_TAG, Packet, PacketType

pytestmark = pytest.mark.asyncio


def make_packet(ttl: int = 7, **kwargs) -> Packet:
    kwargs.setdefault("msg_id", random_bytes(8))
    return Packet(
        ptype=PacketType.DATA,
        payload=b"opaque ciphertext",
        dst_tag=BROADCAST_TAG,
        ttl=ttl,
        **kwargs,
    )


class FlakyLink:
    """A send function that fails while 'off air' and records what got out."""

    def __init__(self) -> None:
        self.on_air = False
        self.sent: list[Packet] = []
        self.attempts = 0

    async def send(self, packet: Packet) -> None:
        self.attempts += 1
        if not self.on_air:
            raise TransportError("radio unavailable")
        self.sent.append(packet)


def build_router(link: FlakyLink, **mesh_kwargs) -> Router:
    config = MeshConfig(
        relay_jitter_min=0.001,
        relay_jitter_max=0.002,
        **mesh_kwargs,
    )

    async def deliver(packet: Packet) -> None:
        return None

    return Router(
        config=config,
        send=link.send,
        is_for_us=lambda p: False,
        deliver=deliver,
    )


async def test_failed_relay_is_stored_then_replayed():
    """The core cycle: cannot send now, held, delivered when the link returns."""
    link = FlakyLink()
    router = build_router(link)

    await router.handle(make_packet())
    await asyncio.sleep(0.05)  # let the jittered relay fire and fail

    assert router.stored_count == 1, "an unsendable relay should have been stored"
    assert link.sent == []

    link.on_air = True
    replayed = await router.replay_store()

    assert replayed == 1
    assert len(link.sent) == 1
    assert router.stored_count == 0, "a replayed frame should not be held twice"

    await router.shutdown()


async def test_frames_are_held_while_the_link_stays_down():
    link = FlakyLink()
    router = build_router(link)

    for _ in range(5):
        await router.handle(make_packet())
    await asyncio.sleep(0.06)

    assert router.stored_count == 5

    # Still down: replay attempts must not silently discard the backlog.
    assert await router.replay_store() == 0
    assert router.stored_count == 5

    link.on_air = True
    assert await router.replay_store() == 5
    assert router.stored_count == 0

    await router.shutdown()


async def test_store_respects_capacity():
    """A long outage must not grow memory without bound."""
    link = FlakyLink()
    router = build_router(link, store_capacity=3)

    for _ in range(20):
        await router.handle(make_packet())
    await asyncio.sleep(0.1)

    assert router.stored_count == 3, "store exceeded its configured capacity"

    await router.shutdown()


async def test_stale_frames_are_purged():
    """Held traffic expires rather than being replayed indefinitely."""
    link = FlakyLink()
    router = build_router(link, store_ttl_seconds=60.0)

    router.store(make_packet(), now=0.0)
    router.store(make_packet(), now=0.0)
    router.store(make_packet(), now=1000.0)
    assert router.stored_count == 3

    purged = router.purge_store(now=1000.0)
    assert purged == 2, "frames older than the TTL should have been dropped"
    assert router.stored_count == 1

    await router.shutdown()


async def test_expired_frames_are_not_replayed():
    link = FlakyLink()
    router = build_router(link, store_ttl_seconds=60.0)

    router.store(make_packet(), now=0.0)
    link.on_air = True

    replayed = await router.replay_store(now=5000.0)
    assert replayed == 0, "an expired frame should not go on air"
    assert link.sent == []

    await router.shutdown()


async def test_store_forward_can_be_disabled():
    link = FlakyLink()
    router = build_router(link, store_forward=False)

    await router.handle(make_packet())
    await asyncio.sleep(0.05)

    assert router.stored_count == 0, "storing while disabled"
    assert link.sent == []

    await router.shutdown()


async def test_stored_frames_keep_their_decremented_ttl():
    """A held frame must not regain hops while it waits.

    Otherwise a frame parked in a store-and-forward node comes back with a
    fresh hop budget and can circulate further than its TTL allows.
    """
    link = FlakyLink()
    router = build_router(link)

    await router.handle(make_packet(ttl=4))
    await asyncio.sleep(0.05)
    assert router.stored_count == 1

    link.on_air = True
    await router.replay_store()

    assert len(link.sent) == 1
    assert link.sent[0].ttl == 3, "stored frame did not keep its decremented TTL"

    await router.shutdown()


async def test_expired_ttl_is_never_stored():
    """A frame at the end of its life is dropped, not held for later."""
    link = FlakyLink()
    router = build_router(link)

    await router.handle(make_packet(ttl=1))
    await asyncio.sleep(0.05)

    assert router.stored_count == 0
    assert router.stats.expired == 1
    assert link.attempts == 0, "an expired frame should not even be attempted"

    await router.shutdown()
