"""End-to-end tests: real handshakes and messages over a simulated radio."""

from __future__ import annotations

import asyncio
import random

import pytest

from chatbit.config import MeshConfig, NodeConfig, RadioConfig
from chatbit.crypto.identity import Identity, TrustStore
from chatbit.node import IncomingMessage, Node
from chatbit.radio.loopback import LoopbackTransport, Medium
from chatbit.wire.padding import PaddingPolicy

pytestmark = pytest.mark.asyncio


def make_config(nickname: str, **mesh_kwargs) -> NodeConfig:
    return NodeConfig(
        nickname=nickname,
        transport="loopback",
        radio=RadioConfig(region="EU868", frequency_hz=868_100_000, mtu=200),
        mesh=MeshConfig(
            relay_jitter_min=0.001,
            relay_jitter_max=0.005,
            padding=PaddingPolicy.STRICT,
            **mesh_kwargs,
        ),
    )


class Harness:
    """A node plus its inbox, wired to a shared medium."""

    def __init__(self, name: str, medium: Medium, mtu: int = 200, **mesh_kwargs):
        self.name = name
        self.inbox: list[IncomingMessage] = []
        self.events: list[str] = []
        self.transport = LoopbackTransport(medium, name=name, mtu=mtu)
        self.node = Node(
            config=make_config(name, **mesh_kwargs),
            transport=self.transport,
            identity=Identity.generate(name),
            trust=TrustStore(None),
            on_message=self._on_message,
            on_event=self.events.append,
        )

    async def _on_message(self, message: IncomingMessage) -> None:
        self.inbox.append(message)

    @property
    def identity(self) -> Identity:
        return self.node.identity


async def settle(seconds: float = 0.4) -> None:
    """Let jittered relays and background tasks run to completion."""
    await asyncio.sleep(seconds)


async def handshake(a: Harness, b: Harness) -> None:
    await a.node.connect(b.identity.static_public)
    await settle()


@pytest.fixture
async def pair():
    medium = Medium()
    a, b = Harness("alice", medium), Harness("bob", medium)
    await a.node.start()
    await b.node.start()
    yield a, b
    await a.node.stop()
    await b.node.stop()


async def test_handshake_establishes_mutual_session(pair):
    a, b = pair
    await handshake(a, b)

    sa = a.node.sessions.session_for(b.identity.signing_public)
    sb = b.node.sessions.session_for(a.identity.signing_public)
    assert sa is not None, "initiator has no session"
    assert sb is not None, "responder has no session"

    # Each side learned the other's real static key.
    assert sa.peer.static_public == b.identity.static_public
    assert sb.peer.static_public == a.identity.static_public

    # Both sides compute the same safety number.
    assert a.node.safety_number_with(
        b.identity.signing_public
    ) == b.node.safety_number_with(a.identity.signing_public)


async def test_text_round_trip(pair):
    a, b = pair
    await handshake(a, b)

    assert await a.node.send_text(b.identity.signing_public, "meet at the bridge")
    await settle()
    assert [m.text for m in b.inbox] == ["meet at the bridge"]

    assert await b.node.send_text(a.identity.signing_public, "understood")
    await settle()
    assert [m.text for m in a.inbox] == ["understood"]


async def test_message_longer_than_mtu_is_fragmented(pair):
    a, b = pair
    await handshake(a, b)

    long_text = "the quick brown fox " * 40  # ~800 bytes, well over the 200 B MTU
    assert await a.node.send_text(b.identity.signing_public, long_text)
    await settle(0.8)
    assert [m.text for m in b.inbox] == [long_text]


async def test_every_frame_is_mtu_sized_under_strict_padding():
    """Traffic analysis defence: on-air frames must not vary in length."""
    medium = Medium()
    sizes: list[int] = []

    a, b = Harness("alice", medium), Harness("bob", medium)
    original_send = a.transport.send

    async def recording_send(frame: bytes) -> None:
        sizes.append(len(frame))
        await original_send(frame)

    a.transport.send = recording_send  # type: ignore[method-assign]

    await a.node.start()
    await b.node.start()
    try:
        await handshake(a, b)
        await a.node.send_text(b.identity.signing_public, "x")
        await a.node.send_text(b.identity.signing_public, "a much longer message " * 10)
        await settle()
    finally:
        await a.node.stop()
        await b.node.stop()

    assert sizes, "no frames were transmitted"
    assert set(sizes) == {200}, f"frame sizes leaked message length: {sorted(set(sizes))}"


async def test_multi_hop_relay():
    """Alice and Carol cannot hear each other; Bob relays between them."""
    medium = Medium()
    medium.topology = {
        "alice": {"bob"},
        "bob": {"alice", "carol"},
        "carol": {"bob"},
    }
    a = Harness("alice", medium)
    b = Harness("bob", medium)
    c = Harness("carol", medium)
    for h in (a, b, c):
        await h.node.start()
    try:
        assert not medium.can_hear("alice", "carol")

        await a.node.connect(c.identity.static_public)
        await settle(1.0)

        session = a.node.sessions.session_for(c.identity.signing_public)
        assert session is not None, "handshake did not survive the relay hop"

        await a.node.send_text(c.identity.signing_public, "relayed hello")
        await settle(1.0)
        assert [m.text for m in c.inbox] == ["relayed hello"]

        # Bob forwarded the traffic without being able to read it.
        assert b.inbox == []
        assert b.node.router.stats.relayed > 0
    finally:
        for h in (a, b, c):
            await h.node.stop()


async def test_relay_does_not_storm():
    """Dedup must stop a frame circulating forever in a dense mesh."""
    medium = Medium()
    nodes = [Harness(f"n{i}", medium) for i in range(5)]
    for h in nodes:
        await h.node.start()
    try:
        await nodes[0].node.broadcast_beacon()
        await settle(1.0)
        # 5 fully-connected nodes: 1 origin + at most 4 relays per fragment.
        assert medium.frames_sent <= 12, f"flood amplified to {medium.frames_sent} frames"
        for h in nodes[1:]:
            assert nodes[0].identity.signing_public in h.node.discovered
    finally:
        for h in nodes:
            await h.node.stop()


async def test_delivery_survives_packet_loss():
    """A handshake completes over a lossy link, given retries.

    The retry budget is not arbitrary. A handshake needs three frames to land
    in one attempt -- the INIT, plus both fragments of the 228-byte Noise
    message 2 -- so at 25% loss a single attempt succeeds only
    0.75 * 0.75**2 = 42% of the time. Six attempts leaves a 3.7% chance of
    failure per run, which across a 13-job CI matrix is a 39% chance of a red
    build from nothing but bad luck. Twenty attempts puts it below 1 in 40,000.

    The medium is also seeded, so the drop pattern is reproducible rather than
    differing on every run and platform.
    """
    medium = Medium(loss=0.25, rng=random.Random(20260728))
    a, b = Harness("alice", medium), Harness("bob", medium)
    await a.node.start()
    await b.node.start()
    try:
        for _ in range(20):
            await a.node.connect(b.identity.static_public)
            await settle(0.3)
            if a.node.sessions.session_for(b.identity.signing_public):
                break
        assert a.node.sessions.session_for(b.identity.signing_public) is not None
        assert medium.frames_dropped > 0, "loss was configured but nothing dropped"
    finally:
        await a.node.stop()
        await b.node.stop()


async def test_relay_cannot_read_traffic(pair):
    """A relay sees only opaque frames -- no plaintext, no identities."""
    a, b = pair
    await handshake(a, b)

    captured: list[bytes] = []
    original = a.transport.send

    async def capture(frame: bytes) -> None:
        captured.append(frame)
        await original(frame)

    a.transport.send = capture  # type: ignore[method-assign]
    secret = "the password is hunter2"
    await a.node.send_text(b.identity.signing_public, secret)
    await settle()

    assert captured
    blob = b"".join(captured)
    assert secret.encode() not in blob
    assert a.identity.signing_public not in blob
    assert b.identity.signing_public not in blob
    assert a.identity.static_public not in blob
    assert b.identity.static_public not in blob
