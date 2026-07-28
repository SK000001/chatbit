"""The chatbit node.

Ties together the transport, the mesh router, session management,
fragmentation and padding into something you can send a message with.

Inbound path::

    transport -> Packet.decode -> Router.handle
                                    |-- addressed to us? -> reassemble -> decrypt
                                    `-- relay (jittered, dedup'd, TTL'd)

Outbound path::

    text -> session.encrypt -> fragment -> pad -> Router.originate -> transport
"""

from __future__ import annotations

import asyncio
import contextlib
import random
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Awaitable, Callable

from .config import NodeConfig
from .crypto.identity import Identity, KeyChangedError, PeerIdentity, TrustStore, safety_number
from .crypto.primitives import random_bytes
from .mesh.router import Router
from .radio.base import ReceivedFrame, Transport
from .session import Session, SessionError, SessionManager
from .wire import tags
from .wire.fragment import Reassembler, ReassemblyError, fragment
from .wire.packet import BROADCAST_TAG, HEADER_LEN, Packet, PacketError, PacketType
from .wire.padding import capacity_for, padded_size

__all__ = ["Node", "IncomingMessage", "MessageKind"]


class MessageKind(IntEnum):
    TEXT = 1
    ACK = 2
    NICK = 3


@dataclass
class IncomingMessage:
    peer: PeerIdentity
    kind: MessageKind
    text: str
    timestamp: float
    verified: bool
    rssi: float | None = None

    @property
    def display_name(self) -> str:
        mark = "✓" if self.verified else "?"
        nick = self.peer.nickname or self.peer.short_id
        return f"{nick}#{self.peer.short_id}{mark}"


def _encode_message(kind: MessageKind, body: bytes) -> bytes:
    return bytes([int(kind)]) + struct.pack("!d", time.time()) + body


def _decode_message(blob: bytes) -> tuple[MessageKind, float, bytes]:
    if len(blob) < 9:
        raise ValueError("message envelope too short")
    kind = MessageKind(blob[0])
    (timestamp,) = struct.unpack("!d", blob[1:9])
    return kind, timestamp, blob[9:]


@dataclass
class NodeStats:
    beacons_sent: int = 0
    beacons_received: int = 0
    cover_sent: int = 0
    handshakes_started: int = 0
    handshakes_completed: int = 0
    handshakes_failed: int = 0
    messages_sent: int = 0
    messages_received: int = 0
    decrypt_failures: int = 0


class Node:
    def __init__(
        self,
        config: NodeConfig,
        transport: Transport,
        identity: Identity | None = None,
        trust: TrustStore | None = None,
        on_message: Callable[[IncomingMessage], Awaitable[None]] | None = None,
        on_event: Callable[[str], None] | None = None,
    ) -> None:
        config.validate()
        self.config = config
        self.transport = transport
        self.identity = identity or Identity.load_or_create(
            config.expanded_identity_path(), config.nickname
        )
        self.trust = trust if trust is not None else TrustStore(config.expanded_trust_path())
        self.sessions = SessionManager(self.identity, self.trust)
        self.reassembler = Reassembler()
        self.stats = NodeStats()
        self.rng = random.Random()

        self._on_message = on_message
        self._on_event = on_event or (lambda msg: None)
        self._running = False
        self._tasks: list[asyncio.Task] = []

        self.router = Router(
            config=config.mesh,
            send=self._transmit,
            is_for_us=self._is_for_us,
            deliver=self._deliver,
            rng=self.rng,
        )

        self.capacity = capacity_for(transport.mtu, HEADER_LEN)
        #: Peers heard via beacons but not yet in a session.
        self.discovered: dict[bytes, PeerIdentity] = {}

    # -- lifecycle --------------------------------------------------------

    async def start(self) -> None:
        await self.transport.start()
        self._running = True
        self._tasks = [
            asyncio.create_task(self._receive_loop()),
            asyncio.create_task(self._beacon_loop()),
        ]
        if self.config.mesh.cover_traffic:
            self._tasks.append(asyncio.create_task(self._cover_loop()))
        self._event(f"node up as {self.identity.nickname}#{self.identity.short_id}")

    async def stop(self) -> None:
        self._running = False
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        await self.router.shutdown()
        await self.transport.stop()

    async def __aenter__(self) -> "Node":
        await self.start()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.stop()

    # -- transmit ---------------------------------------------------------

    async def _transmit(self, packet: Packet) -> None:
        frame = packet.encode()
        target = padded_size(len(frame), self.transport.mtu, self.config.mesh.padding)
        await self.transport.send(packet.encode(pad_to=target))

    async def _emit(
        self, ptype: PacketType, payload: bytes, dst_tag: bytes, ttl: int | None = None
    ) -> None:
        """Fragment, pad and originate a logical message."""
        packets = fragment(
            ptype=ptype,
            payload=payload,
            msg_id=random_bytes(8),
            capacity=self.capacity,
            dst_tag=dst_tag,
            ttl=ttl if ttl is not None else self.config.mesh.default_ttl,
        )
        for packet in packets:
            await self.router.originate(packet)

    # -- public API -------------------------------------------------------

    async def connect(self, peer_static_public: bytes) -> None:
        """Begin a handshake with a peer whose static key we know."""
        payload, dst_tag = self.sessions.start_handshake(peer_static_public)
        self.stats.handshakes_started += 1
        await self._emit(PacketType.HANDSHAKE_INIT, payload, dst_tag)

    async def send_text(self, signing_public: bytes, text: str) -> bool:
        """Send a text message to an established peer. False if no session."""
        session = self.sessions.session_for(signing_public)
        if session is None:
            return False
        blob = session.encrypt(_encode_message(MessageKind.TEXT, text.encode()))
        await self._emit(PacketType.DATA, blob, session.current_send_tag())
        self.stats.messages_sent += 1
        return True

    async def broadcast_beacon(self) -> None:
        """Announce our identity so nearby nodes can start a handshake.

        A beacon proves possession of the identity key (it is signed) but says
        nothing about liveness -- it can be recorded and replayed. It is a
        discovery hint, never authentication. All real authentication happens
        in the handshake.
        """
        timestamp = struct.pack("!d", time.time())
        body = self.identity.signing_public + self.identity.static_public + timestamp
        signature = self.identity.sign_transcript(body)
        nickname = self.identity.nickname.encode()[:64]
        payload = body + signature + bytes([len(nickname)]) + nickname
        await self._emit(PacketType.BEACON, payload, BROADCAST_TAG)
        self.stats.beacons_sent += 1

    def safety_number_with(self, signing_public: bytes) -> str | None:
        """The 60-digit number both sides compare out of band to detect a MITM."""
        peer = self.trust.get(signing_public)
        if peer is None:
            return None
        return safety_number(self.identity.fingerprint, peer.fingerprint)

    # -- receive ----------------------------------------------------------

    async def _receive_loop(self) -> None:
        try:
            async for frame in self.transport.frames():
                if not self._running:
                    break
                try:
                    packet = Packet.decode(frame.data)
                except PacketError:
                    continue  # noise on the channel, or another protocol
                self._last_rssi = frame.rssi
                with contextlib.suppress(Exception):
                    await self.router.handle(packet)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover
            self._event(f"receive loop stopped: {exc}")

    def _is_for_us(self, packet: Packet) -> bool:
        if packet.is_broadcast:
            return True
        # A handshake opening addressed to our static key.
        if packet.ptype == PacketType.HANDSHAKE_INIT and tags.matches(
            packet.dst_tag, self.identity.static_public, handshake=True
        ):
            return True
        return self.sessions.session_by_tag(packet.dst_tag) is not None

    async def _deliver(self, packet: Packet) -> None:
        try:
            payload = self.reassembler.add(packet)
        except ReassemblyError:
            return
        if payload is None:
            return  # still waiting on fragments

        try:
            if packet.ptype == PacketType.HANDSHAKE_INIT:
                await self._on_handshake_init(payload)
            elif packet.ptype == PacketType.HANDSHAKE_RESP:
                await self._on_handshake_resp(payload)
            elif packet.ptype == PacketType.HANDSHAKE_FIN:
                await self._on_handshake_fin(payload)
            elif packet.ptype == PacketType.BEACON:
                await self._on_beacon(payload)
            elif packet.ptype == PacketType.DATA:
                await self._on_data(packet, payload)
        except KeyChangedError as exc:
            self.stats.handshakes_failed += 1
            self._event(f"REFUSED: {exc}")
        except SessionError as exc:
            self.stats.handshakes_failed += 1
            self._event(f"session error: {exc}")

    async def _on_handshake_init(self, payload: bytes) -> None:
        response = self.sessions.handle_init(payload)
        if response is None:
            return
        # The responder does not know the initiator's static key yet, so this
        # cannot be tag-addressed. It goes out broadcast and the initiator
        # picks it up by handshake ID.
        await self._emit(PacketType.HANDSHAKE_RESP, response, BROADCAST_TAG)

    async def _on_handshake_resp(self, payload: bytes) -> None:
        result = self.sessions.handle_response(payload)
        if result is None:
            return
        fin_payload, session = result
        await self._emit(PacketType.HANDSHAKE_FIN, fin_payload, BROADCAST_TAG)
        self.stats.handshakes_completed += 1
        self._announce_session(session)

    async def _on_handshake_fin(self, payload: bytes) -> None:
        session = self.sessions.handle_fin(payload)
        if session is None:
            return
        self.stats.handshakes_completed += 1
        self._announce_session(session)

    def _announce_session(self, session: Session) -> None:
        peer = session.peer
        mark = "verified" if peer.verified else "UNVERIFIED"
        self._event(
            f"session established with {peer.nickname or '(no nick)'}"
            f"#{peer.short_id} [{mark}]"
        )
        if not peer.verified:
            self._event(
                f"  compare safety number out of band: "
                f"{safety_number(self.identity.fingerprint, peer.fingerprint)}"
            )

    async def _on_beacon(self, payload: bytes) -> None:
        if len(payload) < 32 + 32 + 8 + 64 + 1:
            return
        signing_pub = payload[0:32]
        static_pub = payload[32:64]
        body = payload[0:72]
        signature = payload[72:136]
        nick_len = payload[136]
        nickname = payload[137 : 137 + nick_len].decode("utf-8", errors="replace")

        if signing_pub == self.identity.signing_public:
            return  # our own beacon, flooded back to us

        candidate = PeerIdentity(signing_pub, static_pub, nickname)
        if not candidate.verify_transcript(body, signature):
            return  # unsigned or forged: ignore entirely

        self.stats.beacons_received += 1
        known = self.trust.get(signing_pub)
        if known is not None and known.static_public != static_pub:
            self._event(
                f"WARNING: beacon for {known.nickname or known.short_id} carries a "
                "different static key than the pinned one. Ignoring it."
            )
            return

        if signing_pub not in self.discovered:
            self.discovered[signing_pub] = candidate
            self._event(f"discovered {nickname or '(no nick)'}#{candidate.short_id}")

    async def _on_data(self, packet: Packet, payload: bytes) -> None:
        session = self.sessions.session_by_tag(packet.dst_tag)
        if session is None:
            # Either cover traffic, or a frame for someone else that we only
            # relayed. Nothing to do.
            return
        try:
            plaintext = session.decrypt(payload)
        except SessionError:
            self.stats.decrypt_failures += 1
            return

        try:
            kind, timestamp, body = _decode_message(plaintext)
        except (ValueError, KeyError):
            return

        self.stats.messages_received += 1
        if kind == MessageKind.TEXT and self._on_message is not None:
            await self._on_message(
                IncomingMessage(
                    peer=session.peer,
                    kind=kind,
                    text=body.decode("utf-8", errors="replace"),
                    timestamp=timestamp,
                    verified=session.peer.verified,
                    rssi=getattr(self, "_last_rssi", None),
                )
            )

    # -- background loops -------------------------------------------------

    async def _beacon_loop(self, interval: float = 60.0) -> None:
        try:
            while self._running:
                await asyncio.sleep(interval * self.rng.uniform(0.8, 1.2))
                with contextlib.suppress(Exception):
                    await self.broadcast_beacon()
        except asyncio.CancelledError:
            raise

    async def _cover_loop(self) -> None:
        """Emit chaff that is bit-for-bit indistinguishable from real traffic.

        Cover frames are sent as ``DATA`` with a random destination tag and a
        random payload -- not as a distinct packet type, which would defeat the
        entire exercise by letting an observer filter chaff out of the header.
        No node recognises the tag, so the frame floods and dies like any
        undeliverable message.
        """
        mesh = self.config.mesh
        try:
            while self._running:
                delay = self.rng.expovariate(1.0 / mesh.cover_interval_mean)
                await asyncio.sleep(delay)
                with contextlib.suppress(Exception):
                    await self._emit(
                        PacketType.DATA,
                        random_bytes(self.rng.randint(40, self.capacity)),
                        random_bytes(8),
                    )
                    self.stats.cover_sent += 1
        except asyncio.CancelledError:
            raise

    # -- diagnostics ------------------------------------------------------

    def _event(self, message: str) -> None:
        self._on_event(message)

    def status(self) -> str:
        lines = [
            f"identity   {self.identity.nickname}#{self.identity.short_id}",
            f"transport  {self.transport.describe()}",
            f"sessions   {len(self.sessions.sessions())} established, "
            f"{self.sessions.pending_count} pending",
            f"discovered {len(self.discovered)} peer(s) not yet connected",
            f"router     {self.router.stats.summary()}",
            f"padding    {self.config.mesh.padding.value}, "
            f"cover traffic {'on' if self.config.mesh.cover_traffic else 'off'}",
        ]
        return "\n".join(lines)
