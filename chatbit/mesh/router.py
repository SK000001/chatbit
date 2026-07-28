"""Flood routing with deduplication, TTL, and store-and-forward.

There is no routing table. Every node that hears a frame it has not seen
before rebroadcasts it once, with the TTL decremented, until the TTL runs out.
This is the same controlled-flood approach bitchat uses over BLE, and for the
same reason: on a mesh of people walking around, any topology you compute is
already stale, and the cost of maintaining routes exceeds the cost of flooding
short messages.

Three things stop a flood from becoming a storm:

**Deduplication.** Each frame carries a random message ID. A frame whose ID is
already in the cache is dropped rather than relayed, so a frame crosses each
node once regardless of how many neighbours hand it over.

**TTL.** Bounds the diameter of the flood.

**Jittered relay.** Neighbours that hear the same frame simultaneously would
otherwise all rebroadcast simultaneously and collide -- on a half-duplex radio
that means nobody hears anything. Each relay waits a random interval first,
and cancels if it hears someone else relay the same frame in the meantime.
That last part matters a lot on LoRa, where a retransmission costs a second of
airtime.

Store-and-forward holds frames for peers that are out of range, and replays
them when the network looks different. It is what makes the mesh work across a
disconnected crowd rather than only within one radio bubble.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from ..config import MeshConfig
from ..wire.packet import Packet

__all__ = ["Router", "DedupCache", "RouterStats"]


class DedupCache:
    """Bounded, time-limited set of recently seen frame identifiers."""

    def __init__(self, capacity: int = 4096, ttl: float = 900.0) -> None:
        self.capacity = capacity
        self.ttl = ttl
        self._seen: "OrderedDict[tuple[bytes, int], float]" = OrderedDict()

    def seen(self, key: tuple[bytes, int], now: float | None = None) -> bool:
        """Check-and-insert. Returns whether the key was already present."""
        now = now if now is not None else time.monotonic()
        self._expire(now)
        if key in self._seen:
            return True
        self._seen[key] = now
        while len(self._seen) > self.capacity:
            self._seen.popitem(last=False)
        return False

    def contains(self, key: tuple[bytes, int]) -> bool:
        return key in self._seen

    def _expire(self, now: float) -> None:
        cutoff = now - self.ttl
        while self._seen:
            key, timestamp = next(iter(self._seen.items()))
            if timestamp >= cutoff:
                break
            del self._seen[key]

    def __len__(self) -> int:
        return len(self._seen)


@dataclass
class _StoredFrame:
    packet: Packet
    stored_at: float
    attempts: int = 0


@dataclass
class RouterStats:
    received: int = 0
    duplicates: int = 0
    relayed: int = 0
    relay_suppressed: int = 0
    expired: int = 0
    delivered_local: int = 0
    stored: int = 0
    replayed: int = 0

    def summary(self) -> str:
        return (
            f"rx {self.received}  dup {self.duplicates}  relayed {self.relayed} "
            f"(suppressed {self.relay_suppressed})  expired {self.expired}  "
            f"local {self.delivered_local}  stored {self.stored}  "
            f"replayed {self.replayed}"
        )


class Router:
    """Decides what to do with each frame: deliver, relay, store, or drop."""

    def __init__(
        self,
        config: MeshConfig,
        send: Callable[[Packet], Awaitable[None]],
        is_for_us: Callable[[Packet], bool],
        deliver: Callable[[Packet], Awaitable[None]],
        rng: random.Random | None = None,
    ) -> None:
        self.config = config
        self._send = send
        self._is_for_us = is_for_us
        self._deliver = deliver
        self.rng = rng or random.Random()

        self.dedup = DedupCache(config.dedup_cache_size, config.dedup_ttl_seconds)
        self.stats = RouterStats()
        self._store: list[_StoredFrame] = []
        self._pending_relays: dict[tuple[bytes, int], asyncio.TimerHandle] = {}
        self._relay_tasks: set[asyncio.Task] = set()

    # -- inbound ----------------------------------------------------------

    async def handle(self, packet: Packet) -> None:
        """Process one frame received from the transport."""
        self.stats.received += 1
        key = packet.dedup_key

        if self.dedup.seen(key):
            self.stats.duplicates += 1
            # Someone else relayed this while our own relay was pending.
            # Theirs reached the same neighbours ours would have, so stand down.
            self._cancel_pending_relay(key)
            return

        if self._is_for_us(packet):
            self.stats.delivered_local += 1
            await self._deliver(packet)
            # A frame addressed to us is still relayed: in a mesh we may not be
            # the only intended recipient, and suppressing would leak the fact
            # that it was ours to anyone watching relay behaviour.

        self._schedule_relay(packet)

    # -- relaying ---------------------------------------------------------

    def _schedule_relay(self, packet: Packet) -> None:
        forwarded = packet.decrement_ttl()
        if forwarded is None:
            self.stats.expired += 1
            return

        delay = self.rng.uniform(
            self.config.relay_jitter_min, self.config.relay_jitter_max
        )
        loop = asyncio.get_running_loop()
        key = packet.dedup_key
        handle = loop.call_later(delay, self._fire_relay, key, forwarded)
        self._pending_relays[key] = handle

    def _fire_relay(self, key: tuple[bytes, int], packet: Packet) -> None:
        self._pending_relays.pop(key, None)
        task = asyncio.create_task(self._do_relay(packet))
        self._relay_tasks.add(task)
        task.add_done_callback(self._relay_tasks.discard)

    async def _do_relay(self, packet: Packet) -> None:
        try:
            await self._send(packet)
            self.stats.relayed += 1
        except Exception:
            # A relay that cannot go out right now -- duty cycle, radio busy --
            # is stored if we can, and otherwise dropped. Relaying is
            # best-effort by definition.
            if self.config.store_forward:
                self.store(packet)

    def _cancel_pending_relay(self, key: tuple[bytes, int]) -> None:
        handle = self._pending_relays.pop(key, None)
        if handle is not None:
            handle.cancel()
            self.stats.relay_suppressed += 1

    # -- outbound ---------------------------------------------------------

    async def originate(self, packet: Packet) -> None:
        """Transmit a frame we created. Marked seen so we never relay our own."""
        self.dedup.seen(packet.dedup_key)
        await self._send(packet)

    # -- store and forward ------------------------------------------------

    def store(self, packet: Packet, now: float | None = None) -> None:
        if not self.config.store_forward:
            return
        now = now if now is not None else time.monotonic()
        if len(self._store) >= self.config.store_capacity:
            self._store.pop(0)  # oldest out
        self._store.append(_StoredFrame(packet=packet, stored_at=now))
        self.stats.stored += 1

    async def replay_store(self, now: float | None = None) -> int:
        """Retransmit stored frames that have not expired. Returns the count."""
        now = now if now is not None else time.monotonic()
        keep: list[_StoredFrame] = []
        sent = 0
        for entry in self._store:
            if now - entry.stored_at > self.config.store_ttl_seconds:
                continue
            try:
                await self._send(entry.packet)
                sent += 1
                self.stats.replayed += 1
            except Exception:
                keep.append(entry)  # still cannot send; hold it
        self._store = keep
        return sent

    def purge_store(self, now: float | None = None) -> int:
        now = now if now is not None else time.monotonic()
        before = len(self._store)
        self._store = [
            e for e in self._store if now - e.stored_at <= self.config.store_ttl_seconds
        ]
        return before - len(self._store)

    @property
    def stored_count(self) -> int:
        return len(self._store)

    async def shutdown(self) -> None:
        for handle in self._pending_relays.values():
            handle.cancel()
        self._pending_relays.clear()
        for task in list(self._relay_tasks):
            task.cancel()
        if self._relay_tasks:
            await asyncio.gather(*self._relay_tasks, return_exceptions=True)
