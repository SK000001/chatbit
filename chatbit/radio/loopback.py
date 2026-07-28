"""In-process transport for tests and simulation.

Nodes attached to the same :class:`Medium` hear each other. The medium can be
told to drop frames, duplicate them, delay them, and enforce a topology, which
is how the mesh routing tests exercise multi-hop paths and packet loss without
needing nine radios and a field.
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import AsyncIterator

from .base import ReceivedFrame, Transport

__all__ = ["Medium", "LoopbackTransport"]


class Medium:
    """A shared broadcast medium with configurable impairments."""

    def __init__(
        self,
        loss: float = 0.0,
        duplicate: float = 0.0,
        delay: float = 0.0,
        jitter: float = 0.0,
        rng: random.Random | None = None,
    ) -> None:
        self.loss = loss
        self.duplicate = duplicate
        self.delay = delay
        self.jitter = jitter
        self.rng = rng or random.Random()
        self._nodes: list["LoopbackTransport"] = []
        #: Optional adjacency: name -> set of names that can hear it. When
        #: empty, the medium is fully connected.
        self.topology: dict[str, set[str]] = {}
        self.frames_sent = 0
        self.frames_delivered = 0
        self.frames_dropped = 0

    def attach(self, node: "LoopbackTransport") -> None:
        self._nodes.append(node)

    def detach(self, node: "LoopbackTransport") -> None:
        if node in self._nodes:
            self._nodes.remove(node)

    def can_hear(self, sender: str, receiver: str) -> bool:
        if not self.topology:
            return True
        return receiver in self.topology.get(sender, set())

    async def broadcast(self, sender: "LoopbackTransport", frame: bytes) -> None:
        self.frames_sent += 1
        for node in list(self._nodes):
            if node is sender:
                continue
            if not self.can_hear(sender.name, node.name):
                continue
            if self.rng.random() < self.loss:
                self.frames_dropped += 1
                continue

            copies = 2 if self.rng.random() < self.duplicate else 1
            for _ in range(copies):
                delay = self.delay + self.rng.uniform(0, self.jitter)
                if delay > 0:
                    asyncio.get_running_loop().call_later(
                        delay, lambda n=node, f=frame: n._deliver(f)
                    )
                else:
                    node._deliver(frame)
                self.frames_delivered += 1


class LoopbackTransport(Transport):
    def __init__(self, medium: Medium, name: str = "node", mtu: int = 200) -> None:
        self.medium = medium
        self.name = name
        self.mtu = mtu
        self._queue: asyncio.Queue[ReceivedFrame] = asyncio.Queue()
        self._running = False
        self.sent_count = 0

    async def start(self) -> None:
        self.medium.attach(self)
        self._running = True

    async def stop(self) -> None:
        self._running = False
        self.medium.detach(self)
        await self._queue.put(None)  # type: ignore[arg-type]

    async def send(self, frame: bytes) -> None:
        if len(frame) > self.mtu:
            raise ValueError(f"frame of {len(frame)} bytes exceeds MTU {self.mtu}")
        self.sent_count += 1
        await self.medium.broadcast(self, frame)

    def _deliver(self, frame: bytes) -> None:
        if self._running:
            self._queue.put_nowait(
                ReceivedFrame(
                    data=frame,
                    rssi=-60.0 - self.medium.rng.random() * 40,
                    snr=self.medium.rng.uniform(-5, 10),
                    timestamp=time.monotonic(),
                )
            )

    async def frames(self) -> AsyncIterator[ReceivedFrame]:
        while self._running:
            item = await self._queue.get()
            if item is None:
                break
            yield item

    def describe(self) -> str:
        return f"LoopbackTransport(name={self.name!r}, mtu={self.mtu})"
