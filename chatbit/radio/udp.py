"""UDP multicast transport.

For developing and testing the mesh without hardware. Every node joined to the
group hears every frame, which is a decent approximation of a broadcast radio
segment where all nodes are in range of each other.

To make it behave like a radio rather than like a LAN, frames larger than the
configured MTU are refused rather than fragmented by IP, and an optional
``loss`` parameter drops frames at random.

This is a development transport. It offers no security of its own and anyone
on the network segment sees the frames -- which, given the payload is
end-to-end encrypted, is a fair simulation of the threat model on a radio.
"""

from __future__ import annotations

import asyncio
import random
import socket
import struct
import time
from typing import AsyncIterator

from .base import ReceivedFrame, Transport, TransportError

__all__ = ["UDPMulticastTransport"]


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, transport_obj: "UDPMulticastTransport") -> None:
        self.owner = transport_obj

    def datagram_received(self, data: bytes, addr) -> None:
        self.owner._deliver(data, addr)

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        self.owner._error = exc


class UDPMulticastTransport(Transport):
    def __init__(
        self,
        group: str = "239.23.23.23",
        port: int = 4242,
        mtu: int = 200,
        loss: float = 0.0,
        interface: str = "0.0.0.0",
        ttl: int = 1,
    ) -> None:
        self.group = group
        self.port = port
        self.mtu = mtu
        self.loss = loss
        self.interface = interface
        self.ttl = ttl
        self._queue: asyncio.Queue[ReceivedFrame | None] = asyncio.Queue()
        self._sock: socket.socket | None = None
        self._transport: asyncio.DatagramTransport | None = None
        self._running = False
        self._error: Exception | None = None
        self._rng = random.Random()
        # Our own datagrams come back to us on the multicast group; tag each
        # send so we can drop the echo.
        self._session_salt = self._rng.getrandbits(32).to_bytes(4, "big")

    async def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        sock.bind(("", self.port))

        mreq = struct.pack(
            "4s4s", socket.inet_aton(self.group), socket.inet_aton(self.interface)
        )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.ttl)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        sock.setblocking(False)
        self._sock = sock

        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _Protocol(self), sock=sock
        )
        self._running = True

    async def stop(self) -> None:
        self._running = False
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        self._sock = None
        await self._queue.put(None)

    async def send(self, frame: bytes) -> None:
        if not self._running or self._transport is None:
            raise TransportError("transport is not started")
        if len(frame) > self.mtu:
            raise ValueError(f"frame of {len(frame)} bytes exceeds MTU {self.mtu}")
        self._transport.sendto(self._session_salt + frame, (self.group, self.port))

    def _deliver(self, data: bytes, addr) -> None:
        if not self._running or len(data) < 4:
            return
        if data[:4] == self._session_salt:
            return  # our own multicast echo
        if self.loss and self._rng.random() < self.loss:
            return
        self._queue.put_nowait(
            ReceivedFrame(data=data[4:], rssi=None, snr=None, timestamp=time.monotonic())
        )

    async def frames(self) -> AsyncIterator[ReceivedFrame]:
        while self._running:
            item = await self._queue.get()
            if item is None:
                break
            yield item

    def describe(self) -> str:
        return (
            f"UDPMulticastTransport(group={self.group}:{self.port}, mtu={self.mtu})"
        )
