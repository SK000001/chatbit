"""The transport interface.

The whole point of this abstraction is that the mesh and crypto layers never
learn what carries their bytes. bitchat is welded to Bluetooth LE; chatbit
treats the link as a replaceable component, so the same protocol runs over a
LoRa modem, a UDP multicast group, or an in-process queue, and moving between
them is a config change rather than a rewrite.

A transport is a lossy, unordered, broadcast datagram link. That is the honest
description of a radio, and everything above this layer is written to assume
it: no delivery guarantee, no ordering, no addressing, no connection.
Transports that happen to be more reliable than that are still used as if they
were not.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import AsyncIterator

__all__ = ["Transport", "ReceivedFrame", "TransportError"]


class TransportError(Exception):
    """The link failed."""


@dataclass
class ReceivedFrame:
    """One frame off the link, plus whatever the radio knows about it."""

    data: bytes
    rssi: float | None = None  # dBm
    snr: float | None = None  # dB
    timestamp: float = 0.0

    @property
    def link_quality(self) -> str:
        if self.rssi is None:
            return "n/a"
        snr = f" snr {self.snr:+.1f} dB" if self.snr is not None else ""
        return f"rssi {self.rssi:.0f} dBm{snr}"


class Transport(abc.ABC):
    """A broadcast datagram link."""

    #: Largest frame the link accepts, in bytes.
    mtu: int = 200

    @abc.abstractmethod
    async def start(self) -> None:
        """Bring the link up."""

    @abc.abstractmethod
    async def stop(self) -> None:
        """Take the link down and release the hardware."""

    @abc.abstractmethod
    async def send(self, frame: bytes) -> None:
        """Transmit one frame. Must not exceed :attr:`mtu`."""

    @abc.abstractmethod
    def frames(self) -> AsyncIterator[ReceivedFrame]:
        """Async iterator over inbound frames."""

    async def __aenter__(self) -> "Transport":
        await self.start()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.stop()

    def describe(self) -> str:
        return f"{type(self).__name__}(mtu={self.mtu})"
