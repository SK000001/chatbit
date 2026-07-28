"""LoRa time-on-air, and the governor that keeps you legal.

LoRa is slow. At spreading factor 12 on 125 kHz, a single 200-byte frame
occupies the channel for about six and a half seconds. Under EU868's 1% duty
cycle that one frame then buys you ten minutes of silence. Any mesh design
that ignores this works beautifully on a bench with two nodes and falls over
the moment it meets a real band plan.

So airtime is computed up front, budgeted, and enforced. :class:`DutyCycleGovernor`
is the component that says "not yet" -- and it is deliberately in the transmit
path rather than advisory, because a duty-cycle limit you can forget to check
is a duty-cycle limit you will exceed.

The time-on-air calculation follows the Semtech SX1276 datasheet, section 4.1.1.6.
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field

__all__ = ["time_on_air", "DutyCycleGovernor", "DutyCycleExceeded"]


def time_on_air(
    payload_bytes: int,
    spreading_factor: int = 9,
    bandwidth_hz: int = 125_000,
    coding_rate: int = 5,
    preamble_symbols: int = 8,
    explicit_header: bool = True,
    crc: bool = True,
    low_data_rate_optimize: bool | None = None,
) -> float:
    """Airtime in seconds for one LoRa frame.

    ``coding_rate`` is the denominator of 4/n, so 5 means 4/5.
    ``low_data_rate_optimize`` defaults to the datasheet rule: on when the
    symbol duration exceeds 16 ms.
    """
    if not 6 <= spreading_factor <= 12:
        raise ValueError("spreading factor must be 6..12")
    if not 5 <= coding_rate <= 8:
        raise ValueError("coding rate must be 5..8 (for 4/5 .. 4/8)")

    symbol_duration = (2**spreading_factor) / bandwidth_hz

    if low_data_rate_optimize is None:
        low_data_rate_optimize = symbol_duration > 0.016
    de = 1 if low_data_rate_optimize else 0
    ih = 0 if explicit_header else 1
    crc_bits = 16 if crc else 0

    preamble_time = (preamble_symbols + 4.25) * symbol_duration

    numerator = (
        8 * payload_bytes - 4 * spreading_factor + 28 + crc_bits - 20 * ih
    )
    denominator = 4 * (spreading_factor - 2 * de)
    payload_symbols = 8 + max(math.ceil(numerator / denominator) * coding_rate, 0)
    payload_time = payload_symbols * symbol_duration

    return preamble_time + payload_time


def bitrate(
    spreading_factor: int = 9, bandwidth_hz: int = 125_000, coding_rate: int = 5
) -> float:
    """Nominal LoRa bitrate in bits per second, for sanity-checking a config."""
    return spreading_factor * (bandwidth_hz / (2**spreading_factor)) * (4 / coding_rate)


class DutyCycleExceeded(Exception):
    """Transmitting now would breach the configured duty cycle."""

    def __init__(self, wait_seconds: float) -> None:
        self.wait_seconds = wait_seconds
        super().__init__(
            f"duty cycle budget exhausted; {wait_seconds:.1f}s until the next "
            "transmission is permitted"
        )


@dataclass
class DutyCycleGovernor:
    """Sliding-window airtime budget.

    Tracks transmissions over ``window_seconds`` and refuses any that would
    push total airtime above ``duty_cycle`` of the window. ``duty_cycle=None``
    disables enforcement (for regions that have no such limit).
    """

    duty_cycle: float | None
    window_seconds: float = 3600.0
    max_dwell_ms: float | None = None
    _events: deque[tuple[float, float]] = field(default_factory=deque, repr=False)

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    def used_airtime(self, now: float | None = None) -> float:
        now = now if now is not None else time.monotonic()
        self._prune(now)
        return sum(duration for _, duration in self._events)

    @property
    def budget_seconds(self) -> float:
        if self.duty_cycle is None:
            return math.inf
        return self.duty_cycle * self.window_seconds

    def check(self, airtime_seconds: float, now: float | None = None) -> None:
        """Raise :class:`DutyCycleExceeded` if this transmission is not allowed."""
        if self.max_dwell_ms is not None and airtime_seconds * 1000 > self.max_dwell_ms:
            raise DutyCycleExceeded(0.0)  # never permitted at this size/config

        if self.duty_cycle is None:
            return

        now = now if now is not None else time.monotonic()
        self._prune(now)
        used = sum(duration for _, duration in self._events)

        if used + airtime_seconds <= self.budget_seconds:
            return

        # Work out when enough old airtime ages out of the window.
        needed = used + airtime_seconds - self.budget_seconds
        freed = 0.0
        for timestamp, duration in self._events:
            freed += duration
            if freed >= needed:
                raise DutyCycleExceeded(
                    max(0.0, (timestamp + self.window_seconds) - now)
                )
        raise DutyCycleExceeded(self.window_seconds)

    def record(self, airtime_seconds: float, now: float | None = None) -> None:
        now = now if now is not None else time.monotonic()
        self._events.append((now, airtime_seconds))
        self._prune(now)

    def utilisation(self, now: float | None = None) -> float:
        """Fraction of the permitted budget currently consumed, 0.0-1.0+."""
        if self.duty_cycle is None:
            return 0.0
        return self.used_airtime(now) / self.budget_seconds

    def dwell_violation(self, airtime_seconds: float) -> bool:
        return (
            self.max_dwell_ms is not None
            and airtime_seconds * 1000 > self.max_dwell_ms
        )
