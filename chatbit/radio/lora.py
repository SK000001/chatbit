"""LoRa transport over a serial-attached radio module.

This is the transport that replaces Bluetooth, and the one where the frequency
is yours to choose.

Two module families are supported:

``rylr``
    Reyax RYLR896 / RYLR998 and compatible AT-command modules. Cheap, solder
    nothing, talk to it over a USB-serial adapter. The AT interface is
    text-only, so binary frames are hex-encoded, which halves the usable
    payload -- the driver accounts for that automatically.

``slip``
    Any radio running a firmware that exposes a raw framed byte pipe over
    serial, using SLIP framing (RFC 1055). This gets the full 255-byte SX127x
    payload and is the better option if you can flash the board. A reference
    firmware sketch is described in ``docs/firmware.md``.

Every transmission passes through the duty-cycle governor first. On EU868 that
means the radio will refuse to transmit rather than let you exceed 1%, and it
will tell you how long to wait. This is enforcement, not advice.

pyserial is imported lazily, so the rest of chatbit works on a machine with no
radio attached.
"""

from __future__ import annotations

import asyncio
import queue
import threading
import time
from typing import AsyncIterator

from ..config import RadioConfig
from .airtime import DutyCycleExceeded, DutyCycleGovernor, time_on_air
from .base import ReceivedFrame, Transport, TransportError

__all__ = ["LoRaTransport", "SlipCodec"]

# SLIP framing constants, RFC 1055.
SLIP_END = 0xC0
SLIP_ESC = 0xDB
SLIP_ESC_END = 0xDC
SLIP_ESC_ESC = 0xDD

# RYLR modules accept at most 240 bytes of payload per AT+SEND.
RYLR_MAX_PAYLOAD = 240

# LoRa bandwidth -> RYLR parameter index.
_RYLR_BW_INDEX = {125_000: 7, 250_000: 8, 500_000: 9}


class SlipCodec:
    """SLIP framing: escape the delimiter, terminate frames with END."""

    @staticmethod
    def encode(payload: bytes) -> bytes:
        out = bytearray([SLIP_END])
        for byte in payload:
            if byte == SLIP_END:
                out += bytes([SLIP_ESC, SLIP_ESC_END])
            elif byte == SLIP_ESC:
                out += bytes([SLIP_ESC, SLIP_ESC_ESC])
            else:
                out.append(byte)
        out.append(SLIP_END)
        return bytes(out)

    def __init__(self) -> None:
        self._buf = bytearray()
        self._escaped = False

    def feed(self, data: bytes) -> list[bytes]:
        """Push received bytes in, get zero or more complete frames out."""
        frames: list[bytes] = []
        for byte in data:
            if self._escaped:
                if byte == SLIP_ESC_END:
                    self._buf.append(SLIP_END)
                elif byte == SLIP_ESC_ESC:
                    self._buf.append(SLIP_ESC)
                else:
                    self._buf.clear()  # protocol violation, resynchronise
                self._escaped = False
            elif byte == SLIP_ESC:
                self._escaped = True
            elif byte == SLIP_END:
                if self._buf:
                    frames.append(bytes(self._buf))
                    self._buf.clear()
            else:
                self._buf.append(byte)
        return frames


class LoRaTransport(Transport):
    """Frames over a serial-attached LoRa radio."""

    def __init__(
        self,
        config: RadioConfig,
        port: str = "/dev/ttyUSB0",
        baud: int = 115200,
        driver: str = "rylr",
        enforce_duty_cycle: bool = True,
        network_id: int = 6,
    ) -> None:
        config.validate()
        self.config = config
        self.port = port
        self.baud = baud
        self.driver = driver
        self.network_id = network_id

        plan = config.region_plan()
        self.governor = DutyCycleGovernor(
            duty_cycle=plan.duty_cycle if enforce_duty_cycle else None,
            max_dwell_ms=plan.max_dwell_ms if enforce_duty_cycle else None,
        )

        if driver == "rylr":
            # Hex encoding doubles every byte on the AT interface.
            self.mtu = min(config.mtu, RYLR_MAX_PAYLOAD // 2)
        elif driver == "slip":
            self.mtu = min(config.mtu, 255)
        else:
            raise ValueError(f"unknown LoRa driver {driver!r}; use 'rylr' or 'slip'")

        self._serial = None
        self._codec = SlipCodec()
        self._rx_thread: threading.Thread | None = None
        self._rx_queue: queue.Queue[ReceivedFrame | None] = queue.Queue()
        self._async_queue: asyncio.Queue[ReceivedFrame | None] = asyncio.Queue()
        self._pump_task: asyncio.Task | None = None
        self._running = False
        self._tx_lock = asyncio.Lock()
        self.frames_sent = 0
        self.frames_received = 0

    # -- lifecycle --------------------------------------------------------

    async def start(self) -> None:
        try:
            import serial  # noqa: PLC0415  (optional dependency)
        except ImportError as exc:  # pragma: no cover
            raise TransportError(
                "pyserial is required for the LoRa transport: pip install pyserial"
            ) from exc

        try:
            self._serial = serial.Serial(self.port, self.baud, timeout=0.2)
        except Exception as exc:
            raise TransportError(f"cannot open {self.port}: {exc}") from exc

        self._running = True
        await asyncio.sleep(0.2)  # let the module settle after opening the port

        if self.driver == "rylr":
            await self._configure_rylr()

        self._rx_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._rx_thread.start()
        self._pump_task = asyncio.create_task(self._pump())

    async def stop(self) -> None:
        self._running = False
        if self._pump_task is not None:
            self._pump_task.cancel()
            try:
                await self._pump_task
            except (asyncio.CancelledError, Exception):
                pass
            self._pump_task = None
        if self._rx_thread is not None:
            self._rx_thread.join(timeout=1.0)
            self._rx_thread = None
        if self._serial is not None:
            try:
                self._serial.close()
            finally:
                self._serial = None
        await self._async_queue.put(None)

    # -- module configuration ---------------------------------------------

    async def _configure_rylr(self) -> None:
        """Push frequency, spreading factor, bandwidth, coding rate and power.

        This is the bit that has no Bluetooth equivalent.
        """
        cfg = self.config
        bw_index = _RYLR_BW_INDEX.get(cfg.bandwidth_hz)
        if bw_index is None:
            raise TransportError(
                f"RYLR modules support 125/250/500 kHz, not {cfg.bandwidth_hz} Hz"
            )

        commands = [
            f"AT+NETWORKID={self.network_id}",
            f"AT+BAND={cfg.frequency_hz}",
            f"AT+PARAMETER={cfg.spreading_factor},{bw_index},"
            f"{cfg.coding_rate - 4},{cfg.preamble_symbols}",
            f"AT+CRFOP={cfg.tx_power_dbm}",
            # Address 0 with broadcast sends; the mesh does its own addressing
            # via dst_tag, so the module's addressing is left wide open.
            "AT+ADDRESS=0",
        ]
        for command in commands:
            reply = await self._at(command)
            if reply is not None and reply.startswith("+ERR"):
                raise TransportError(f"module rejected {command!r}: {reply}")

    async def _at(self, command: str, timeout: float = 1.0) -> str | None:
        assert self._serial is not None
        await asyncio.to_thread(self._serial.write, (command + "\r\n").encode())
        deadline = time.monotonic() + timeout
        buf = b""
        while time.monotonic() < deadline:
            chunk = await asyncio.to_thread(self._serial.read, 64)
            if chunk:
                buf += chunk
                if b"\r\n" in buf:
                    return buf.decode(errors="replace").strip()
            else:
                await asyncio.sleep(0.02)
        return None

    # -- transmit ---------------------------------------------------------

    async def send(self, frame: bytes) -> None:
        if not self._running or self._serial is None:
            raise TransportError("transport is not started")
        if len(frame) > self.mtu:
            raise ValueError(f"frame of {len(frame)} bytes exceeds MTU {self.mtu}")

        airtime = self.config.airtime_for(len(frame))

        async with self._tx_lock:
            self.governor.check(airtime)
            if self.driver == "rylr":
                payload = frame.hex().upper()
                command = f"AT+SEND=0,{len(payload)},{payload}"
                await asyncio.to_thread(
                    self._serial.write, (command + "\r\n").encode()
                )
            else:
                await asyncio.to_thread(self._serial.write, SlipCodec.encode(frame))
            self.governor.record(airtime)
            self.frames_sent += 1
            # Hold the lock for the duration of the transmission: the radio is
            # half-duplex and queueing a second frame mid-transmission drops it.
            await asyncio.sleep(airtime)

    async def send_when_permitted(self, frame: bytes, max_wait: float = 60.0) -> bool:
        """Send, waiting out the duty-cycle budget if needed.

        Returns ``False`` if the wait would exceed ``max_wait``.
        """
        try:
            await self.send(frame)
            return True
        except DutyCycleExceeded as exc:
            if exc.wait_seconds > max_wait or exc.wait_seconds <= 0:
                return False
            await asyncio.sleep(exc.wait_seconds + 0.1)
            try:
                await self.send(frame)
                return True
            except DutyCycleExceeded:
                return False

    # -- receive ----------------------------------------------------------

    def _read_loop(self) -> None:
        """Blocking serial reader, runs on its own thread."""
        line_buf = bytearray()
        while self._running and self._serial is not None:
            try:
                chunk = self._serial.read(256)
            except Exception:
                break
            if not chunk:
                continue

            if self.driver == "slip":
                for frame in self._codec.feed(chunk):
                    self._rx_queue.put(
                        ReceivedFrame(data=frame, timestamp=time.monotonic())
                    )
                continue

            line_buf += chunk
            while b"\n" in line_buf:
                line, _, rest = line_buf.partition(b"\n")
                line_buf = bytearray(rest)
                parsed = self._parse_rylr_line(line.decode(errors="replace").strip())
                if parsed is not None:
                    self._rx_queue.put(parsed)

    def _parse_rylr_line(self, line: str) -> ReceivedFrame | None:
        """Parse ``+RCV=<addr>,<len>,<hexdata>,<rssi>,<snr>``."""
        if not line.startswith("+RCV="):
            return None
        try:
            body = line[len("+RCV=") :]
            parts = body.split(",")
            if len(parts) < 5:
                return None
            # Data itself never contains a comma (it is hex), so a fixed split
            # from both ends is safe.
            hex_data = parts[2]
            rssi = float(parts[-2])
            snr = float(parts[-1])
            return ReceivedFrame(
                data=bytes.fromhex(hex_data),
                rssi=rssi,
                snr=snr,
                timestamp=time.monotonic(),
            )
        except (ValueError, IndexError):
            return None

    async def _pump(self) -> None:
        """Move frames from the reader thread onto the asyncio queue."""
        while self._running:
            try:
                item = await asyncio.to_thread(self._rx_queue.get, True, 0.25)
            except queue.Empty:
                continue
            except Exception:
                break
            if item is None:
                break
            self.frames_received += 1
            await self._async_queue.put(item)

    async def frames(self) -> AsyncIterator[ReceivedFrame]:
        while self._running:
            item = await self._async_queue.get()
            if item is None:
                break
            yield item

    # -- diagnostics ------------------------------------------------------

    def describe(self) -> str:
        return (
            f"LoRaTransport({self.driver} on {self.port} @ {self.baud})\n"
            f"  {self.config.summary()}\n"
            f"  mtu {self.mtu} B, duty cycle "
            f"{self.governor.utilisation():.1%} of budget used"
        )
