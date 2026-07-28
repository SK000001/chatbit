"""Node and radio configuration.

The radio settings here are the answer to "instead of Bluetooth, we get to set
the frequency". Bluetooth LE gives you three advertising channels at 2.4 GHz,
a ~27-byte usable advertising payload, and no control over any of it. A LoRa
transceiver gives you the whole licence-exempt band, a choice of spreading
factor trading throughput against range, and the ability to move channel.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .radio.regions import Region, RegionError, get_region
from .wire.padding import PaddingPolicy

__all__ = ["RadioConfig", "MeshConfig", "NodeConfig"]


@dataclass
class RadioConfig:
    """Physical-layer settings.

    Defaults are EU868 at SF9/125 kHz: roughly 1.7 kbit/s, a few kilometres in
    open terrain, and airtime low enough that the 1% duty cycle is usable for
    conversation.
    """

    region: str = "EU868"
    frequency_hz: int = 868_100_000
    spreading_factor: int = 9
    bandwidth_hz: int = 125_000
    coding_rate: int = 5  # 4/5
    tx_power_dbm: int = 14
    preamble_symbols: int = 8
    sync_word: int = 0x12  # private network; 0x34 is the LoRaWAN public value
    mtu: int = 200  # bytes on air per frame, <= 255 for SX127x

    def region_plan(self) -> Region:
        return get_region(self.region)

    def validate(self) -> None:
        plan = self.region_plan()
        plan.validate(self.frequency_hz, self.tx_power_dbm)
        if not 6 <= self.spreading_factor <= 12:
            raise RegionError("spreading factor must be 6..12")
        if self.bandwidth_hz not in (7_800, 10_400, 15_600, 20_800, 31_250,
                                     41_700, 62_500, 125_000, 250_000, 500_000):
            raise RegionError(f"unsupported bandwidth {self.bandwidth_hz} Hz")
        if not 5 <= self.coding_rate <= 8:
            raise RegionError("coding rate must be 5..8")
        if not 16 <= self.mtu <= 255:
            raise RegionError("mtu must be 16..255 bytes")

    def airtime_for(self, frame_bytes: int) -> float:
        from .radio.airtime import time_on_air

        return time_on_air(
            frame_bytes,
            spreading_factor=self.spreading_factor,
            bandwidth_hz=self.bandwidth_hz,
            coding_rate=self.coding_rate,
            preamble_symbols=self.preamble_symbols,
        )

    def summary(self) -> str:
        from .radio.airtime import bitrate

        toa = self.airtime_for(self.mtu)
        return (
            f"{self.frequency_hz / 1e6:.3f} MHz  SF{self.spreading_factor}  "
            f"BW{self.bandwidth_hz // 1000}k  CR4/{self.coding_rate}  "
            f"{self.tx_power_dbm} dBm  [{self.region}]\n"
            f"  {bitrate(self.spreading_factor, self.bandwidth_hz, self.coding_rate):.0f} bit/s nominal, "
            f"{toa * 1000:.0f} ms per {self.mtu}-byte frame"
        )


@dataclass
class MeshConfig:
    """Routing and traffic-shaping settings."""

    default_ttl: int = 7
    dedup_cache_size: int = 4096
    dedup_ttl_seconds: float = 900.0

    # Store-and-forward: hold undeliverable frames for peers that may come
    # back into range.
    store_forward: bool = True
    store_capacity: int = 512
    store_ttl_seconds: float = 3600.0

    # Relaying is jittered so that neighbours who heard the same frame do not
    # all retransmit at once and collide.
    relay_jitter_min: float = 0.05
    relay_jitter_max: float = 0.40

    padding: PaddingPolicy = PaddingPolicy.STRICT

    # Cover traffic: indistinguishable-from-real chaff on a randomised
    # schedule, so that "this node is transmitting" stops implying "this
    # person is talking". Costs airtime; off by default on duty-cycle-limited
    # bands, where the budget is better spent on real messages.
    cover_traffic: bool = False
    cover_interval_mean: float = 120.0
    cover_max_duty_fraction: float = 0.25  # never spend more of the budget than this


@dataclass
class NodeConfig:
    nickname: str = "anon"
    identity_path: str = "~/.chatbit/identity.json"
    trust_path: str = "~/.chatbit/trust.json"
    radio: RadioConfig = field(default_factory=RadioConfig)
    mesh: MeshConfig = field(default_factory=MeshConfig)

    # Transport selection: "lora", "udp", or "loopback".
    transport: str = "udp"
    serial_port: str = "/dev/ttyUSB0"
    serial_baud: int = 115200
    udp_group: str = "239.23.23.23"
    udp_port: int = 4242

    def expanded_identity_path(self) -> Path:
        return Path(self.identity_path).expanduser()

    def expanded_trust_path(self) -> Path:
        return Path(self.trust_path).expanduser()

    def validate(self) -> None:
        self.radio.validate()
        if self.transport not in ("lora", "udp", "loopback"):
            raise ValueError(f"unknown transport {self.transport!r}")

    @classmethod
    def load(cls, path: str | Path) -> "NodeConfig":
        with open(Path(path).expanduser()) as fh:
            blob = json.load(fh)
        radio = RadioConfig(**blob.pop("radio", {}))
        mesh_blob = blob.pop("mesh", {})
        if "padding" in mesh_blob:
            mesh_blob["padding"] = PaddingPolicy(mesh_blob["padding"])
        mesh = MeshConfig(**mesh_blob)
        return cls(radio=radio, mesh=mesh, **blob)

    def save(self, path: str | Path) -> None:
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        blob = asdict(self)
        blob["mesh"]["padding"] = self.mesh.padding.value
        with open(path, "w") as fh:
            json.dump(blob, fh, indent=2)
