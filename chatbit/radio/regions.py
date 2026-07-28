"""Band plans and the limits that come with them.

Read this before you transmit anything.

Radio spectrum is regulated everywhere. "We get to set the frequency" is true
in the sense that the software exposes the knob, and false in the sense that
you may turn it to any value you like. Which frequencies you may use, at what
power, for what fraction of the time, and whether you may encrypt at all,
depends on the band and on where you are standing.

The short version:

* **ISM / licence-exempt bands** (433 MHz in EU, 915 MHz in US, 2.4 GHz
  worldwide, plus the regional LoRaWAN plans below) are the bands this
  software is built for. No licence, encryption is fine, but power and
  duty-cycle limits apply and are enforced here.

* **Amateur radio bands** get you far more power and much better range, and
  in most jurisdictions -- including the US, under FCC Part 97.113(a)(4) --
  you may not transmit "messages encoded for the purpose of obscuring their
  meaning". An encrypted chat protocol on ham spectrum is not a grey area;
  it is the specific thing that rule prohibits. Some jurisdictions permit
  authentication-only signing without encryption. chatbit does not ship a
  mode for that, because a messenger that authenticates but does not encrypt
  would be a strange thing to build under this name.

* **Everything else** -- cellular, public safety, aviation, marine, licensed
  point-to-point -- is not available to you, and transmitting there is the
  kind of mistake that ends in a fine and confiscated equipment.

:class:`Region` encodes the licence-exempt plans. :meth:`Region.validate`
refuses configurations that fall outside them. This is a guard rail against
mistakes, not legal advice, and it does not know where you are: selecting a
region is an assertion by you that you are entitled to use it.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["Region", "REGIONS", "get_region", "RegionError"]


class RegionError(Exception):
    """A radio configuration is outside the selected band plan."""


@dataclass(frozen=True)
class Region:
    name: str
    description: str
    freq_min_hz: int
    freq_max_hz: int
    max_power_dbm: int
    duty_cycle: float | None  # fraction of time, e.g. 0.01 == 1%; None = unlimited
    max_dwell_ms: float | None  # per-transmission airtime cap
    notes: str = ""

    def validate(self, frequency_hz: int, power_dbm: int) -> None:
        if not self.freq_min_hz <= frequency_hz <= self.freq_max_hz:
            raise RegionError(
                f"{frequency_hz / 1e6:.3f} MHz is outside {self.name} "
                f"({self.freq_min_hz / 1e6:.3f}-{self.freq_max_hz / 1e6:.3f} MHz)"
            )
        if power_dbm > self.max_power_dbm:
            raise RegionError(
                f"{power_dbm} dBm exceeds the {self.name} limit of "
                f"{self.max_power_dbm} dBm"
            )

    def describe(self) -> str:
        duty = "unlimited" if self.duty_cycle is None else f"{self.duty_cycle:.1%}"
        dwell = "none" if self.max_dwell_ms is None else f"{self.max_dwell_ms:.0f} ms"
        return (
            f"{self.name}: {self.description}\n"
            f"  frequency   {self.freq_min_hz / 1e6:.3f} - {self.freq_max_hz / 1e6:.3f} MHz\n"
            f"  max power   {self.max_power_dbm} dBm\n"
            f"  duty cycle  {duty}\n"
            f"  max dwell   {dwell}"
            + (f"\n  note        {self.notes}" if self.notes else "")
        )


REGIONS: dict[str, Region] = {
    "EU868": Region(
        name="EU868",
        description="European SRD band, the common LoRa plan in ETSI countries",
        freq_min_hz=863_000_000,
        freq_max_hz=870_000_000,
        max_power_dbm=14,
        duty_cycle=0.01,
        max_dwell_ms=None,
        notes="Duty cycle is per sub-band; 1% is the conservative figure used here.",
    ),
    "EU433": Region(
        name="EU433",
        description="European 433 MHz ISM band",
        freq_min_hz=433_050_000,
        freq_max_hz=434_790_000,
        max_power_dbm=10,
        duty_cycle=0.10,
        max_dwell_ms=None,
    ),
    "US915": Region(
        name="US915",
        description="US/Canada ISM band, FCC Part 15.247",
        freq_min_hz=902_000_000,
        freq_max_hz=928_000_000,
        max_power_dbm=30,
        duty_cycle=None,
        max_dwell_ms=400.0,
        notes=(
            "No duty cycle, but a 400 ms dwell limit per channel applies to "
            "digitally modulated systems. High SF at narrow BW will exceed it."
        ),
    ),
    "AU915": Region(
        name="AU915",
        description="Australia / New Zealand ISM band",
        freq_min_hz=915_000_000,
        freq_max_hz=928_000_000,
        max_power_dbm=30,
        duty_cycle=None,
        max_dwell_ms=400.0,
    ),
    "AS923": Region(
        name="AS923",
        description="Asia-Pacific shared plan (JP, SG, TH, VN and others)",
        freq_min_hz=915_000_000,
        freq_max_hz=928_000_000,
        max_power_dbm=16,
        duty_cycle=0.01,
        max_dwell_ms=400.0,
        notes="Per-country variations are significant; check your national rules.",
    ),
    "IN865": Region(
        name="IN865",
        description="India 865-867 MHz",
        freq_min_hz=865_000_000,
        freq_max_hz=867_000_000,
        max_power_dbm=30,
        duty_cycle=None,
        max_dwell_ms=None,
    ),
    "KR920": Region(
        name="KR920",
        description="South Korea 920-923 MHz",
        freq_min_hz=920_900_000,
        freq_max_hz=923_300_000,
        max_power_dbm=14,
        duty_cycle=None,
        max_dwell_ms=None,
    ),
    "CN470": Region(
        name="CN470",
        description="China 470-510 MHz",
        freq_min_hz=470_000_000,
        freq_max_hz=510_000_000,
        max_power_dbm=17,
        duty_cycle=None,
        max_dwell_ms=None,
    ),
    "ISM2400": Region(
        name="ISM2400",
        description="Worldwide 2.4 GHz ISM (SX128x LoRa); short range, no duty cycle",
        freq_min_hz=2_400_000_000,
        freq_max_hz=2_500_000_000,
        max_power_dbm=20,
        duty_cycle=None,
        max_dwell_ms=None,
    ),
    "LAB": Region(
        name="LAB",
        description="Bench testing into a dummy load or shielded enclosure",
        freq_min_hz=1,
        freq_max_hz=6_000_000_000,
        max_power_dbm=0,
        duty_cycle=None,
        max_dwell_ms=None,
        notes=(
            "No limits enforced. Only legitimate with the antenna port "
            "terminated into a dummy load. Do not radiate."
        ),
    ),
}


def get_region(name: str) -> Region:
    try:
        return REGIONS[name.upper()]
    except KeyError:
        raise RegionError(
            f"unknown region {name!r}; known regions: {', '.join(sorted(REGIONS))}"
        ) from None
