"""Airtime, duty cycle, band plans and the serial framing codec."""

from __future__ import annotations

import pytest

from chatbit.config import RadioConfig
from chatbit.radio.airtime import (
    DutyCycleExceeded,
    DutyCycleGovernor,
    bitrate,
    time_on_air,
)
from chatbit.radio.lora import SlipCodec
from chatbit.radio.regions import REGIONS, RegionError, get_region


# ---------------------------------------------------------------------------
# time on air
# ---------------------------------------------------------------------------


def test_matches_semtech_reference_values():
    """Checked against the Semtech SX1276 airtime calculator.

    SF7/BW125/CR4-5/8-symbol preamble/explicit header/CRC, 13-byte payload is
    the canonical worked example and comes to 46.3 ms.
    """
    assert time_on_air(13, spreading_factor=7) == pytest.approx(0.0463, abs=0.0005)
    # A short SF12 frame is the familiar "about a second" case.
    assert time_on_air(10, spreading_factor=12) == pytest.approx(0.991, abs=0.002)


def test_airtime_grows_with_spreading_factor():
    times = [time_on_air(50, spreading_factor=sf) for sf in range(7, 13)]
    assert times == sorted(times)
    # Each step up in SF roughly doubles airtime.
    for earlier, later in zip(times, times[1:]):
        assert 1.6 < later / earlier < 2.6


def test_wider_bandwidth_is_faster():
    narrow = time_on_air(50, bandwidth_hz=125_000)
    wide = time_on_air(50, bandwidth_hz=250_000)
    assert wide < narrow


def test_low_data_rate_optimisation_engages_at_high_sf():
    """SF11 and SF12 at 125 kHz have symbol times over 16 ms and need DE on."""
    forced_off = time_on_air(50, spreading_factor=12, low_data_rate_optimize=False)
    automatic = time_on_air(50, spreading_factor=12)
    assert automatic != forced_off


def test_invalid_parameters_are_rejected():
    with pytest.raises(ValueError):
        time_on_air(10, spreading_factor=13)
    with pytest.raises(ValueError):
        time_on_air(10, coding_rate=9)


def test_bitrate_ordering():
    assert bitrate(7) > bitrate(9) > bitrate(12)


# ---------------------------------------------------------------------------
# duty cycle
# ---------------------------------------------------------------------------


def test_governor_allows_transmission_within_budget():
    gov = DutyCycleGovernor(duty_cycle=0.01, window_seconds=3600)
    gov.check(1.0, now=0.0)
    gov.record(1.0, now=0.0)
    assert gov.used_airtime(now=0.0) == pytest.approx(1.0)


def test_governor_blocks_over_budget():
    gov = DutyCycleGovernor(duty_cycle=0.01, window_seconds=3600)  # 36 s of airtime
    for i in range(36):
        gov.check(1.0, now=float(i))
        gov.record(1.0, now=float(i))
    with pytest.raises(DutyCycleExceeded):
        gov.check(1.0, now=36.0)


def test_governor_reports_a_usable_wait():
    gov = DutyCycleGovernor(duty_cycle=0.01, window_seconds=3600)
    for i in range(36):
        gov.record(1.0, now=float(i))
    with pytest.raises(DutyCycleExceeded) as exc:
        gov.check(1.0, now=36.0)
    assert 0 < exc.value.wait_seconds <= 3600


def test_budget_frees_as_the_window_slides():
    gov = DutyCycleGovernor(duty_cycle=0.01, window_seconds=3600)
    for i in range(36):
        gov.record(1.0, now=float(i))
    gov.check(1.0, now=3700.0)  # everything has aged out


def test_unlimited_duty_cycle_never_blocks():
    gov = DutyCycleGovernor(duty_cycle=None)
    for i in range(1000):
        gov.check(1.0, now=float(i))
        gov.record(1.0, now=float(i))


def test_dwell_limit_blocks_regardless_of_budget():
    gov = DutyCycleGovernor(duty_cycle=None, max_dwell_ms=400)
    gov.check(0.3)
    with pytest.raises(DutyCycleExceeded):
        gov.check(0.5)
    assert gov.dwell_violation(0.5)


def test_utilisation_tracks_usage():
    gov = DutyCycleGovernor(duty_cycle=0.01, window_seconds=3600)
    gov.record(18.0, now=0.0)
    assert gov.utilisation(now=0.0) == pytest.approx(0.5, abs=0.01)


# ---------------------------------------------------------------------------
# regions
# ---------------------------------------------------------------------------


def test_out_of_band_frequency_is_refused():
    eu = get_region("EU868")
    with pytest.raises(RegionError):
        eu.validate(915_000_000, 14)


def test_excess_power_is_refused():
    eu = get_region("EU868")
    with pytest.raises(RegionError):
        eu.validate(868_100_000, 27)


def test_valid_config_passes():
    get_region("EU868").validate(868_100_000, 14)
    get_region("US915").validate(915_000_000, 20)


def test_unknown_region_is_an_error():
    with pytest.raises(RegionError):
        get_region("ATLANTIS")


def test_every_region_is_self_consistent():
    for region in REGIONS.values():
        assert region.freq_min_hz <= region.freq_max_hz
        assert region.describe()


def test_radio_config_validation():
    config = RadioConfig(region="EU868", frequency_hz=868_100_000, tx_power_dbm=14)
    config.validate()

    with pytest.raises(RegionError):
        RadioConfig(region="EU868", frequency_hz=433_000_000).validate()
    with pytest.raises(RegionError):
        RadioConfig(spreading_factor=13).validate()
    with pytest.raises(RegionError):
        RadioConfig(bandwidth_hz=99_999).validate()
    with pytest.raises(RegionError):
        RadioConfig(mtu=999).validate()


def test_default_config_exceeds_us915_dwell_limit():
    """Documents a real constraint rather than pretending the default is universal.

    SF9 with a 200-byte frame is about 1 s on air, which is over the 400 ms
    FCC dwell limit. US915 users need a lower spreading factor.
    """
    config = RadioConfig(region="US915", frequency_hz=915_000_000, spreading_factor=9)
    gov = DutyCycleGovernor(duty_cycle=None, max_dwell_ms=400)
    assert gov.dwell_violation(config.airtime_for(200))

    faster = RadioConfig(region="US915", frequency_hz=915_000_000, spreading_factor=7)
    assert not gov.dwell_violation(faster.airtime_for(200))


# ---------------------------------------------------------------------------
# SLIP framing
# ---------------------------------------------------------------------------


def test_slip_round_trip():
    codec = SlipCodec()
    payload = bytes(range(256))
    assert codec.feed(SlipCodec.encode(payload)) == [payload]


def test_slip_escapes_delimiters():
    payload = b"\xc0\xdb\xc0"
    encoded = SlipCodec.encode(payload)
    assert encoded.count(0xC0) == 2, "delimiters inside the payload were not escaped"
    assert SlipCodec().feed(encoded) == [payload]


def test_slip_handles_split_reads():
    codec = SlipCodec()
    encoded = SlipCodec.encode(b"hello world")
    assert codec.feed(encoded[:5]) == []
    assert codec.feed(encoded[5:]) == [b"hello world"]


def test_slip_recovers_multiple_frames_in_one_read():
    codec = SlipCodec()
    blob = SlipCodec.encode(b"one") + SlipCodec.encode(b"two")
    assert codec.feed(blob) == [b"one", b"two"]
