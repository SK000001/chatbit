"""The reference implementation must match the committed test vectors.

This is the guard against silent protocol drift. Any change to a key
derivation, a domain separation string, a wire offset or a padding rule
changes the vectors, and this fails until they are regenerated deliberately
with ``python tools/generate_vectors.py``.

That deliberateness is the point. Once other implementations exist, a
regenerated vector file is a protocol version bump, not a routine diff.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "vectors"

sys.path.insert(0, str(ROOT / "tools"))

import verify_vectors  # noqa: E402


VECTOR_FILES = [
    "primitives.json",
    "noise_xx.json",
    "ratchet.json",
    "wire.json",
    "tags_identity.json",
]


def test_all_vector_files_exist():
    missing = [name for name in VECTOR_FILES if not (VECTORS / name).exists()]
    assert not missing, f"missing vector files: {missing}"


@pytest.mark.parametrize("name", VECTOR_FILES)
def test_vector_file_is_valid_json(name):
    with open(VECTORS / name) as fh:
        blob = json.load(fh)
    assert blob.get("description"), f"{name} has no description"


def test_implementation_matches_vectors():
    checker = verify_vectors.run(verbose=False)
    assert not checker.failures, "\n" + "\n".join(checker.failures)
    assert checker.passed > 100, f"only {checker.passed} checks ran; expected the full suite"


def test_generator_is_deterministic(tmp_path):
    """Regenerating must reproduce the committed files byte for byte.

    Catches two things: accidental non-determinism in the generator (a stray
    random key, a dict iteration order), and vectors that were edited by hand
    rather than regenerated.
    """
    before = {name: (VECTORS / name).read_bytes() for name in VECTOR_FILES}

    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "generate_vectors.py")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"generator failed:\n{result.stderr}"

    after = {name: (VECTORS / name).read_bytes() for name in VECTOR_FILES}
    drifted = [name for name in VECTOR_FILES if before[name] != after[name]]
    assert not drifted, (
        f"regenerating changed {drifted}. Either the protocol changed (bump the "
        "version and commit the new vectors) or the generator is not deterministic."
    )


def test_noise_vector_covers_full_transcript():
    """The Noise vector must expose intermediate state, not just final keys.

    A port that only gets the final handshake hash has no way to localise a
    divergence; per-message h and ck are what make a mismatch diagnosable.
    """
    with open(VECTORS / "noise_xx.json") as fh:
        blob = json.load(fh)

    steps = {s["step"] for s in blob["transcript"]}
    assert {"initialize", "message_1", "message_2", "message_3"} <= steps

    for step in blob["transcript"]:
        if step["step"] == "initialize":
            continue
        assert "h" in step and "ck" in step, f"{step['step']} lacks intermediate state"


def test_ratchet_vector_exercises_the_hard_paths():
    """Sequential sends alone would not catch the bugs ports actually hit."""
    with open(VECTORS / "ratchet.json") as fh:
        blob = json.load(fh)

    headers = [m["header"] for m in blob["messages"]]

    # More than one ratchet public key means the DH ratchet actually turned.
    assert len({h["ratchet_public"] for h in headers}) >= 3, "no DH ratchet steps"

    # A non-zero pn means a chain was closed with messages still outstanding.
    assert any(h["pn"] > 0 for h in headers), "no previous-chain counter exercised"

    # Both directions must appear.
    assert {m["from"] for m in blob["messages"]} == {"initiator", "responder"}

    # Out-of-order delivery: some message is delivered before an earlier one.
    deliveries = [s["index"] for s in blob["schedule"] if s["op"] == "deliver"]
    assert deliveries != sorted(deliveries), "delivery order is monotonic"

    # Non-empty associated data must be covered.
    assert any(m["associated_data"] for m in blob["messages"])


def test_primitives_vector_catches_nonce_endianness():
    """n=0 and n=1 pass under either byte order; the vector must go further."""
    with open(VECTORS / "primitives.json") as fh:
        blob = json.load(fh)

    counters = {c["n"] for c in blob["chacha20poly1305_noise_nonce"]["cases"]}
    assert any(n >= 2**32 for n in counters), (
        "nonce vectors only cover small counters, which cannot distinguish "
        "little-endian from big-endian encoding"
    )
