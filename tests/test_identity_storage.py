"""Identity files at rest, and the CLI plumbing that decides how they are written.

The library could always encrypt an identity; until now the CLI never asked for
a passphrase, so in practice every private key on disk was in the clear. These
tests cover both halves so the capability and the tool cannot drift apart
again.
"""

from __future__ import annotations

import json
import os

import pytest

from chatbit.cli import build_parser, resolve_passphrase
from chatbit.crypto.identity import Identity, TrustError


# ---------------------------------------------------------------------------
# on-disk format
# ---------------------------------------------------------------------------


def test_encrypted_round_trip(tmp_path):
    path = tmp_path / "id.json"
    original = Identity.generate("alice")
    original.save(path, passphrase="correct horse")

    loaded = Identity.load(path, passphrase="correct horse")
    assert loaded.signing_public == original.signing_public
    assert loaded.static_public == original.static_public
    assert loaded.nickname == "alice"


def test_encrypted_file_contains_no_key_material(tmp_path):
    path = tmp_path / "id.json"
    identity = Identity.generate("alice")
    identity.save(path, passphrase="correct horse")

    raw = path.read_bytes()
    blob = json.loads(raw)

    assert blob["enc"] == "scrypt-chacha20poly1305"
    assert set(blob) == {"v", "enc", "salt", "nonce", "ct"}
    # The private keys must not appear anywhere in the file, in any encoding.
    from chatbit.crypto.primitives import (
        ed25519_private_bytes,
        x25519_private_bytes,
    )

    for secret in (
        ed25519_private_bytes(identity.signing_private),
        x25519_private_bytes(identity.static_private),
    ):
        assert secret not in raw
        assert secret.hex().encode() not in raw


def test_wrong_passphrase_fails(tmp_path):
    path = tmp_path / "id.json"
    Identity.generate("alice").save(path, passphrase="right")
    with pytest.raises(Exception):
        Identity.load(path, passphrase="wrong")


def test_encrypted_file_requires_a_passphrase(tmp_path):
    path = tmp_path / "id.json"
    Identity.generate("alice").save(path, passphrase="secret")
    with pytest.raises(TrustError, match="passphrase"):
        Identity.load(path)


def test_is_encrypted_detection(tmp_path):
    encrypted = tmp_path / "enc.json"
    plain = tmp_path / "plain.json"
    Identity.generate("a").save(encrypted, passphrase="secret")
    Identity.generate("b").save(plain)

    assert Identity.is_encrypted(encrypted) is True
    assert Identity.is_encrypted(plain) is False
    assert Identity.is_encrypted(tmp_path / "missing.json") is False


def test_is_encrypted_tolerates_junk(tmp_path):
    junk = tmp_path / "junk.json"
    junk.write_text("this is not json")
    assert Identity.is_encrypted(junk) is False


@pytest.mark.skipif(
    os.name == "nt", reason="Windows has no POSIX permission bits; see the test below"
)
def test_unencrypted_file_is_owner_only_on_posix(tmp_path):
    import stat

    path = tmp_path / "id.json"
    Identity.generate("alice").save(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, f"identity file mode is {mode:o}, expected 600"


@pytest.mark.skipif(os.name != "nt", reason="documents Windows-specific behaviour")
def test_windows_cannot_restrict_the_file_mode(tmp_path):
    """Documents a real gap rather than skipping quietly past it.

    ``os.chmod`` on Windows can only toggle the read-only flag -- POSIX
    permission bits do not exist there, so the 0600 we request is a no-op and
    the file ends up 0666. An unencrypted identity on Windows is therefore
    protected only by whatever NTFS ACLs it inherits from its directory, which
    is a much weaker guarantee than the one this project makes on POSIX.

    Closing it properly means manipulating ACLs through pywin32 or icacls.
    Until then the honest mitigation is a passphrase, and the CLI says so when
    it writes an unencrypted identity on Windows.
    """
    import stat

    path = tmp_path / "id.json"
    Identity.generate("alice").save(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode != 0o600, (
        "Windows now honours POSIX permission bits -- if this ever passes, the "
        "warning in Identity.save and SECURITY.md should be revisited"
    )


# ---------------------------------------------------------------------------
# CLI passphrase resolution
# ---------------------------------------------------------------------------


def parse(*argv):
    return build_parser().parse_args([*argv, "id"])


def test_passphrase_comes_from_the_environment(tmp_path, monkeypatch):
    path = tmp_path / "id.json"
    Identity.generate("alice").save(path, passphrase="from-env")
    monkeypatch.setenv("CHATBIT_PASSPHRASE", "from-env")

    args = parse("--identity", str(path))
    assert resolve_passphrase(path, args) == "from-env"


def test_custom_environment_variable(tmp_path, monkeypatch):
    path = tmp_path / "id.json"
    monkeypatch.setenv("MY_SECRET", "abc123")
    args = parse("--identity", str(path), "--passphrase-env", "MY_SECRET")
    assert resolve_passphrase(path, args) == "abc123"


def test_existing_plaintext_file_is_not_prompted_for(tmp_path, monkeypatch):
    path = tmp_path / "id.json"
    Identity.generate("alice").save(path)
    monkeypatch.delenv("CHATBIT_PASSPHRASE", raising=False)

    args = parse("--identity", str(path))
    assert resolve_passphrase(path, args) is None


def test_no_encrypt_skips_prompting(tmp_path, monkeypatch):
    path = tmp_path / "new.json"
    monkeypatch.delenv("CHATBIT_PASSPHRASE", raising=False)

    args = parse("--identity", str(path), "--no-encrypt")
    assert resolve_passphrase(path, args) is None


def test_encrypted_file_without_a_tty_fails_clearly(tmp_path, monkeypatch):
    """Better a precise error than a hanging prompt in a script or CI job."""
    path = tmp_path / "id.json"
    Identity.generate("alice").save(path, passphrase="secret")
    monkeypatch.delenv("CHATBIT_PASSPHRASE", raising=False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    args = parse("--identity", str(path))
    with pytest.raises(SystemExit, match="CHATBIT_PASSPHRASE"):
        resolve_passphrase(path, args)


def test_passphrase_flag_is_rejected():
    """A regression test for a genuinely dangerous argparse behaviour.

    Without an explicit ``--passphrase`` option, argparse prefix-matching
    resolves it to ``--passphrase-env``. The secret is then read as an
    environment *variable name*, no such variable exists, and the identity is
    written unencrypted -- while the passphrase sits in argv for `ps` and shell
    history to pick up. Silently doing the opposite of what was asked is worse
    than refusing.
    """
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--passphrase", "hunter2", "id"])


def test_passphrase_env_flag_still_works():
    args = build_parser().parse_args(
        ["--passphrase-env", "SOME_VAR", "id"]
    )
    assert args.passphrase_env == "SOME_VAR"
