"""Tests for the possession-proof tool's handling of key material.

The tool's whole reason to read the key from the environment rather than a flag
is that key material must not end up anywhere it can be read later. Moving it
out of argv is only half of that: the libraries that parse a private key put the
offending value straight into their exception messages, so a malformed key would
be printed in full by the default excepthook and collected by whatever gathers
that output. These tests pin both halves.
"""

import sys

import prove_possession
import pytest
from prove_possession import FACTOR_KEY_ENV, VERIFIER_P256, VERIFIER_SECP256K1, main

# Well-formed prefix, wrong length: plausible enough that a library will try to
# parse it and quote it back, which is exactly the case that must not leak.
MALFORMED_KEY = "0xdeadbeefcafe1234567890abcdef"
PROBE_QX = "0x1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83"
PROBE_QY = "0xce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9"


def _run(monkeypatch: pytest.MonkeyPatch, argv: list[str], key: str | None) -> str:
    """Run the tool's entry point, returning the message it exited with."""
    monkeypatch.setattr(sys, "argv", ["prove_possession.py", *argv])
    if key is None:
        monkeypatch.delenv(FACTOR_KEY_ENV, raising=False)
    else:
        monkeypatch.setenv(FACTOR_KEY_ENV, key)
    with pytest.raises(SystemExit) as exit_info:
        main()
    return str(exit_info.value)


def test_a_malformed_secp256k1_key_never_appears_in_the_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    message = _run(
        monkeypatch, ["--slot", "0", "--type", str(VERIFIER_SECP256K1)], MALFORMED_KEY
    )

    assert MALFORMED_KEY not in message
    assert "deadbeef" not in message.lower()
    assert FACTOR_KEY_ENV in message


def test_a_malformed_p256_key_never_appears_in_the_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    message = _run(
        monkeypatch,
        [
            "--slot",
            "1",
            "--type",
            str(VERIFIER_P256),
            "--qx",
            PROBE_QX,
            "--qy",
            PROBE_QY,
        ],
        MALFORMED_KEY,
    )

    assert MALFORMED_KEY not in message
    assert "deadbeef" not in message.lower()
    assert FACTOR_KEY_ENV in message


def test_the_original_exception_is_dropped_rather_than_chained() -> None:
    """A chained cause would print the library's message — and the key with it.

    Exercised on the boundary directly: the length and range checks now refuse
    the malformed keys that used to reach a library, so the boundary is the last
    line of defence against a library that quotes its input for some other
    reason, and it must still drop the original rather than chain it.
    """
    with (
        pytest.raises(SystemExit) as exit_info,
        prove_possession.sanitized_key_errors(),
    ):
        raise ValueError(f"invalid literal for int() with base 16: {MALFORMED_KEY!r}")

    assert MALFORMED_KEY not in str(exit_info.value)
    assert exit_info.value.__cause__ is None
    assert exit_info.value.__suppress_context__ is True


def test_a_valid_key_still_produces_a_proof(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The green-both-ways twin: the boundary must not swallow working input."""
    monkeypatch.setattr(
        sys, "argv", ["prove_possession.py", "--slot", "0", "--type", "1"]
    )
    monkeypatch.setenv(FACTOR_KEY_ENV, "0x" + "11" * 32)

    main()

    printed = capsys.readouterr().out.strip()
    assert printed.startswith("0x")
    assert len(printed) == 2 + 65 * 2  # r||s||v, hex


def test_the_key_is_never_printed_on_the_success_path(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    key = "0x" + "11" * 32
    monkeypatch.setattr(
        sys, "argv", ["prove_possession.py", "--slot", "0", "--type", "1"]
    )
    monkeypatch.setenv(FACTOR_KEY_ENV, key)

    main()

    captured = capsys.readouterr()
    assert key not in captured.out
    assert key not in captured.err


def test_a_key_on_the_command_line_is_refused_by_the_parser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The flags are gone for good: argparse must reject them, not ignore them."""
    monkeypatch.setattr(
        sys,
        "argv",
        ["prove_possession.py", "--slot", "0", "--type", "1", "--key", "0xdeadbeef"],
    )
    monkeypatch.setenv(FACTOR_KEY_ENV, "0x" + "11" * 32)

    with pytest.raises(SystemExit) as exit_info:
        main()

    # The flag NAME may be reported; the value must not be — argparse's own
    # "unrecognized arguments" message would print the key straight to stderr.
    message = str(exit_info.value)
    assert "0xdeadbeef" not in message
    assert "--key" in message
    assert FACTOR_KEY_ENV in message


def test_digest_only_needs_no_key_at_all(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The hardware-backed path: a device key cannot be exported to any variable."""
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prove_possession.py",
            "--slot",
            "1",
            "--type",
            str(VERIFIER_P256),
            "--qx",
            PROBE_QX,
            "--qy",
            PROBE_QY,
            "--digest-only",
        ],
    )
    monkeypatch.delenv(FACTOR_KEY_ENV, raising=False)

    main()

    printed = capsys.readouterr().out.strip()
    assert printed.startswith("0x")
    assert len(printed) == 2 + 32 * 2


def test_the_sanitizing_boundary_lets_a_deliberate_exit_through() -> None:
    """`sys.exit` inside the boundary must not be rewritten as a key error."""
    with (
        pytest.raises(SystemExit) as exit_info,
        prove_possession.sanitized_key_errors(),
    ):
        sys.exit("a deliberate refusal")

    assert str(exit_info.value) == "a deliberate refusal"
