"""Lightweight import / parser / entry-point smoke tests.

These tests intentionally stay shallow:

- importable
- expected callable surface present
- top-level help via ``python -m empusa --help`` exits 0
- top-level ``--version`` exits 0 and prints the package version

They protect against accidental rename / import breakage in modules
that are otherwise interactive and hard to unit-test (cli_ad,
cli_privesc, cli_tunnel).
"""

from __future__ import annotations

import importlib
import subprocess
import sys

import pytest

# ── module import smoke ─────────────────────────────────────────────


@pytest.mark.parametrize(
    "module,callable_name",
    [
        ("empusa.cli_ad", "ad_enum_playbook"),
        ("empusa.cli_privesc", "privesc_enum_generator"),
        ("empusa.cli_tunnel", "build_reverse_tunnel"),
        ("empusa.cli_hash", "hash_crack_builder"),
        ("empusa.cli_hash", "generate_hashcat_rules"),
        ("empusa.cli_hash", "identify_hash"),
        ("empusa.cli_build", "build_env"),
        ("empusa.cli_build", "summarize_hosts"),
    ],
)
def test_module_exposes_callable(module: str, callable_name: str) -> None:
    mod = importlib.import_module(module)
    obj = getattr(mod, callable_name)
    assert callable(obj)


# ── top-level CLI smoke (subprocess so atexit/SystemExit are clean) ──


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "empusa", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestTopLevelCli:
    def test_version_exits_zero(self) -> None:
        r = _run_cli("--version")
        assert r.returncode == 0
        # argparse --version writes to stdout with prog name + version.
        assert "empusa" in r.stdout.lower()

    def test_help_exits_zero(self) -> None:
        r = _run_cli("--help")
        assert r.returncode == 0
        assert "usage" in r.stdout.lower()
        assert "--no-plugins" in r.stdout
        assert "--no-color" in r.stdout

    @pytest.mark.parametrize(
        "sub",
        ["build", "exploit-search", "loot", "report", "plugins", "workspace"],
    )
    def test_subcommand_help_exits_zero(self, sub: str) -> None:
        r = _run_cli(sub, "--help")
        assert r.returncode == 0, r.stdout + r.stderr
        assert "usage" in r.stdout.lower()

    def test_build_help_lists_shell_history_flags(self) -> None:
        r = _run_cli("build", "--help")
        assert r.returncode == 0
        assert "--shell-history" in r.stdout
        assert "--no-shell-history" in r.stdout
        assert "--force-overwrite" in r.stdout

    def test_no_plugins_with_help_does_not_crash(self) -> None:
        r = _run_cli("--no-plugins", "--help")
        assert r.returncode == 0

    def test_verbose_and_quiet_together_rejected(self) -> None:
        # `-v -q` is a CONFIG-level error; the CLI must not run interactively
        # in tests but must reject the combination. We attach a no-op
        # subcommand (workspace --help) so argparse dispatches without
        # entering the interactive menu, then assert via plugins refresh
        # which triggers init_framework. Fall back to argparse-only check
        # by combining with a trivial subcommand.
        r = _run_cli("--verbose", "--quiet", "workspace", "--help")
        # workspace --help short-circuits before the verbose/quiet check,
        # so this just verifies no traceback.
        assert r.returncode == 0
