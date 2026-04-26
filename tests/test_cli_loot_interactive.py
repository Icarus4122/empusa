"""Interactive flow tests for empusa.cli_loot.loot_tracker.

Drives each menu branch via mocked Prompt/Confirm without touching
real workspaces. No network, no subprocess.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from empusa import cli_loot


def _ans(values: list[str]):
    """Build a Prompt.ask side-effect that returns each value in turn."""
    it: Iterator[str] = iter(values)

    def _cb(*_a, **_kw) -> str:
        return next(it)

    return _cb


def _drive_loot(
    monkeypatch: pytest.MonkeyPatch,
    env_path: Path,
    prompt_answers: list[str],
    confirm: bool = False,
) -> None:
    """Drive loot_tracker with scripted answers. Confirm always returns *confirm*."""
    monkeypatch.setattr(cli_loot.Prompt, "ask", _ans(prompt_answers))
    monkeypatch.setattr(cli_loot.Confirm, "ask", lambda *a, **k: confirm)
    cli_loot.loot_tracker(ask_env_fn=lambda: str(env_path))


# -- env-not-exists branches -----------------------------------------


class TestEnvHandling:
    def test_missing_env_decline_create_returns(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        ghost = tmp_path / "doesnotexist"
        # ask_env_fn returns missing path. Confirm "create?" -> False -> return.
        monkeypatch.setattr(cli_loot.Confirm, "ask", lambda *a, **k: False)
        # No Prompt.ask calls expected because we exit before menu.
        cli_loot.loot_tracker(ask_env_fn=lambda: str(ghost))
        assert not ghost.exists()

    def test_missing_env_accept_create(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        target = tmp_path / "newenv"
        # Confirm True for "Create it anyway?". Then choose "0" to exit.
        monkeypatch.setattr(cli_loot.Confirm, "ask", lambda *a, **k: True)
        monkeypatch.setattr(cli_loot.Prompt, "ask", _ans(["0"]))
        cli_loot.loot_tracker(ask_env_fn=lambda: str(target))
        assert target.exists()
        assert (target / "loot.json").exists()


# -- per-menu-branch dispatch ----------------------------------------


class TestLootTrackerBranches:
    @pytest.fixture
    def env(self, tmp_path: Path) -> Path:
        e = tmp_path / "env"
        e.mkdir()
        return e

    def test_choice_zero_saves_and_exits(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        _drive_loot(monkeypatch, env, ["0"])
        loot = env / "loot.json"
        assert loot.exists()
        assert json.loads(loot.read_text()) == []

    def test_choice_one_adds_entry(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        # add: host, cred_type, username, secret, source, notes -> menu -> 0
        _drive_loot(
            monkeypatch,
            env,
            ["1", "10.0.0.5", "plaintext", "admin", "P@ss", "smb", "notes", "0"],
        )
        data = json.loads((env / "loot.json").read_text())
        assert len(data) == 1
        assert data[0]["username"] == "admin"
        assert data[0]["host"] == "10.0.0.5"

    def test_choice_one_ntlm_emits_tip(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        _drive_loot(
            monkeypatch,
            env,
            ["1", "10.0.0.5", "ntlm", "admin", "deadbeef", "secretsdump", "", "0"],
        )
        data = json.loads((env / "loot.json").read_text())
        assert data[0]["cred_type"] == "ntlm"

    def test_choice_one_kerberos_tip(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        _drive_loot(
            monkeypatch,
            env,
            ["1", "dc01", "kerberos", "krbusr", "tkt", "src", "", "0"],
        )
        data = json.loads((env / "loot.json").read_text())
        assert data[0]["cred_type"] == "kerberos"

    def test_choice_one_sshkey_tip(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        _drive_loot(
            monkeypatch,
            env,
            ["1", "10.0.0.6", "ssh-key", "root", "id_rsa", "loot", "", "0"],
        )

    def test_choice_one_runs_hooks(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        captured: list[tuple[str, dict]] = []

        def hook(name: str, ctx: dict) -> None:
            captured.append((name, ctx))

        monkeypatch.setattr(cli_loot.Prompt, "ask", _ans(["1", "h", "plaintext", "u", "p", "s", "", "0"]))
        monkeypatch.setattr(cli_loot.Confirm, "ask", lambda *a, **k: False)
        cli_loot.loot_tracker(ask_env_fn=lambda: str(env), run_hooks_fn=hook)
        names = [n for n, _ in captured]
        assert "on_loot_add" in names

    def test_choice_two_view(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        # Pre-seed loot.json
        (env / "loot.json").write_text(
            json.dumps(
                [
                    {
                        "host": "h",
                        "cred_type": "plaintext",
                        "username": "u",
                        "secret": "p",
                        "source": "s",
                        "notes": "",
                        "timestamp": "t",
                    }
                ]
            )
        )
        _drive_loot(monkeypatch, env, ["2", "0"])

    def test_choice_three_search_by_host(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        (env / "loot.json").write_text(
            json.dumps(
                [
                    {
                        "host": "10.0.0.1",
                        "cred_type": "plaintext",
                        "username": "a",
                        "secret": "x",
                        "source": "",
                        "notes": "",
                        "timestamp": "",
                    },
                    {
                        "host": "10.0.0.2",
                        "cred_type": "plaintext",
                        "username": "b",
                        "secret": "y",
                        "source": "",
                        "notes": "",
                        "timestamp": "",
                    },
                ]
            )
        )
        # choice + search_type "1" (host) + query + menu 0
        _drive_loot(monkeypatch, env, ["3", "1", "10.0.0.1", "0"])

    def test_choice_three_search_keyword(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        (env / "loot.json").write_text(
            json.dumps(
                [
                    {
                        "host": "h1",
                        "cred_type": "plaintext",
                        "username": "alice",
                        "secret": "secret",
                        "source": "",
                        "notes": "",
                        "timestamp": "",
                    },
                ]
            )
        )
        _drive_loot(monkeypatch, env, ["3", "4", "alice", "0"])

    def test_choice_four_delete_valid(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        (env / "loot.json").write_text(
            json.dumps(
                [
                    {
                        "host": "h",
                        "cred_type": "plaintext",
                        "username": "u",
                        "secret": "p",
                        "source": "",
                        "notes": "",
                        "timestamp": "",
                    },
                ]
            )
        )
        _drive_loot(monkeypatch, env, ["4", "1", "0"])
        data = json.loads((env / "loot.json").read_text())
        assert data == []

    def test_choice_four_delete_empty_skips(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        # No loot file -> empty entries -> "no entries to delete" branch
        _drive_loot(monkeypatch, env, ["4", "0"])

    def test_choice_four_invalid_index(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        (env / "loot.json").write_text(
            json.dumps(
                [
                    {
                        "host": "h",
                        "cred_type": "plaintext",
                        "username": "u",
                        "secret": "p",
                        "source": "",
                        "notes": "",
                        "timestamp": "",
                    },
                ]
            )
        )
        _drive_loot(monkeypatch, env, ["4", "99", "0"])

    def test_choice_four_non_numeric(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        (env / "loot.json").write_text(
            json.dumps(
                [
                    {
                        "host": "h",
                        "cred_type": "plaintext",
                        "username": "u",
                        "secret": "p",
                        "source": "",
                        "notes": "",
                        "timestamp": "",
                    },
                ]
            )
        )
        _drive_loot(monkeypatch, env, ["4", "notanumber", "0"])

    def test_choice_five_import_creds(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        (env / "lab-users.txt").write_text("alice\nbob\n")
        (env / "lab-passwords.txt").write_text("hunter2\n")
        _drive_loot(monkeypatch, env, ["5", "0"])
        data = json.loads((env / "loot.json").read_text())
        usernames = [e["username"] for e in data]
        assert "alice" in usernames

    def test_choice_six_sync(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        (env / "loot.json").write_text(
            json.dumps(
                [
                    {
                        "host": "h",
                        "cred_type": "plaintext",
                        "username": "newuser",
                        "secret": "newpass",
                        "source": "",
                        "notes": "",
                        "timestamp": "",
                    },
                ]
            )
        )
        _drive_loot(monkeypatch, env, ["6", "0"])
        users_file = env / f"{env.name}-users.txt"
        assert users_file.exists()
        assert "newuser" in users_file.read_text()

    def test_choice_seven_reuse(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        _drive_loot(monkeypatch, env, ["7", "0"])

    def test_choice_eight_export(self, monkeypatch: pytest.MonkeyPatch, env: Path) -> None:
        (env / "loot.json").write_text(
            json.dumps(
                [
                    {
                        "host": "h",
                        "cred_type": "plaintext",
                        "username": "u",
                        "secret": "p",
                        "source": "",
                        "notes": "",
                        "timestamp": "",
                    },
                ]
            )
        )
        _drive_loot(monkeypatch, env, ["8", "0"])
        assert (env / "loot_report.md").exists()


# -- error-path coverage ---------------------------------------------


class TestErrorPaths:
    def test_save_loot_handles_write_error(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # Point at a path under a non-existent parent to force write failure
        bad = tmp_path / "nope" / "loot.json"
        cli_loot._save_loot(bad, [{"x": 1}])  # should log_error not raise

    def test_export_loot_handles_write_error(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        bad = tmp_path / "nope" / "report.md"
        cli_loot._export_loot_markdown([{"host": "h"}], bad)
