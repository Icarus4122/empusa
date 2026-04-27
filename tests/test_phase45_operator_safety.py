"""Tests for Phase 45 operator command safety + naming.

Covers:

- ``empusa evidentia quickflow`` exists and forwards to the same
  wrapper path as the legacy ``run`` subcommand,
- ``empusa evidentia run`` still works but emits a deprecation
  warning and delegates to ``quickflow``,
- ``empusa evidentia replay --write`` without ``--confirm-write``
  is refused (non-zero exit) with an explanatory message,
- ``empusa evidentia replay --write --confirm-write`` proceeds and
  passes ``write=True`` through to the wrapper,
- read-only ``empusa evidentia replay`` (no flags) is unchanged,
- ``empusa evidentia status`` advertises its artifact-only scope in
  both help text and stdout,
- the ``directory inspect --type`` and ``evidentia report`` help
  text was clarified,
- top-level dispatcher routes the new ``quickflow`` action,
- no direct Evidentia source imports / no Badger access in the
  modified Empusa modules.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from empusa import cli_directory, cli_evidentia, evidentia


def _ws(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


def _ok_result(stdout: str = "{}\n") -> evidentia.EvidentiaResult:
    return evidentia.EvidentiaResult(
        argv=["evidentia", "--store", "badger", "--path", "x"],
        exit_code=0,
        stdout=stdout,
        stderr="",
    )


def _stub_quickflow_wrappers(
    monkeypatch: pytest.MonkeyPatch,
    workspace: Path,
) -> dict[str, list[dict]]:
    """Patch ingest_jsonl + replay so cmd_evidentia_quickflow runs in-process."""
    calls: dict[str, list[dict]] = {"ingest": [], "replay": []}

    ingest_art = workspace / "artifacts" / "evidentia" / "ingest-x.json"
    ingest_art.parent.mkdir(parents=True, exist_ok=True)
    ingest_art.write_text("{}\n", encoding="utf-8")
    replay_art = workspace / "artifacts" / "evidentia" / "replay-x.json"
    replay_art.write_text('{"diffs":[]}', encoding="utf-8")

    def fake_ingest(**kw: object) -> evidentia.IngestOutcome:
        calls["ingest"].append(dict(kw))
        return evidentia.IngestOutcome(
            artifact_path=ingest_art,
            stderr_path=None,
            result=_ok_result(stdout='{"accepted":1,"failed":0}\n'),
        )

    def fake_replay(**kw: object) -> evidentia.ReplayOutcome:
        calls["replay"].append(dict(kw))
        return evidentia.ReplayOutcome(
            artifact_path=replay_art,
            divergence=False,
            diff_count=0,
            result=_ok_result(),
        )

    monkeypatch.setattr(cli_evidentia.evidentia, "ingest_jsonl", fake_ingest)
    monkeypatch.setattr(cli_evidentia.evidentia, "replay", fake_replay)
    return calls


# ── quickflow ──────────────────────────────────────────────────────


class TestQuickflow:
    def test_quickflow_calls_same_wrappers_as_run(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        ws = _ws(tmp_path)
        jsonl = ws / "obs.jsonl"
        jsonl.write_text("{}\n", encoding="utf-8")
        calls = _stub_quickflow_wrappers(monkeypatch, ws)

        args = argparse.Namespace(workspace=str(ws), jsonl=str(jsonl), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_quickflow(args)
        out = capsys.readouterr().out

        assert rc == 0
        assert len(calls["ingest"]) == 1
        assert len(calls["replay"]) == 1
        assert "Quickflow" in out or "quickflow" in out
        assert "Step 1/2" in out
        assert "Step 2/2" in out

    def test_run_emits_deprecation_warning_and_forwards(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        ws = _ws(tmp_path)
        jsonl = ws / "obs.jsonl"
        jsonl.write_text("{}\n", encoding="utf-8")
        calls = _stub_quickflow_wrappers(monkeypatch, ws)

        args = argparse.Namespace(workspace=str(ws), jsonl=str(jsonl), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_run(args)
        out = capsys.readouterr().out

        assert rc == 0
        assert "empusa evidentia run is deprecated; use empusa evidentia quickflow." in out
        # The deprecated alias must have driven the same wrappers.
        assert len(calls["ingest"]) == 1
        assert len(calls["replay"]) == 1

    def test_run_delegates_via_quickflow_handler(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """``run`` must NOT inline a second copy of the flow -- it
        must delegate to ``cmd_evidentia_quickflow`` so the two stay
        in lock-step."""
        ws = _ws(tmp_path)
        jsonl = ws / "obs.jsonl"
        jsonl.write_text("{}\n", encoding="utf-8")

        delegated: list[argparse.Namespace] = []

        def fake_quickflow(a: argparse.Namespace) -> int:
            delegated.append(a)
            return 0

        monkeypatch.setattr(cli_evidentia, "cmd_evidentia_quickflow", fake_quickflow)
        args = argparse.Namespace(workspace=str(ws), jsonl=str(jsonl), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_run(args)

        assert rc == 0
        assert len(delegated) == 1
        assert delegated[0] is args


# ── replay write safety ───────────────────────────────────────────


class TestReplayWriteSafety:
    def test_write_without_confirm_write_is_refused(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        ws = _ws(tmp_path)

        def fake_replay(**_: object) -> evidentia.ReplayOutcome:
            raise AssertionError("replay must not be called without --confirm-write")

        monkeypatch.setattr(cli_evidentia.evidentia, "replay", fake_replay)

        args = argparse.Namespace(
            workspace=str(ws),
            binary=None,
            db_path=None,
            write=True,
            confirm_write=False,
        )
        rc = cli_evidentia.cmd_evidentia_replay(args)
        out = capsys.readouterr().out

        assert rc != 0
        assert "--confirm-write" in out
        # Operator should learn WHY this is destructive.
        assert "live" in out.lower() and "store" in out.lower()

    def test_write_with_confirm_write_succeeds(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        ws = _ws(tmp_path)
        artifact = ws / "artifacts" / "evidentia" / "replay-x.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text('{"diffs":[]}', encoding="utf-8")

        seen: list[bool] = []

        def fake_replay(*, workspace_path, binary, db_path, alert, write=False):
            seen.append(write)
            return evidentia.ReplayOutcome(
                artifact_path=artifact,
                divergence=False,
                diff_count=0,
                result=_ok_result(),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "replay", fake_replay)

        args = argparse.Namespace(
            workspace=str(ws),
            binary=None,
            db_path=None,
            write=True,
            confirm_write=True,
        )
        rc = cli_evidentia.cmd_evidentia_replay(args)

        assert rc == 0
        assert seen == [True]

    def test_confirm_write_alone_is_refused(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        ws = _ws(tmp_path)

        def fake_replay(**_: object) -> evidentia.ReplayOutcome:
            raise AssertionError("replay must not be called when --confirm-write is set without --write")

        monkeypatch.setattr(cli_evidentia.evidentia, "replay", fake_replay)

        args = argparse.Namespace(
            workspace=str(ws),
            binary=None,
            db_path=None,
            write=False,
            confirm_write=True,
        )
        rc = cli_evidentia.cmd_evidentia_replay(args)
        out = capsys.readouterr().out

        assert rc != 0
        assert "--confirm-write" in out and "--write" in out

    def test_read_only_replay_unchanged(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Read-only replay (the default) must keep working with the
        existing namespace shape -- no new required flags.
        """
        ws = _ws(tmp_path)
        artifact = ws / "artifacts" / "evidentia" / "replay-x.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text('{"diffs":[]}', encoding="utf-8")

        seen: list[bool] = []

        def fake_replay(*, workspace_path, binary, db_path, alert, write=False):
            seen.append(write)
            return evidentia.ReplayOutcome(
                artifact_path=artifact,
                divergence=False,
                diff_count=0,
                result=_ok_result(),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "replay", fake_replay)

        # Note: legacy callers do NOT supply write/confirm_write at all.
        args = argparse.Namespace(workspace=str(ws), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_replay(args)
        assert rc == 0
        assert seen == [False]


# ── status scope clarification ────────────────────────────────────


class TestStatusScopeClarification:
    def test_status_help_text_is_artifact_only(self) -> None:
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="cmd")
        cli_evidentia.register_evidentia_parser(sub)
        help_text = parser.format_help() + "\n"
        # Render the evidentia subparser help so we can read the
        # status entry's help string.
        ev_help = ""
        for action in parser._actions:  # type: ignore[attr-defined]
            if isinstance(action, argparse._SubParsersAction):
                ev_parser = action.choices.get("evidentia")
                if ev_parser is not None:
                    ev_help = ev_parser.format_help()
                    break
        combined = help_text + ev_help
        assert "artifact-only" in combined.lower() or "does not query" in combined.lower()

    def test_status_output_advertises_artifact_only_scope(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        # No artifacts -- still needs to print scope notice.
        args = argparse.Namespace(workspace=str(ws))
        rc = cli_evidentia.cmd_evidentia_status(args)
        out = capsys.readouterr().out

        assert rc == 0
        assert "artifact-only" in out.lower()
        assert "does not query" in out.lower()


# ── help text polish ──────────────────────────────────────────────


class TestHelpTextPolish:
    def test_directory_inspect_type_help_mentions_neighbors_memberships(self) -> None:
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="cmd")
        cli_directory.register_directory_parser(sub)
        # Drill to the directory inspect subparser.
        dir_parser = None
        for action in parser._actions:  # type: ignore[attr-defined]
            if isinstance(action, argparse._SubParsersAction):
                dir_parser = action.choices.get("directory")
                break
        assert dir_parser is not None
        inspect_parser = None
        for action in dir_parser._actions:  # type: ignore[attr-defined]
            if isinstance(action, argparse._SubParsersAction):
                inspect_parser = action.choices.get("inspect")
                break
        assert inspect_parser is not None
        help_text = inspect_parser.format_help()
        assert "neighbors" in help_text
        assert "memberships" in help_text
        assert "one-hop" in help_text or "targeted" in help_text

    def test_evidentia_report_help_mentions_composition(self) -> None:
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="cmd")
        cli_evidentia.register_evidentia_parser(sub)
        ev_parser = None
        for action in parser._actions:  # type: ignore[attr-defined]
            if isinstance(action, argparse._SubParsersAction):
                ev_parser = action.choices.get("evidentia")
                break
        assert ev_parser is not None
        help_text = ev_parser.format_help()
        assert "workspace-summary" in help_text
        assert "replay" in help_text


# ── top-level dispatch ────────────────────────────────────────────


class TestQuickflowTopLevelDispatch:
    def test_quickflow_action_dispatches_to_handler(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli as empusa_cli

        ws = _ws(tmp_path)
        jsonl = ws / "obs.jsonl"
        jsonl.write_text("{}\n", encoding="utf-8")

        called: list[argparse.Namespace] = []

        def fake_handler(args: argparse.Namespace) -> int:
            called.append(args)
            return 0

        monkeypatch.setattr(empusa_cli, "cmd_evidentia_quickflow", fake_handler)
        monkeypatch.setattr(empusa_cli, "_init_framework", lambda: None)
        monkeypatch.setattr(empusa_cli, "_shutdown", lambda: None)

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="cmd")
        cli_evidentia.register_evidentia_parser(sub)

        args = parser.parse_args(["evidentia", "quickflow", "--workspace", str(ws), "--jsonl", str(jsonl)])
        rc = empusa_cli._cmd_evidentia(args, parser)

        assert rc == 0
        assert len(called) == 1
        assert called[0].workspace == str(ws)


# ── boundary discipline ──────────────────────────────────────────


class TestBoundaryDiscipline:
    def test_no_evidentia_or_badger_imports(self) -> None:
        forbidden = (
            "evidentia.pkg",
            "Evidentia.pkg",
            "github.com/Icarus4122/Evidentia",
            "badger",
            "bsddb",
        )
        for mod_path in (
            Path(cli_evidentia.__file__),
            Path(cli_directory.__file__),
        ):
            text = mod_path.read_text(encoding="utf-8")
            for line in text.splitlines():
                stripped = line.lstrip()
                if not (stripped.startswith("import ") or stripped.startswith("from ")):
                    continue
                lowered = stripped.lower()
                for bad in forbidden:
                    assert bad.lower() not in lowered, f"forbidden import substring {bad!r} in {mod_path}: {stripped!r}"
