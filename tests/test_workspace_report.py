"""Tests for the workspace evidence report (Phase 43).

Covers:

- the wrapper :func:`evidentia.generate_workspace_report` composes
  the existing inspection wrappers and writes a NEW Empusa-owned
  artifact under ``artifacts/evidentia/report-<timestamp>.json``
  without re-shelling Evidentia or duplicating raw stdout payloads,
- warning emission for schema failures, replay divergence, missing
  build runs, and an empty directory entity surface,
- the operator-facing CLI command
  :func:`cli_evidentia.cmd_evidentia_report`,
- top-level dispatcher wiring through ``empusa.cli``,
- the boundary contract: no direct Evidentia source/store imports.

The report is built by COMPOSITION: it must call only the existing
``inspect_workspace_summary`` and ``replay`` wrappers. The tests
monkeypatch those wrappers and assert the composition properties
directly; the report itself never spawns ``evidentia``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from empusa import cli_evidentia, evidentia


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


def _ok_result(stdout: str = "") -> evidentia.EvidentiaResult:
    return evidentia.EvidentiaResult(
        argv=["evidentia", "--store", "badger", "--path", "x"],
        exit_code=0,
        stdout=stdout,
        stderr="",
    )


def _make_summary_outcome(
    workspace: Path,
    *,
    scalars: dict[str, object] | None,
    name: str = "inspect-workspace-summary-x.json",
) -> evidentia.InspectWorkspaceSummaryOutcome:
    art = workspace / "artifacts" / "evidentia" / name
    art.parent.mkdir(parents=True, exist_ok=True)
    art.write_text(
        json.dumps(scalars) if scalars is not None else "null",
        encoding="utf-8",
    )
    return evidentia.InspectWorkspaceSummaryOutcome(
        artifact_path=art,
        scalars=scalars,
        result=_ok_result(art.read_text(encoding="utf-8")),
    )


def _make_replay_outcome(
    workspace: Path,
    *,
    diff_count: int = 0,
    name: str = "replay-x.json",
) -> evidentia.ReplayOutcome:
    art = workspace / "artifacts" / "evidentia" / name
    art.parent.mkdir(parents=True, exist_ok=True)
    art.write_text(json.dumps({"diffs": [{} for _ in range(diff_count)]}), encoding="utf-8")
    return evidentia.ReplayOutcome(
        artifact_path=art,
        divergence=diff_count > 0,
        diff_count=diff_count,
        result=_ok_result(art.read_text(encoding="utf-8")),
    )


def _patch_wrappers(
    monkeypatch: pytest.MonkeyPatch,
    *,
    summary_outcome: evidentia.InspectWorkspaceSummaryOutcome,
    replay_outcome: evidentia.ReplayOutcome,
    spawn_guard: bool = True,
) -> dict[str, list[dict]]:
    """Install fake wrappers and return per-call argument logs."""

    calls: dict[str, list[dict]] = {"summary": [], "replay": [], "raw": []}

    def fake_summary(*, workspace_path, binary, db_path, timeout=None):
        calls["summary"].append({"workspace_path": workspace_path, "binary": binary, "db_path": db_path})
        return summary_outcome

    def fake_replay(*, workspace_path, binary, db_path, alert=None, write=False):
        calls["replay"].append(
            {
                "workspace_path": workspace_path,
                "binary": binary,
                "db_path": db_path,
                "write": write,
                "alert_passed": alert is not None,
            }
        )
        return replay_outcome

    monkeypatch.setattr(evidentia, "inspect_workspace_summary", fake_summary)
    monkeypatch.setattr(evidentia, "replay", fake_replay)

    if spawn_guard:
        # The report must compose existing wrappers only -- it must
        # NEVER reach for the binary directly.
        def fake_spawn(*_a, **_kw):
            calls["raw"].append({"args": _a, "kwargs": _kw})
            raise AssertionError("generate_workspace_report must not call run_evidentia_command")

        monkeypatch.setattr(evidentia, "run_evidentia_command", fake_spawn)

    return calls


# ── Wrapper: composition + persistence ────────────────────────────


class TestGenerateWorkspaceReport:
    def test_calls_existing_wrappers_only(self, monkeypatch: pytest.MonkeyPatch, workspace: Path) -> None:
        scalars = {
            "event_count": 5,
            "schema_failure_count": 0,
            "directory_user_count": 1,
            "directory_group_count": 1,
            "directory_computer_count": 1,
            "directory_relationship_count": 1,
            "directory_alias_count": 1,
            "build_run_count": 1,
            "latest_event_seq": 5,
            "latest_build_run_started_at": "2026-04-26T14:00:00Z",
            "latest_build_run_completed_at": "2026-04-26T14:00:05Z",
        }
        summary_outcome = _make_summary_outcome(workspace, scalars=scalars)
        replay_outcome = _make_replay_outcome(workspace, diff_count=0)
        calls = _patch_wrappers(
            monkeypatch,
            summary_outcome=summary_outcome,
            replay_outcome=replay_outcome,
        )

        outcome = evidentia.generate_workspace_report(
            workspace_path=workspace,
            binary="ev-bin",
            db_path=workspace / "evidentia.db",
        )

        assert calls["raw"] == []
        assert len(calls["summary"]) == 1
        assert len(calls["replay"]) == 1
        # The report must propagate caller arguments verbatim and
        # MUST request a read-only replay (write=False).
        assert calls["summary"][0]["binary"] == "ev-bin"
        assert calls["summary"][0]["workspace_path"] == workspace
        assert calls["summary"][0]["db_path"] == workspace / "evidentia.db"
        assert calls["replay"][0]["write"] is False
        assert calls["replay"][0]["binary"] == "ev-bin"
        assert outcome.summary_outcome is summary_outcome
        assert outcome.replay_outcome is replay_outcome

    def test_persists_new_report_artifact(self, monkeypatch: pytest.MonkeyPatch, workspace: Path) -> None:
        scalars = {
            "event_count": 3,
            "schema_failure_count": 0,
            "directory_user_count": 1,
            "directory_group_count": 0,
            "directory_computer_count": 0,
            "directory_relationship_count": 0,
            "directory_alias_count": 0,
            "build_run_count": 1,
            "latest_event_seq": 3,
            "latest_build_run_started_at": "2026-04-26T14:00:00Z",
            "latest_build_run_completed_at": None,
        }
        summary_outcome = _make_summary_outcome(workspace, scalars=scalars)
        replay_outcome = _make_replay_outcome(workspace, diff_count=0)
        _patch_wrappers(
            monkeypatch,
            summary_outcome=summary_outcome,
            replay_outcome=replay_outcome,
        )

        outcome = evidentia.generate_workspace_report(workspace_path=workspace)

        # Filename prefix and location.
        assert outcome.artifact_path.parent == workspace / evidentia.ARTIFACTS_SUBDIR
        assert outcome.artifact_path.name.startswith("report-")
        assert outcome.artifact_path.suffix == ".json"
        # The raw underlying artifacts must STILL exist alongside the
        # new report artifact -- the report must not move, copy, or
        # rewrite them.
        assert summary_outcome.artifact_path.exists()
        assert replay_outcome.artifact_path.exists()
        assert outcome.artifact_path != summary_outcome.artifact_path
        assert outcome.artifact_path != replay_outcome.artifact_path

        body = json.loads(outcome.artifact_path.read_text(encoding="utf-8"))
        assert body == outcome.report
        assert body["workspace_path"] == str(workspace)
        assert body["summary_artifact"] == str(summary_outcome.artifact_path)
        assert body["replay_artifact"] == str(replay_outcome.artifact_path)
        assert body["replay_diff_count"] == 0
        assert body["counts"] == scalars
        assert isinstance(body["generated_at"], str) and body["generated_at"].endswith("Z")
        assert isinstance(body["warnings"], list)

    def test_warnings_emitted_for_failures_diffs_and_empty_state(
        self, monkeypatch: pytest.MonkeyPatch, workspace: Path
    ) -> None:
        scalars = {
            "event_count": 7,
            "schema_failure_count": 2,
            "directory_user_count": 0,
            "directory_group_count": 0,
            "directory_computer_count": 0,
            "directory_relationship_count": 0,
            "directory_alias_count": 0,
            "build_run_count": 0,
            "latest_event_seq": 7,
            "latest_build_run_started_at": None,
            "latest_build_run_completed_at": None,
        }
        summary_outcome = _make_summary_outcome(workspace, scalars=scalars)
        replay_outcome = _make_replay_outcome(workspace, diff_count=3)
        _patch_wrappers(
            monkeypatch,
            summary_outcome=summary_outcome,
            replay_outcome=replay_outcome,
        )

        outcome = evidentia.generate_workspace_report(workspace_path=workspace)

        warnings = outcome.report["warnings"]
        assert isinstance(warnings, list)
        assert evidentia.REPORT_WARNING_SCHEMA_FAILURES in warnings
        assert evidentia.REPORT_WARNING_REPLAY_DIVERGED in warnings
        assert evidentia.REPORT_WARNING_NO_BUILD_RUNS in warnings
        assert evidentia.REPORT_WARNING_DIRECTORY_EMPTY in warnings
        assert outcome.report["replay_diff_count"] == 3

    def test_no_warnings_when_workspace_is_healthy(self, monkeypatch: pytest.MonkeyPatch, workspace: Path) -> None:
        scalars = {
            "event_count": 9,
            "schema_failure_count": 0,
            "directory_user_count": 1,
            "directory_group_count": 0,
            "directory_computer_count": 0,
            "directory_relationship_count": 0,
            "directory_alias_count": 0,
            "build_run_count": 2,
            "latest_event_seq": 9,
            "latest_build_run_started_at": "2026-04-26T14:00:00Z",
            "latest_build_run_completed_at": "2026-04-26T14:00:05Z",
        }
        summary_outcome = _make_summary_outcome(workspace, scalars=scalars)
        replay_outcome = _make_replay_outcome(workspace, diff_count=0)
        _patch_wrappers(
            monkeypatch,
            summary_outcome=summary_outcome,
            replay_outcome=replay_outcome,
        )

        outcome = evidentia.generate_workspace_report(workspace_path=workspace)
        assert outcome.report["warnings"] == []

    def test_summary_failure_propagates(self, monkeypatch: pytest.MonkeyPatch, workspace: Path) -> None:
        def fake_summary(**_: object):
            raise evidentia.EvidentiaCLIError(
                evidentia.EvidentiaResult(argv=["evidentia"], exit_code=1, stdout="", stderr="boom")
            )

        called_replay = []

        def fake_replay(**kwargs):
            called_replay.append(kwargs)
            raise AssertionError("replay must not be called when summary fails")

        monkeypatch.setattr(evidentia, "inspect_workspace_summary", fake_summary)
        monkeypatch.setattr(evidentia, "replay", fake_replay)

        with pytest.raises(evidentia.EvidentiaCLIError):
            evidentia.generate_workspace_report(workspace_path=workspace)
        assert called_replay == []


# ── CLI dispatch ──────────────────────────────────────────────────


class TestCmdEvidentiaReport:
    def test_success_prints_artifacts_and_warning_count(
        self,
        monkeypatch: pytest.MonkeyPatch,
        workspace: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        scalars = {
            "event_count": 1,
            "schema_failure_count": 1,
            "directory_user_count": 1,
            "directory_group_count": 0,
            "directory_computer_count": 0,
            "directory_relationship_count": 0,
            "directory_alias_count": 0,
            "build_run_count": 0,
            "latest_event_seq": 1,
            "latest_build_run_started_at": None,
            "latest_build_run_completed_at": None,
        }
        summary_outcome = _make_summary_outcome(workspace, scalars=scalars)
        replay_outcome = _make_replay_outcome(workspace, diff_count=0)
        report_artifact = workspace / "artifacts" / "evidentia" / "report-x.json"
        report_artifact.parent.mkdir(parents=True, exist_ok=True)
        report_body = {
            "generated_at": "2026-04-26T14:30:00Z",
            "workspace_path": str(workspace),
            "summary_artifact": str(summary_outcome.artifact_path),
            "replay_artifact": str(replay_outcome.artifact_path),
            "replay_diff_count": 0,
            "counts": scalars,
            "warnings": [
                evidentia.REPORT_WARNING_SCHEMA_FAILURES,
                evidentia.REPORT_WARNING_NO_BUILD_RUNS,
            ],
        }
        report_artifact.write_text(json.dumps(report_body), encoding="utf-8")

        def fake_generate(*, workspace_path, binary, db_path):
            return evidentia.WorkspaceReportOutcome(
                artifact_path=report_artifact,
                report=report_body,
                summary_outcome=summary_outcome,
                replay_outcome=replay_outcome,
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "generate_workspace_report", fake_generate)

        args = argparse.Namespace(workspace=str(workspace), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_report(args)
        out = capsys.readouterr().out

        assert rc == 0
        assert report_artifact.name in out
        assert summary_outcome.artifact_path.name in out
        assert replay_outcome.artifact_path.name in out
        assert "Warnings" in out
        assert "2" in out
        assert evidentia.REPORT_WARNING_SCHEMA_FAILURES in out
        assert evidentia.REPORT_WARNING_NO_BUILD_RUNS in out
        # Counts surface in operator output too.
        assert "event_count" in out
        assert "build_run_count" in out

    def test_replay_divergence_returns_failure(
        self,
        monkeypatch: pytest.MonkeyPatch,
        workspace: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        summary_outcome = _make_summary_outcome(workspace, scalars={"event_count": 1})
        replay_outcome = _make_replay_outcome(workspace, diff_count=2)
        report_artifact = workspace / "artifacts" / "evidentia" / "report-y.json"
        report_artifact.parent.mkdir(parents=True, exist_ok=True)
        report_body = {
            "generated_at": "2026-04-26T14:30:00Z",
            "workspace_path": str(workspace),
            "summary_artifact": str(summary_outcome.artifact_path),
            "replay_artifact": str(replay_outcome.artifact_path),
            "replay_diff_count": 2,
            "counts": {"event_count": 1},
            "warnings": [evidentia.REPORT_WARNING_REPLAY_DIVERGED],
        }
        report_artifact.write_text(json.dumps(report_body), encoding="utf-8")

        def fake_generate(**_: object):
            return evidentia.WorkspaceReportOutcome(
                artifact_path=report_artifact,
                report=report_body,
                summary_outcome=summary_outcome,
                replay_outcome=replay_outcome,
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "generate_workspace_report", fake_generate)

        args = argparse.Namespace(workspace=str(workspace), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_report(args)
        out = capsys.readouterr().out

        assert rc == 1
        assert "diverged" in out.lower() or "divergence" in out.lower()

    def test_failure_surfaces_failure(
        self,
        monkeypatch: pytest.MonkeyPatch,
        workspace: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        def fake_generate(**_: object):
            raise evidentia.EvidentiaCLIError(
                evidentia.EvidentiaResult(argv=["evidentia"], exit_code=1, stdout="", stderr="store error")
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "generate_workspace_report", fake_generate)

        args = argparse.Namespace(workspace=str(workspace), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_report(args)
        out = capsys.readouterr().out

        assert rc == 1
        assert "exit code: 1" in out.lower()

    def test_missing_workspace_returns_1(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        def fake_generate(**_: object):
            raise AssertionError("generate_workspace_report must not be called")

        monkeypatch.setattr(cli_evidentia.evidentia, "generate_workspace_report", fake_generate)

        args = argparse.Namespace(workspace=str(tmp_path / "nope"), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_report(args)
        assert rc == 1


# ── Top-level dispatch via empusa.cli ─────────────────────────────


class TestTopLevelDispatch:
    def test_report_action_dispatches_to_handler(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli as empusa_cli

        ws = tmp_path / "ws"
        ws.mkdir()

        called: list[argparse.Namespace] = []

        def fake_handler(args: argparse.Namespace) -> int:
            called.append(args)
            return 0

        monkeypatch.setattr(empusa_cli, "cmd_evidentia_report", fake_handler)
        monkeypatch.setattr(empusa_cli, "_init_framework", lambda: None)
        monkeypatch.setattr(empusa_cli, "_shutdown", lambda: None)

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="cmd")
        cli_evidentia.register_evidentia_parser(sub)

        args = parser.parse_args(["evidentia", "report", "--workspace", str(ws)])
        rc = empusa_cli._cmd_evidentia(args, parser)

        assert rc == 0
        assert len(called) == 1
        assert called[0].workspace == str(ws)


# ── Boundary discipline ───────────────────────────────────────────


class TestBoundaryDiscipline:
    def test_no_evidentia_or_badger_imports_in_empusa_modules(self) -> None:
        forbidden_substrings = (
            "evidentia.pkg",
            "Evidentia.pkg",
            "github.com/Icarus4122/Evidentia",
            "badger",
            "bsddb",
        )
        for mod_path in (Path(evidentia.__file__), Path(cli_evidentia.__file__)):
            text = mod_path.read_text(encoding="utf-8")
            for line in text.splitlines():
                stripped = line.lstrip()
                if not (stripped.startswith("import ") or stripped.startswith("from ")):
                    continue
                lowered = stripped.lower()
                for bad in forbidden_substrings:
                    assert bad.lower() not in lowered, f"forbidden import substring {bad!r} in {mod_path}: {stripped!r}"
