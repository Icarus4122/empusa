"""Tests for empusa.cli_evidentia - operator-facing Evidentia workflow.

These tests monkeypatch the underlying ``empusa.evidentia`` wrapper
functions; the wrapper itself is exercised end-to-end against a fake
``evidentia`` binary in ``test_evidentia.py``. The goal here is to
verify operator-visible behavior:

- the workflow commands call into ``empusa.evidentia`` (and nothing
  else),
- the artifact path is displayed,
- failures surface the stderr artifact path,
- replay divergence triggers the alert and exposes the diff count,
- the wrapper module is the *only* Evidentia bridge imported.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from empusa import cli_evidentia, evidentia


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


def _fail_result(exit_code: int = 1, stderr: str = "boom") -> evidentia.EvidentiaResult:
    return evidentia.EvidentiaResult(
        argv=["evidentia", "--store", "badger", "--path", "x"],
        exit_code=exit_code,
        stdout="",
        stderr=stderr,
    )


# ═══════════════════════════════════════════════════════════════════
#  cmd_evidentia_ingest
# ═══════════════════════════════════════════════════════════════════


class TestCmdEvidentiaIngest:
    def test_calls_ingest_jsonl_and_displays_artifact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        jsonl = ws / "obs.jsonl"
        jsonl.write_text("{}\n", encoding="utf-8")
        artifact = ws / "artifacts" / "evidentia" / "ingest-x.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("{}\n", encoding="utf-8")

        calls: list[dict] = []

        def fake_ingest(*, workspace_path, jsonl_path, binary, db_path):
            calls.append(
                {
                    "workspace_path": workspace_path,
                    "jsonl_path": jsonl_path,
                    "binary": binary,
                    "db_path": db_path,
                }
            )
            return evidentia.IngestOutcome(
                artifact_path=artifact,
                stderr_path=None,
                result=_ok_result(),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_jsonl", fake_ingest)

        args = argparse.Namespace(workspace=str(ws), jsonl=str(jsonl), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_ingest(args)
        out = capsys.readouterr().out
        flat = "".join(out.split())

        assert rc == 0
        assert len(calls) == 1
        assert calls[0]["workspace_path"] == ws
        assert calls[0]["jsonl_path"] == jsonl
        assert calls[0]["binary"] == evidentia.DEFAULT_BINARY
        assert calls[0]["db_path"] is None
        assert artifact.name in out
        assert "".join(str(artifact).split()) in flat
        assert "Exit code" in out

    def test_failure_surfaces_stderr_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        jsonl = ws / "obs.jsonl"
        jsonl.write_text("{}\n", encoding="utf-8")
        stderr_path = ws / "artifacts" / "evidentia" / "ingest-x.stderr"
        stderr_path.parent.mkdir(parents=True)
        stderr_path.write_text("schema failure\n", encoding="utf-8")

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            raise evidentia.EvidentiaCLIError(
                _fail_result(exit_code=1, stderr="schema failure"),
                stderr_path=stderr_path,
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_jsonl", fake_ingest)

        args = argparse.Namespace(workspace=str(ws), jsonl=str(jsonl), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_ingest(args)
        out = capsys.readouterr().out
        flat = "".join(out.split())

        assert rc == 1
        assert "exit code: 1" in out.lower()
        assert stderr_path.name in out
        assert "".join(str(stderr_path).split()) in flat

    def test_missing_workspace_returns_1(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        called: list[bool] = []

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            called.append(True)
            raise AssertionError("ingest_jsonl must not be called")

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_jsonl", fake_ingest)

        args = argparse.Namespace(
            workspace=str(tmp_path / "nope"),
            jsonl=str(tmp_path / "x.jsonl"),
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_ingest(args)
        assert rc == 1
        assert called == []

    def test_missing_jsonl_returns_1(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ws = _ws(tmp_path)
        called: list[bool] = []

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            called.append(True)
            raise AssertionError("ingest_jsonl must not be called")

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_jsonl", fake_ingest)

        args = argparse.Namespace(workspace=str(ws), jsonl=str(ws / "missing.jsonl"), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_ingest(args)
        assert rc == 1
        assert called == []


# ═══════════════════════════════════════════════════════════════════
#  cmd_evidentia_replay
# ═══════════════════════════════════════════════════════════════════


class TestCmdEvidentiaReplay:
    def test_no_divergence_returns_0(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        artifact = ws / "artifacts" / "evidentia" / "replay-x.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text('{"diffs":[]}', encoding="utf-8")

        def fake_replay(*, workspace_path, binary, db_path, alert, write=False):
            assert workspace_path == ws
            # alert MUST NOT be invoked when no divergence.
            return evidentia.ReplayOutcome(
                artifact_path=artifact,
                divergence=False,
                diff_count=0,
                result=_ok_result(),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "replay", fake_replay)

        args = argparse.Namespace(workspace=str(ws), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_replay(args)
        out = capsys.readouterr().out
        flat = "".join(out.split())

        assert rc == 0
        assert "Diff count" in out
        assert artifact.name in out
        assert "".join(str(artifact).split()) in flat
        assert "ALERT" not in out

    def test_divergence_invokes_alert_and_returns_1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        artifact = ws / "artifacts" / "evidentia" / "replay-x.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text('{"diffs":[1,2,3]}', encoding="utf-8")

        def fake_replay(*, workspace_path, binary, db_path, alert, write=False):
            # The wrapper passes its alert callback through; emulate
            # evidentia.replay invoking it on divergence.
            alert(artifact, 3)
            return evidentia.ReplayOutcome(
                artifact_path=artifact,
                divergence=True,
                diff_count=3,
                result=_ok_result(),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "replay", fake_replay)

        args = argparse.Namespace(workspace=str(ws), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_replay(args)
        out = capsys.readouterr().out
        flat = "".join(out.split())

        assert rc == 1
        assert "ALERT" in out
        assert "3 diff" in out
        assert artifact.name in out
        assert "".join(str(artifact).split()) in flat

    def test_failure_surfaces_stderr_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        stderr_path = ws / "artifacts" / "evidentia" / "replay-x.stderr"
        stderr_path.parent.mkdir(parents=True)
        stderr_path.write_text("backend error", encoding="utf-8")

        def fake_replay(**_: object):
            raise evidentia.EvidentiaCLIError(
                _fail_result(exit_code=1, stderr="backend error"),
                stderr_path=stderr_path,
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "replay", fake_replay)

        args = argparse.Namespace(workspace=str(ws), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_replay(args)
        out = capsys.readouterr().out
        flat = "".join(out.split())

        assert rc == 1
        assert stderr_path.name in out
        assert "".join(str(stderr_path).split()) in flat


# ═══════════════════════════════════════════════════════════════════
#  cmd_evidentia_audit
# ═══════════════════════════════════════════════════════════════════


class TestCmdEvidentiaAudit:
    def test_calls_audit_capability_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        artifact = ws / "artifacts" / "evidentia" / "audit-run-1-x.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("{}", encoding="utf-8")

        calls: list[dict] = []

        def fake_audit(*, workspace_path, run_id, binary, db_path):
            calls.append(
                {
                    "workspace_path": workspace_path,
                    "run_id": run_id,
                    "binary": binary,
                    "db_path": db_path,
                }
            )
            return evidentia.AuditOutcome(
                run_id=run_id,
                artifact_path=artifact,
                result=_ok_result(),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "audit_capability_run", fake_audit)

        args = argparse.Namespace(workspace=str(ws), run_id="run-1", binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_audit(args)
        out = capsys.readouterr().out
        flat = "".join(out.split())

        assert rc == 0
        assert calls[0]["run_id"] == "run-1"
        assert artifact.name in out
        assert "".join(str(artifact).split()) in flat

    def test_empty_run_id_returns_1(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ws = _ws(tmp_path)
        called: list[bool] = []

        def fake_audit(**_: object) -> evidentia.AuditOutcome:
            called.append(True)
            raise AssertionError("audit_capability_run must not be called")

        monkeypatch.setattr(cli_evidentia.evidentia, "audit_capability_run", fake_audit)

        args = argparse.Namespace(workspace=str(ws), run_id="", binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_audit(args)
        assert rc == 1
        assert called == []

    def test_failure_surfaces_stderr_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        stderr_path = ws / "artifacts" / "evidentia" / "audit-run-1-x.stderr"
        stderr_path.parent.mkdir(parents=True)
        stderr_path.write_text("not found", encoding="utf-8")

        def fake_audit(**_: object) -> evidentia.AuditOutcome:
            raise evidentia.EvidentiaCLIError(
                _fail_result(exit_code=1, stderr="not found"),
                stderr_path=stderr_path,
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "audit_capability_run", fake_audit)

        args = argparse.Namespace(workspace=str(ws), run_id="run-1", binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_audit(args)
        out = capsys.readouterr().out
        flat = "".join(out.split())

        assert rc == 1
        assert stderr_path.name in out
        assert "".join(str(stderr_path).split()) in flat


# ═══════════════════════════════════════════════════════════════════
#  Phase 19: error classification & output clarity
# ═══════════════════════════════════════════════════════════════════


class TestPhase19ErrorClassification:
    def test_binary_not_found_classified_distinctly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        jsonl = ws / "obs.jsonl"
        jsonl.write_text("{}\n", encoding="utf-8")

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            raise FileNotFoundError("evidentia binary not found: /nope/evidentia")

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_jsonl", fake_ingest)

        args = argparse.Namespace(workspace=str(ws), jsonl=str(jsonl), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_ingest(args)
        out = capsys.readouterr().out

        assert rc == 1
        assert "Evidentia binary not found" in out
        assert "binary not found" in out  # Failure type label
        # Must not be misclassified as a runtime failure.
        assert "runtime failure" not in out
        assert "invalid usage" not in out

    def test_invalid_usage_classified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        jsonl = ws / "obs.jsonl"
        jsonl.write_text("{}\n", encoding="utf-8")

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            raise evidentia.EvidentiaCLIError(_fail_result(exit_code=2, stderr="bad flag"))

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_jsonl", fake_ingest)

        args = argparse.Namespace(workspace=str(ws), jsonl=str(jsonl), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_ingest(args)
        out = capsys.readouterr().out

        assert rc == 1
        assert "exit code: 2" in out.lower()
        assert "invalid usage" in out
        assert "binary not found" not in out

    def test_runtime_failure_classified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)

        def fake_replay(**_: object) -> evidentia.ReplayOutcome:
            raise evidentia.EvidentiaCLIError(_fail_result(exit_code=1, stderr="db locked"))

        monkeypatch.setattr(cli_evidentia.evidentia, "replay", fake_replay)

        args = argparse.Namespace(workspace=str(ws), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_replay(args)
        out = capsys.readouterr().out

        assert rc == 1
        assert "runtime failure" in out
        assert "binary not found" not in out
        assert "invalid usage" not in out

    def test_timeout_classified_as_runtime(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)

        def fake_replay(**_: object) -> evidentia.ReplayOutcome:
            raise evidentia.EvidentiaCLIError(_fail_result(exit_code=124, stderr="evidentia timed out after 5s"))

        monkeypatch.setattr(cli_evidentia.evidentia, "replay", fake_replay)

        args = argparse.Namespace(workspace=str(ws), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_replay(args)
        out = capsys.readouterr().out

        assert rc == 1
        assert "runtime failure (timeout)" in out


class TestPhase19OutputClarity:
    def test_ingest_displays_accepted_and_failed_counts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        jsonl = ws / "obs.jsonl"
        jsonl.write_text("{}\n", encoding="utf-8")
        artifact = ws / "artifacts" / "evidentia" / "ingest-x.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("{}\n", encoding="utf-8")

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            return evidentia.IngestOutcome(
                artifact_path=artifact,
                stderr_path=None,
                result=_ok_result(stdout='{"accepted":7,"failed":2}\n'),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_jsonl", fake_ingest)

        args = argparse.Namespace(workspace=str(ws), jsonl=str(jsonl), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_ingest(args)
        out = capsys.readouterr().out

        assert rc == 0
        assert "Accepted" in out
        assert "7" in out
        assert "Failed" in out
        assert "2" in out

    def test_ingest_omits_counts_when_payload_lacks_fields(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        jsonl = ws / "obs.jsonl"
        jsonl.write_text("{}\n", encoding="utf-8")
        artifact = ws / "artifacts" / "evidentia" / "ingest-x.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("{}\n", encoding="utf-8")

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            return evidentia.IngestOutcome(
                artifact_path=artifact,
                stderr_path=None,
                result=_ok_result(stdout="{}\n"),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_jsonl", fake_ingest)

        args = argparse.Namespace(workspace=str(ws), jsonl=str(jsonl), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_ingest(args)
        out = capsys.readouterr().out

        # Existing scriptable markers preserved.
        assert rc == 0
        assert "Exit code" in out
        assert "Artifact" in out
        # No fabricated counts when the payload omits the fields.
        assert "Accepted" not in out
        assert "Failed" not in out

    def test_replay_no_divergence_line(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        artifact = ws / "artifacts" / "evidentia" / "replay-x.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text('{"diffs":[]}', encoding="utf-8")

        def fake_replay(*, workspace_path, binary, db_path, alert, write=False):
            return evidentia.ReplayOutcome(
                artifact_path=artifact,
                divergence=False,
                diff_count=0,
                result=_ok_result(),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "replay", fake_replay)

        args = argparse.Namespace(workspace=str(ws), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_replay(args)
        out = capsys.readouterr().out

        assert rc == 0
        assert "No divergence" in out

    def test_replay_divergence_detected_line(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        artifact = ws / "artifacts" / "evidentia" / "replay-x.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text('{"diffs":[1,2]}', encoding="utf-8")

        def fake_replay(*, workspace_path, binary, db_path, alert, write=False):
            alert(artifact, 2)
            return evidentia.ReplayOutcome(
                artifact_path=artifact,
                divergence=True,
                diff_count=2,
                result=_ok_result(),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "replay", fake_replay)

        args = argparse.Namespace(workspace=str(ws), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_replay(args)
        out = capsys.readouterr().out

        assert rc == 1
        assert "detected: 2 diff(s)" in out
        # Existing markers preserved.
        assert "ALERT" in out
        assert "Diff count" in out


# ═══════════════════════════════════════════════════════════════════
#  Phase 19: cmd_evidentia_status
# ═══════════════════════════════════════════════════════════════════


def _seed_artifact(ws: Path, name: str, payload: str, *, mtime: float | None = None) -> Path:
    """Drop a JSON artifact under the workspace's evidentia/ directory."""
    artifacts = ws / evidentia.ARTIFACTS_SUBDIR
    artifacts.mkdir(parents=True, exist_ok=True)
    path = artifacts / name
    path.write_text(payload, encoding="utf-8")
    if mtime is not None:
        import os as _os

        _os.utime(path, (mtime, mtime))
    return path


class TestCmdEvidentiaStatus:
    def test_empty_workspace_passes_with_none_markers(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        ws = _ws(tmp_path)
        args = argparse.Namespace(workspace=str(ws))
        rc = cli_evidentia.cmd_evidentia_status(args)
        out = capsys.readouterr().out

        assert rc == 0
        assert "<none>" in out
        assert "No Evidentia artifacts" in out
        # Heading per kind is present for operator clarity.
        assert "Latest ingest" in out
        assert "Latest replay" in out
        assert "Latest audit" in out

    def test_picks_latest_per_kind(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        ws = _ws(tmp_path)
        # Older ingest then newer ingest.
        old = _seed_artifact(
            ws,
            "ingest-old.json",
            '{"accepted":1,"failed":0}\n',
            mtime=1_000_000_000.0,
        )
        new = _seed_artifact(
            ws,
            "ingest-new.json",
            '{"accepted":5,"failed":1}\n',
            mtime=2_000_000_000.0,
        )
        # Replay with divergence.
        replay_art = _seed_artifact(
            ws,
            "replay-1.json",
            '{"diffs":[1,2,3]}\n',
            mtime=2_000_000_500.0,
        )
        # Audit without summary fields (we never parse it).
        audit_art = _seed_artifact(
            ws,
            "audit-run-1.json",
            '{"opaque":"do not parse"}\n',
            mtime=2_000_001_000.0,
        )

        args = argparse.Namespace(workspace=str(ws))
        rc = cli_evidentia.cmd_evidentia_status(args)
        out = capsys.readouterr().out
        flat = "".join(out.split())

        assert rc == 0
        assert "".join(str(new).split()) in flat
        assert "".join(str(old).split()) not in flat
        assert "Accepted" in out and "5" in out
        assert "Failed" in out and "1" in out
        assert "".join(str(replay_art).split()) in flat
        assert "detected: 3 diff(s)" in out
        assert "".join(str(audit_art).split()) in flat

    def test_status_does_not_invoke_evidentia_binary(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """`status` is a workspace roll-up; it must never run a subprocess."""
        ws = _ws(tmp_path)

        def boom(*_a: object, **_k: object) -> object:
            raise AssertionError("status must not invoke evidentia subprocess")

        monkeypatch.setattr(cli_evidentia.evidentia, "run_evidentia_command", boom)
        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_jsonl", boom)
        monkeypatch.setattr(cli_evidentia.evidentia, "replay", boom)
        monkeypatch.setattr(cli_evidentia.evidentia, "audit_capability_run", boom)

        args = argparse.Namespace(workspace=str(ws))
        rc = cli_evidentia.cmd_evidentia_status(args)
        assert rc == 0

    def test_missing_workspace_returns_1(self, tmp_path: Path) -> None:
        args = argparse.Namespace(workspace=str(tmp_path / "nope"))
        rc = cli_evidentia.cmd_evidentia_status(args)
        assert rc == 1


# ═══════════════════════════════════════════════════════════════════
#  Phase 19: cmd_evidentia_run
# ═══════════════════════════════════════════════════════════════════


class TestCmdEvidentiaRun:
    def test_runs_ingest_then_replay_in_order(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        jsonl = ws / "obs.jsonl"
        jsonl.write_text("{}\n", encoding="utf-8")
        ingest_art = ws / "artifacts" / "evidentia" / "ingest-x.json"
        ingest_art.parent.mkdir(parents=True)
        ingest_art.write_text("{}\n", encoding="utf-8")
        replay_art = ws / "artifacts" / "evidentia" / "replay-x.json"
        replay_art.write_text('{"diffs":[]}', encoding="utf-8")

        order: list[str] = []

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            order.append("ingest")
            return evidentia.IngestOutcome(
                artifact_path=ingest_art,
                stderr_path=None,
                result=_ok_result(stdout='{"accepted":1,"failed":0}\n'),
            )

        def fake_replay(*, workspace_path, binary, db_path, alert, write=False):
            order.append("replay")
            return evidentia.ReplayOutcome(
                artifact_path=replay_art,
                divergence=False,
                diff_count=0,
                result=_ok_result(),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_jsonl", fake_ingest)
        monkeypatch.setattr(cli_evidentia.evidentia, "replay", fake_replay)

        args = argparse.Namespace(workspace=str(ws), jsonl=str(jsonl), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_run(args)
        out = capsys.readouterr().out

        assert rc == 0
        assert order == ["ingest", "replay"]
        assert "Step 1/2" in out
        assert "Step 2/2" in out
        assert "ingest + replay" in out

    def test_aborts_at_ingest_failure_and_skips_replay(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        jsonl = ws / "obs.jsonl"
        jsonl.write_text("{}\n", encoding="utf-8")
        stderr_art = ws / "artifacts" / "evidentia" / "ingest-x.stderr"
        stderr_art.parent.mkdir(parents=True)
        stderr_art.write_text("schema failure\n", encoding="utf-8")

        replay_called: list[bool] = []

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            raise evidentia.EvidentiaCLIError(
                _fail_result(exit_code=1, stderr="schema failure"),
                stderr_path=stderr_art,
            )

        def fake_replay(**_: object) -> evidentia.ReplayOutcome:
            replay_called.append(True)
            raise AssertionError("replay must not run after ingest failure")

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_jsonl", fake_ingest)
        monkeypatch.setattr(cli_evidentia.evidentia, "replay", fake_replay)

        args = argparse.Namespace(workspace=str(ws), jsonl=str(jsonl), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_run(args)
        out = capsys.readouterr().out

        assert rc == 1
        assert replay_called == []
        assert "aborted at ingest" in out

    def test_propagates_replay_divergence_exit_code(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        jsonl = ws / "obs.jsonl"
        jsonl.write_text("{}\n", encoding="utf-8")
        ingest_art = ws / "artifacts" / "evidentia" / "ingest-x.json"
        ingest_art.parent.mkdir(parents=True)
        ingest_art.write_text("{}\n", encoding="utf-8")
        replay_art = ws / "artifacts" / "evidentia" / "replay-x.json"
        replay_art.write_text('{"diffs":[1,2]}', encoding="utf-8")

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            return evidentia.IngestOutcome(
                artifact_path=ingest_art,
                stderr_path=None,
                result=_ok_result(),
            )

        def fake_replay(*, workspace_path, binary, db_path, alert, write=False):
            alert(replay_art, 2)
            return evidentia.ReplayOutcome(
                artifact_path=replay_art,
                divergence=True,
                diff_count=2,
                result=_ok_result(),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_jsonl", fake_ingest)
        monkeypatch.setattr(cli_evidentia.evidentia, "replay", fake_replay)

        args = argparse.Namespace(workspace=str(ws), jsonl=str(jsonl), binary=None, db_path=None)
        rc = cli_evidentia.cmd_evidentia_run(args)
        out = capsys.readouterr().out

        assert rc == 1
        assert "aborted at replay" in out

    def test_missing_jsonl_returns_1(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ws = _ws(tmp_path)

        def boom(**_: object) -> object:
            raise AssertionError("must not be called when jsonl is missing")

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_jsonl", boom)
        monkeypatch.setattr(cli_evidentia.evidentia, "replay", boom)

        args = argparse.Namespace(
            workspace=str(ws),
            jsonl=str(ws / "missing.jsonl"),
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_run(args)
        assert rc == 1


# ═══════════════════════════════════════════════════════════════════
#  Phase 19: scriptable output guard
# ═══════════════════════════════════════════════════════════════════


class TestScriptableOutputPreserved:
    """Guarantee that line markers downstream scripts may grep for survive Phase 19."""

    def test_ingest_success_keeps_existing_markers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        jsonl = ws / "obs.jsonl"
        jsonl.write_text("{}\n", encoding="utf-8")
        artifact = ws / "artifacts" / "evidentia" / "ingest-x.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("{}\n", encoding="utf-8")

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            return evidentia.IngestOutcome(
                artifact_path=artifact,
                stderr_path=None,
                result=_ok_result(stdout='{"accepted":1,"failed":0}\n'),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_jsonl", fake_ingest)
        args = argparse.Namespace(workspace=str(ws), jsonl=str(jsonl), binary=None, db_path=None)
        cli_evidentia.cmd_evidentia_ingest(args)
        out = capsys.readouterr().out
        for marker in ("Exit code", "Artifact", "[PASS]"):
            assert marker in out

    def test_replay_success_keeps_existing_markers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ws = _ws(tmp_path)
        artifact = ws / "artifacts" / "evidentia" / "replay-x.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text('{"diffs":[]}', encoding="utf-8")

        def fake_replay(*, workspace_path, binary, db_path, alert, write=False):
            return evidentia.ReplayOutcome(
                artifact_path=artifact,
                divergence=False,
                diff_count=0,
                result=_ok_result(),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "replay", fake_replay)
        args = argparse.Namespace(workspace=str(ws), binary=None, db_path=None)
        cli_evidentia.cmd_evidentia_replay(args)
        out = capsys.readouterr().out
        for marker in ("Exit code", "Artifact", "Diff count", "[PASS]"):
            assert marker in out


# ═══════════════════════════════════════════════════════════════════
#  Contract guard
# ═══════════════════════════════════════════════════════════════════


def test_workflow_only_imports_evidentia_via_wrapper() -> None:
    """The workflow must not reach into Evidentia directly.

    Only ``empusa.evidentia`` is allowed as the bridge module.
    """
    src = Path(cli_evidentia.__file__).read_text(encoding="utf-8")
    forbidden = (
        "import pkg.",
        "from pkg.",
        "github.com/Icarus4122/Evidentia",
        "import badger",
        "from badger",
        "import evidentia.",  # any non-empusa evidentia.* path
    )
    for needle in forbidden:
        assert needle not in src, f"forbidden import surface: {needle}"

    # Permitted bridge import is present.
    assert "from empusa import evidentia" in src
