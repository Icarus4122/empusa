"""Tests for the workspace-summary inspection surface (Phase 42).

Covers:

- the wrapper :func:`evidentia.inspect_workspace_summary` (argv
  shape, byte-for-byte stdout artifact, stderr handling on failure,
  flat-scalar parsing contract),
- the operator-facing CLI command
  :func:`cli_evidentia.cmd_evidentia_workspace_summary`,
- the boundary contract: Empusa parses only top-level scalar
  fields (no per-field semantics, no nested object/array decoding),
- top-level dispatcher wiring through ``empusa.cli``.

The ``evidentia`` binary is not invoked. A fake script that mirrors
the documented exit-code contract is materialised on disk so we
exercise the real ``subprocess`` boundary, the real
``--store badger --path <db>`` argv injection, and the real
artifact-on-disk persistence path.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path

import pytest

from empusa import cli_evidentia, evidentia

# ── Fake binary helpers ───────────────────────────────────────────


def _python_payload(*, stdout: str, stderr: str, exit_code: int, record_argv_to: Path | None) -> str:
    return (
        "import sys, pathlib\n"
        f"stdout = {stdout!r}\n"
        f"stderr = {stderr!r}\n"
        f"exit_code = {exit_code!r}\n"
        f"record = {str(record_argv_to) if record_argv_to else None!r}\n"
        "if record:\n"
        "    with pathlib.Path(record).open('a', encoding='utf-8') as _f:\n"
        "        if _f.tell() > 0:\n"
        "            _f.write('\\n')\n"
        "        _f.write('\\n'.join(sys.argv))\n"
        "if stdout:\n"
        "    sys.stdout.write(stdout)\n"
        "if stderr:\n"
        "    sys.stderr.write(stderr)\n"
        "sys.exit(exit_code)\n"
    )


def _write_fake_binary(
    dirpath: Path,
    *,
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    record_argv_to: Path | None = None,
) -> Path:
    payload = _python_payload(stdout=stdout, stderr=stderr, exit_code=exit_code, record_argv_to=record_argv_to)
    if os.name == "nt":
        py_path = dirpath / "evidentia_impl.py"
        py_path.write_text(payload, encoding="utf-8")
        bat_path = dirpath / "evidentia.bat"
        bat_path.write_text(
            f'@echo off\r\n"{sys.executable}" "{py_path!s}" %*\r\nexit /b %ERRORLEVEL%\r\n',
            encoding="utf-8",
        )
        return bat_path
    path = dirpath / "evidentia"
    path.write_text(f"#!{sys.executable}\n{payload}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


# Representative workspace summary. All values are JSON scalars
# (numbers, strings, or null) so the wrapper's flat-scalar
# acceptance check passes. Per-field semantics are owned by
# Evidentia; the wrapper does not interpret them.
SUMMARY_JSON = (
    "{"
    '"event_count":12,'
    '"schema_failure_count":1,'
    '"directory_user_count":3,'
    '"directory_group_count":2,'
    '"directory_computer_count":1,'
    '"directory_relationship_count":4,'
    '"directory_alias_count":5,'
    '"build_run_count":2,'
    '"latest_event_seq":42,'
    '"latest_build_run_started_at":"2026-04-26T15:00:00Z",'
    '"latest_build_run_completed_at":"2026-04-26T15:00:05Z"'
    "}\n"
)


# ── Wrapper: argv shape and contract ──────────────────────────────


class TestInspectWorkspaceSummaryWrapper:
    def test_argv_shape_with_backend_flags(self, tmp_path: Path, workspace: Path) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        argv_log = tmp_path / "argv.txt"
        binary = _write_fake_binary(bindir, stdout=SUMMARY_JSON, record_argv_to=argv_log)

        outcome = evidentia.inspect_workspace_summary(
            workspace_path=workspace,
            binary=str(binary),
        )

        assert outcome.result.ok
        recorded = argv_log.read_text(encoding="utf-8").splitlines()
        # argv[0] is the binary; backend flags MUST come before the
        # subcommand and the subcommand MUST be exactly
        # ``inspect workspace-summary`` with no extra positional args.
        assert recorded[1:5] == [
            "--store",
            "badger",
            "--path",
            str(workspace / evidentia.DEFAULT_DB_DIRNAME),
        ]
        assert recorded[5:7] == ["inspect", "workspace-summary"]
        # Any trailing argv must be the post-success ``version``
        # provenance call (no backend flags).
        tail = recorded[7:]
        if tail:
            assert tail[-1] == "version", f"unexpected trailing argv: {tail}"

    def test_success_persists_stdout_byte_for_byte(self, tmp_path: Path, workspace: Path) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        binary = _write_fake_binary(bindir, stdout=SUMMARY_JSON)

        outcome = evidentia.inspect_workspace_summary(
            workspace_path=workspace,
            binary=str(binary),
        )

        assert outcome.artifact_path.parent == workspace / evidentia.ARTIFACTS_SUBDIR
        # Filename prefix is distinct from sibling inspect surfaces
        # so status rollups can tell the streams apart.
        assert outcome.artifact_path.name.startswith("inspect-workspace-summary-")
        assert outcome.artifact_path.read_bytes() == SUMMARY_JSON.encode("utf-8")
        meta_path = outcome.artifact_path.with_suffix(outcome.artifact_path.suffix + ".meta.json")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        assert meta["exit_code"] == 0
        assert meta["artifact_path"] == str(outcome.artifact_path)

    def test_scalars_populated_for_flat_object(self, tmp_path: Path, workspace: Path) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        binary = _write_fake_binary(bindir, stdout=SUMMARY_JSON)

        outcome = evidentia.inspect_workspace_summary(
            workspace_path=workspace,
            binary=str(binary),
        )

        assert outcome.scalars is not None
        # The wrapper exposes the parsed mapping but every value
        # MUST already be a JSON scalar. No nested objects/arrays.
        for key, value in outcome.scalars.items():
            assert value is None or isinstance(value, (bool, int, float, str)), (
                f"scalar contract violated for {key}: {value!r} ({type(value).__name__})"
            )

    def test_scalars_is_none_for_non_object_body(self, tmp_path: Path, workspace: Path) -> None:
        """``null`` (or any non-object body) must yield ``scalars =
        None`` so the operator surface cannot accidentally render an
        empty summary as a populated one."""
        bindir = tmp_path / "bin"
        bindir.mkdir()
        binary = _write_fake_binary(bindir, stdout="null\n")

        outcome = evidentia.inspect_workspace_summary(
            workspace_path=workspace,
            binary=str(binary),
        )

        assert outcome.scalars is None
        assert outcome.artifact_path.read_bytes() == b"null\n"

    def test_scalars_is_none_when_object_contains_nested_value(self, tmp_path: Path, workspace: Path) -> None:
        """If Evidentia ever changed the contract from "flat object
        of scalars" to "object containing nested data", the wrapper
        must refuse to treat the body as a parsed summary -- the
        operator surface must surface the contract drift instead of
        silently projecting a partial view."""
        bindir = tmp_path / "bin"
        bindir.mkdir()
        binary = _write_fake_binary(
            bindir,
            stdout='{"event_count":1,"nested":{"k":"v"}}\n',
        )

        outcome = evidentia.inspect_workspace_summary(
            workspace_path=workspace,
            binary=str(binary),
        )

        assert outcome.scalars is None

    def test_failure_persists_stderr_and_raises(self, tmp_path: Path, workspace: Path) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        binary = _write_fake_binary(
            bindir,
            stdout="",
            stderr="evidentia inspect workspace-summary: store error\n",
            exit_code=1,
        )

        with pytest.raises(evidentia.EvidentiaCLIError) as exc:
            evidentia.inspect_workspace_summary(
                workspace_path=workspace,
                binary=str(binary),
            )

        err = exc.value
        assert err.result.exit_code == 1
        assert err.stderr_path is not None
        assert err.stderr_path.exists()
        assert err.stderr_path.name.startswith("inspect-workspace-summary-")
        assert "store error" in err.stderr_path.read_text(encoding="utf-8")
        # No success artifact must have been written.
        art_dir = workspace / evidentia.ARTIFACTS_SUBDIR
        json_artifacts = [
            p for p in art_dir.glob("inspect-workspace-summary-*.json") if not p.name.endswith(".meta.json")
        ]
        assert json_artifacts == []

    def test_wrapper_source_does_not_reference_summary_field_names(self) -> None:
        """The wrapper must treat the summary's keys as opaque: it
        only walks the top-level mapping. Hard-coding any specific
        field name would imply Empusa is decoding a contract owned
        by Evidentia."""
        text = Path(evidentia.__file__).read_text(encoding="utf-8")
        match = re.search(
            r"def inspect_workspace_summary\(.*?(?=\n(?:def |class |@dataclass)|\Z)",
            text,
            flags=re.DOTALL,
        )
        assert match is not None, "could not locate inspect_workspace_summary source block"
        body = match.group(0)
        for forbidden in (
            "event_count",
            "schema_failure_count",
            "directory_user_count",
            "directory_group_count",
            "directory_computer_count",
            "directory_relationship_count",
            "directory_alias_count",
            "build_run_count",
            "latest_event_seq",
            "latest_build_run_started_at",
            "latest_build_run_completed_at",
        ):
            assert forbidden not in body, f"inspect_workspace_summary must not reference summary field {forbidden!r}"


# ── CLI dispatch ──────────────────────────────────────────────────


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


class TestCmdEvidentiaWorkspaceSummary:
    def test_success_displays_artifact_and_scalars(
        self,
        workspace: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        artifact = workspace / "artifacts" / "evidentia" / "inspect-workspace-summary-x.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(SUMMARY_JSON, encoding="utf-8")

        scalars = {
            "event_count": 12,
            "build_run_count": 2,
            "directory_user_count": 3,
            "latest_event_seq": 42,
            "latest_build_run_started_at": "2026-04-26T15:00:00Z",
        }

        calls: list[dict] = []

        def fake_inspect(*, workspace_path, binary, db_path):
            calls.append({"workspace_path": workspace_path, "binary": binary, "db_path": db_path})
            return evidentia.InspectWorkspaceSummaryOutcome(
                artifact_path=artifact,
                scalars=scalars,
                result=_ok_result(SUMMARY_JSON),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "inspect_workspace_summary", fake_inspect)

        args = argparse.Namespace(
            workspace=str(workspace),
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_workspace_summary(args)
        out = capsys.readouterr().out

        assert rc == 0
        assert len(calls) == 1
        assert calls[0]["workspace_path"] == workspace
        assert calls[0]["binary"] == evidentia.DEFAULT_BINARY
        assert calls[0]["db_path"] is None
        assert artifact.name in out
        assert "Exit code" in out
        assert "event_count" in out
        assert "12" in out
        assert "build_run_count" in out

    def test_omits_scalars_when_none(
        self,
        workspace: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        artifact = workspace / "artifacts" / "evidentia" / "inspect-workspace-summary-y.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("null\n", encoding="utf-8")

        def fake_inspect(**_: object) -> evidentia.InspectWorkspaceSummaryOutcome:
            return evidentia.InspectWorkspaceSummaryOutcome(
                artifact_path=artifact,
                scalars=None,
                result=_ok_result("null\n"),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "inspect_workspace_summary", fake_inspect)

        args = argparse.Namespace(
            workspace=str(workspace),
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_workspace_summary(args)
        out = capsys.readouterr().out

        assert rc == 0
        assert "event_count" not in out

    def test_failure_surfaces_stderr_path(
        self,
        workspace: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        stderr_path = workspace / "artifacts" / "evidentia" / "inspect-workspace-summary-x.stderr"
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.write_text("store error\n", encoding="utf-8")

        def fake_inspect(**_: object) -> evidentia.InspectWorkspaceSummaryOutcome:
            raise evidentia.EvidentiaCLIError(
                _fail_result(exit_code=1, stderr="store error"),
                stderr_path=stderr_path,
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "inspect_workspace_summary", fake_inspect)

        args = argparse.Namespace(
            workspace=str(workspace),
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_workspace_summary(args)
        out = capsys.readouterr().out

        assert rc == 1
        assert "exit code: 1" in out.lower()
        assert stderr_path.name in out

    def test_missing_workspace_returns_1(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_inspect(**_: object) -> evidentia.InspectWorkspaceSummaryOutcome:
            raise AssertionError("inspect_workspace_summary must not be called")

        monkeypatch.setattr(cli_evidentia.evidentia, "inspect_workspace_summary", fake_inspect)

        args = argparse.Namespace(
            workspace=str(tmp_path / "nope"),
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_workspace_summary(args)
        assert rc == 1


# ── Top-level dispatch via empusa.cli ─────────────────────────────


class TestTopLevelDispatch:
    def test_workspace_summary_action_dispatches_to_handler(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from empusa import cli as empusa_cli

        ws = tmp_path / "ws"
        ws.mkdir()

        called: list[argparse.Namespace] = []

        def fake_handler(args: argparse.Namespace) -> int:
            called.append(args)
            return 0

        monkeypatch.setattr(empusa_cli, "cmd_evidentia_workspace_summary", fake_handler)
        monkeypatch.setattr(empusa_cli, "_init_framework", lambda: None)
        monkeypatch.setattr(empusa_cli, "_shutdown", lambda: None)

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="cmd")
        cli_evidentia.register_evidentia_parser(sub)

        args = parser.parse_args(["evidentia", "workspace-summary", "--workspace", str(ws)])
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
