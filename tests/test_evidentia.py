"""
Tests for the Empusa → Evidentia CLI consumer
(``empusa/evidentia.py``).

The Evidentia binary itself is never invoked by these tests. Instead a
fake ``evidentia`` script is materialised on disk for each scenario
(success, runtime failure, usage error). This keeps the suite hermetic
while still exercising the real ``subprocess`` boundary, the real
exit-code routing, and the real artifact-on-disk persistence path.

These tests pin the integration contract documented in
``Evidentia/docs/integration/empusa-evidentia.md``:

- stdout is persisted byte-for-byte,
- stderr is persisted only on failure,
- exit code 2 is surfaced as a usage error and never auto-retried,
- replay divergence is detected from the top-level ``diffs`` array
  alone (no schema transformation),
- the consumer never imports Evidentia source.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from empusa import evidentia

# -- Fake binary helpers ---------------------------------------------


def _write_fake_binary(
    dirpath: Path,
    *,
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    record_argv_to: Path | None = None,
) -> Path:
    """Write a tiny executable script that mimics ``evidentia``.

    The script writes ``stdout`` to fd1, ``stderr`` to fd2, optionally
    records its argv to ``record_argv_to`` (one arg per line), and
    exits with ``exit_code``. On Windows the script is a ``.bat`` that
    shells out to the same Python interpreter; on POSIX it is a
    ``#!/usr/bin/env python3`` script. Either way the resulting file
    behaves like a real executable on PATH.
    """
    if os.name == "nt":
        return _write_fake_binary_windows(
            dirpath,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            record_argv_to=record_argv_to,
        )
    return _write_fake_binary_posix(
        dirpath,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        record_argv_to=record_argv_to,
    )


def _python_payload(
    *,
    stdout: str,
    stderr: str,
    exit_code: int,
    record_argv_to: Path | None,
) -> str:
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


def _write_fake_binary_posix(
    dirpath: Path,
    *,
    stdout: str,
    stderr: str,
    exit_code: int,
    record_argv_to: Path | None,
) -> Path:
    path = dirpath / "evidentia"
    payload = _python_payload(stdout=stdout, stderr=stderr, exit_code=exit_code, record_argv_to=record_argv_to)
    path.write_text(
        f"#!{sys.executable}\n{payload}",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _write_fake_binary_windows(
    dirpath: Path,
    *,
    stdout: str,
    stderr: str,
    exit_code: int,
    record_argv_to: Path | None,
) -> Path:
    py_path = dirpath / "evidentia_impl.py"
    py_path.write_text(
        _python_payload(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            record_argv_to=record_argv_to,
        ),
        encoding="utf-8",
    )
    bat_path = dirpath / "evidentia.bat"
    bat_path.write_text(
        f'@echo off\r\n"{sys.executable}" "{str(py_path)}" %*\r\nexit /b %ERRORLEVEL%\r\n',
        encoding="utf-8",
    )
    return bat_path


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


@pytest.fixture()
def jsonl_file(workspace: Path) -> Path:
    f = workspace / "observations.jsonl"
    # The contents are opaque to Empusa; the fake binary does not read
    # them. A non-empty file is enough to satisfy the existence check.
    f.write_text('{"placeholder":true}\n', encoding="utf-8")
    return f


# -- run_evidentia_command -------------------------------------------


def test_run_evidentia_command_builds_argv_with_backend_flags(tmp_path: Path, workspace: Path) -> None:
    """The wrapper MUST inject ``--store badger --path <db>`` between the
    binary and the user's command, per §2 of the contract."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    argv_log = tmp_path / "argv.txt"
    binary = _write_fake_binary(bindir, stdout='{"version":"0.1.0"}\n', record_argv_to=argv_log)

    result = evidentia.run_evidentia_command(["version"], workspace_path=workspace, binary=str(binary))

    assert result.ok
    assert result.exit_code == 0
    assert result.stdout == '{"version":"0.1.0"}\n'
    recorded = argv_log.read_text(encoding="utf-8").splitlines()
    # argv[0] is the binary; the next four MUST be the backend flags
    # in this exact order, and the user's positional arg comes last.
    assert recorded[1:6] == [
        "--store",
        "badger",
        "--path",
        str(workspace / evidentia.DEFAULT_DB_DIRNAME),
        "version",
    ]


def test_run_evidentia_command_empty_cmd_is_rejected(workspace: Path) -> None:
    with pytest.raises(ValueError):
        evidentia.run_evidentia_command([], workspace_path=workspace)


def test_run_evidentia_command_missing_workspace(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        evidentia.run_evidentia_command(["version"], workspace_path=tmp_path / "nope")


# -- ingest_jsonl ----------------------------------------------------


def test_ingest_jsonl_success_persists_stdout_byte_for_byte(tmp_path: Path, workspace: Path, jsonl_file: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    summary = '{"records_read":3,"accepted":2,"failed":1,"event_ids":["a","b"],"failure_event_ids":["c"]}\n'
    binary = _write_fake_binary(bindir, stdout=summary)

    outcome = evidentia.ingest_jsonl(
        workspace_path=workspace,
        jsonl_path=jsonl_file,
        binary=str(binary),
    )

    assert outcome.result.ok
    assert outcome.stderr_path is None
    assert outcome.artifact_path.parent == workspace / evidentia.ARTIFACTS_SUBDIR
    # Byte-for-byte preservation: the artifact is exactly what
    # Evidentia emitted on stdout, no re-serialisation.
    assert outcome.artifact_path.read_text(encoding="utf-8") == summary
    # The artifact MUST still be valid JSON (we did not corrupt it).
    decoded = json.loads(outcome.artifact_path.read_text(encoding="utf-8"))
    assert decoded["accepted"] == 2


def test_ingest_jsonl_runtime_failure_persists_stderr_and_raises(
    tmp_path: Path, workspace: Path, jsonl_file: Path
) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(
        bindir,
        stdout="",
        stderr="evidentia ingest jsonl: open: no such file\n",
        exit_code=1,
    )

    with pytest.raises(evidentia.EvidentiaCLIError) as exc:
        evidentia.ingest_jsonl(
            workspace_path=workspace,
            jsonl_path=jsonl_file,
            binary=str(binary),
        )

    err = exc.value
    assert err.result.exit_code == 1
    assert err.stderr_path is not None
    assert err.stderr_path.exists()
    assert "no such file" in err.stderr_path.read_text(encoding="utf-8")
    # No success artifact must have been written.
    art_dir = workspace / evidentia.ARTIFACTS_SUBDIR
    json_artifacts = [p for p in art_dir.glob("ingest-*.json") if not p.name.endswith(".meta.json")]
    assert json_artifacts == []


def test_ingest_jsonl_usage_error_is_not_retried(tmp_path: Path, workspace: Path, jsonl_file: Path) -> None:
    """Exit 2 surfaces as ``EvidentiaCLIError`` with ``is_usage_error``
    set; the wrapper itself never retries (single subprocess.run
    invocation per call)."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    call_log = tmp_path / "calls.txt"
    binary = _write_fake_binary(
        bindir,
        stdout="",
        stderr="evidentia ingest: unknown subcommand\n",
        exit_code=2,
        record_argv_to=call_log,
    )

    with pytest.raises(evidentia.EvidentiaCLIError) as exc:
        evidentia.ingest_jsonl(
            workspace_path=workspace,
            jsonl_path=jsonl_file,
            binary=str(binary),
        )

    assert exc.value.result.exit_code == 2
    assert exc.value.result.is_usage_error
    # The fake records argv on every invocation; there must be exactly
    # one set of argv lines, proving no retry occurred.
    assert call_log.read_text(encoding="utf-8").count("--store") == 1


def test_ingest_jsonl_missing_input_file(workspace: Path) -> None:
    with pytest.raises(FileNotFoundError):
        evidentia.ingest_jsonl(
            workspace_path=workspace,
            jsonl_path=workspace / "missing.jsonl",
            binary="evidentia",  # never invoked; fail before exec
        )


# -- audit_capability_run --------------------------------------------


def test_audit_capability_run_persists_artifact(tmp_path: Path, workspace: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    payload = '{"run_id":"run-123","status":"ok"}\n'
    binary = _write_fake_binary(bindir, stdout=payload)

    outcome = evidentia.audit_capability_run(
        workspace_path=workspace,
        run_id="run-123",
        binary=str(binary),
    )

    assert outcome.run_id == "run-123"
    assert outcome.artifact_path.exists()
    assert outcome.artifact_path.read_text(encoding="utf-8") == payload
    # Filename includes the run id so artifacts correlate with the
    # source capability run without requiring a second index.
    assert "run-123" in outcome.artifact_path.name


def test_audit_capability_run_not_found_raises(tmp_path: Path, workspace: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(
        bindir,
        stdout="",
        stderr="evidentia audit capability-run: not found: run-x\n",
        exit_code=1,
    )

    with pytest.raises(evidentia.EvidentiaCLIError) as exc:
        evidentia.audit_capability_run(
            workspace_path=workspace,
            run_id="run-x",
            binary=str(binary),
        )

    assert exc.value.result.exit_code == 1
    assert "not found" in exc.value.result.stderr


# -- replay ----------------------------------------------------------


def test_replay_no_divergence_does_not_alert(tmp_path: Path, workspace: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(
        bindir,
        stdout='{"reducers":2,"applied_count":[3,4]}\n',
    )
    alerts: list[tuple] = []

    outcome = evidentia.replay(
        workspace_path=workspace,
        binary=str(binary),
        alert=lambda p, n: alerts.append((p, n)),
    )

    assert outcome.divergence is False
    assert outcome.diff_count == 0
    assert alerts == []
    assert outcome.artifact_path.exists()


def test_replay_with_divergence_triggers_alert(tmp_path: Path, workspace: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stdout = '{"reducers":2,"applied_count":[3,4],"diffs":[{"id":"e1"},{"id":"e2"},{"id":"e3"}]}\n'
    binary = _write_fake_binary(bindir, stdout=stdout)
    alerts: list[tuple] = []

    outcome = evidentia.replay(
        workspace_path=workspace,
        binary=str(binary),
        alert=lambda p, n: alerts.append((p, n)),
    )

    assert outcome.divergence is True
    assert outcome.diff_count == 3
    assert len(alerts) == 1
    alert_path, alert_count = alerts[0]
    assert alert_path == outcome.artifact_path
    assert alert_count == 3
    # The artifact MUST be preserved verbatim — Empusa never edits
    # Evidentia's diff payload.
    assert outcome.artifact_path.read_text(encoding="utf-8") == stdout


def test_replay_failure_raises_without_artifact(tmp_path: Path, workspace: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(bindir, stdout="", stderr="evidentia replay: db locked\n", exit_code=1)

    with pytest.raises(evidentia.EvidentiaCLIError):
        evidentia.replay(workspace_path=workspace, binary=str(binary))

    art_dir = workspace / evidentia.ARTIFACTS_SUBDIR
    # No replay-*.json artifact should exist on a failed run.
    assert list(art_dir.glob("replay-*.json")) == []


# -- Binary resolution (Phase 17A) ----------------------------------


def test_resolve_binary_absolute_path_is_returned_verbatim(tmp_path: Path) -> None:
    """Absolute paths bypass PATH and LAB_ROOT lookups entirely."""
    fake = tmp_path / "evidentia"
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    assert evidentia._resolve_binary(str(fake)) == str(fake)


def test_resolve_binary_path_lookup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-absolute name resolves via ``shutil.which`` (PATH)."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(bindir, stdout='{"version":"0.1.0"}\n')
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.delenv("LAB_ROOT", raising=False)

    resolved = evidentia._resolve_binary(binary.name)
    assert Path(resolved).resolve() == binary.resolve()


def test_resolve_binary_lab_root_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When PATH lookup fails, ``${LAB_ROOT}/tools/binaries/evidentia`` wins."""
    lab_root = tmp_path / "lab"
    toolchain = lab_root / "tools" / "binaries" / "evidentia"
    toolchain.mkdir(parents=True)
    # Hecate installs the binary literally as ``evidentia`` (or
    # ``evidentia.exe`` on Windows). Write a placeholder file under
    # the canonical name so the resolver's executable check matches
    # what an operator would actually have on disk.
    binary_name = "evidentia.exe" if os.name == "nt" else "evidentia"
    binary = toolchain / binary_name
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    if os.name != "nt":
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Empty PATH so shutil.which returns None for ``evidentia``.
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.setenv("LAB_ROOT", str(lab_root))

    resolved = evidentia._resolve_binary("evidentia")
    assert Path(resolved).resolve() == binary.resolve()


def test_resolve_binary_missing_returns_name_then_subprocess_raises(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When nothing resolves, the wrapper surfaces FileNotFoundError
    via the existing error path with the resolved (i.e. unresolved)
    binary name in the message."""
    monkeypatch.setenv("PATH", str(workspace / "nope"))
    monkeypatch.delenv("LAB_ROOT", raising=False)

    with pytest.raises(FileNotFoundError) as exc:
        evidentia.run_evidentia_command(
            ["version"], workspace_path=workspace, binary="definitely-not-on-path-evidentia"
        )
    assert "definitely-not-on-path-evidentia" in str(exc.value)


# -- Version capture & cache (Phase 17A) ----------------------------


def test_capture_version_called_once_per_resolved_binary(tmp_path: Path, workspace: Path, jsonl_file: Path) -> None:
    """Two workflows against the same resolved binary share the cache:
    ``evidentia version`` is invoked at most once."""
    evidentia._clear_version_cache()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    call_log = tmp_path / "calls.txt"
    binary = _write_fake_binary(
        bindir,
        stdout='{"version":"0.1.0","records_read":0,"accepted":0,"failed":0,"event_ids":[],"failure_event_ids":[]}\n',
        record_argv_to=call_log,
    )

    # Two successful ingests in a row.
    evidentia.ingest_jsonl(workspace_path=workspace, jsonl_path=jsonl_file, binary=str(binary))
    evidentia.ingest_jsonl(workspace_path=workspace, jsonl_path=jsonl_file, binary=str(binary))

    # Each ingest invokes the binary once for the workflow + the
    # version capture happens exactly once across both ingests.
    lines = call_log.read_text(encoding="utf-8").splitlines()
    # Two ingest invocations -> two argv lines containing 'jsonl'
    # as a standalone token (the subcommand). Use exact-token match
    # because the jsonl path argument also contains the substring.
    jsonl_subcommand_lines = [line for line in lines if line == "jsonl"]
    assert len(jsonl_subcommand_lines) == 2
    # One version invocation -> one argv line equal to 'version'
    # WITHOUT the backend flags (capture is stateless).
    version_lines = [line for line in lines if line == "version"]
    assert len(version_lines) == 1


def test_capture_version_failure_does_not_break_workflow(
    tmp_path: Path, workspace: Path, jsonl_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If ``evidentia version`` fails, the artifact is still written
    and the sidecar records the version as ``null`` with an error
    note. The workflow must NOT abort on provenance failure."""
    evidentia._clear_version_cache()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(
        bindir,
        stdout='{"records_read":0,"accepted":0,"failed":0,"event_ids":[],"failure_event_ids":[]}\n',
    )

    # Force the version capture to fail by stubbing it.
    def _broken_capture(_resolved: str, *, timeout: float | None = 10.0) -> tuple[str | None, str | None]:
        return None, "stubbed failure"

    monkeypatch.setattr(evidentia, "_capture_version", _broken_capture)

    outcome = evidentia.ingest_jsonl(
        workspace_path=workspace,
        jsonl_path=jsonl_file,
        binary=str(binary),
    )
    assert outcome.result.ok
    meta_path = outcome.artifact_path.with_suffix(outcome.artifact_path.suffix + ".meta.json")
    assert meta_path.exists()
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["evidentia_version"] is None
    assert meta["evidentia_version_error"] == "stubbed failure"


# -- Sidecar metadata (Phase 17A) -----------------------------------


def _read_meta(artifact_path: Path) -> dict[str, object]:
    meta_path = artifact_path.with_suffix(artifact_path.suffix + ".meta.json")
    assert meta_path.exists(), f"missing sidecar: {meta_path}"
    return json.loads(meta_path.read_text(encoding="utf-8"))


def test_ingest_success_writes_meta_sidecar(tmp_path: Path, workspace: Path, jsonl_file: Path) -> None:
    evidentia._clear_version_cache()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    summary = '{"records_read":1,"accepted":1,"failed":0,"event_ids":["x"],"failure_event_ids":[]}\n'
    # Same binary serves both the ingest call and the version capture
    # because the fake script ignores argv beyond stdout/exit.
    binary = _write_fake_binary(bindir, stdout=summary)

    # Pre-seed the cache so version provenance is deterministic.
    evidentia._VERSION_CACHE[str(binary.resolve())] = "0.1.0"
    # Some platforms (Windows .bat) hand back an unresolved path.
    evidentia._VERSION_CACHE[str(binary)] = "0.1.0"

    outcome = evidentia.ingest_jsonl(
        workspace_path=workspace,
        jsonl_path=jsonl_file,
        binary=str(binary),
    )

    # Main artifact is byte-for-byte preserved.
    assert outcome.artifact_path.read_text(encoding="utf-8") == summary

    meta = _read_meta(outcome.artifact_path)
    assert meta["evidentia_version"] == "0.1.0"
    assert meta["exit_code"] == 0
    assert meta["artifact_path"] == str(outcome.artifact_path)
    assert isinstance(meta["argv"], list) and "--store" in meta["argv"]
    assert "created_at" in meta and meta["created_at"].endswith("Z")
    assert "stderr_path" not in meta


def test_ingest_failure_writes_meta_sidecar_with_stderr_path(tmp_path: Path, workspace: Path, jsonl_file: Path) -> None:
    evidentia._clear_version_cache()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(
        bindir,
        stdout="",
        stderr="evidentia ingest jsonl: open: no such file\n",
        exit_code=1,
    )

    with pytest.raises(evidentia.EvidentiaCLIError) as exc:
        evidentia.ingest_jsonl(
            workspace_path=workspace,
            jsonl_path=jsonl_file,
            binary=str(binary),
        )

    stderr_path = exc.value.stderr_path
    assert stderr_path is not None
    meta = _read_meta(stderr_path)
    assert meta["exit_code"] == 1
    assert meta["stderr_path"] == str(stderr_path)
    assert meta["artifact_path"] == str(stderr_path)
    # version_error is recorded when version capture fails (the fake
    # binary returns the same exit-1 stderr for the version command),
    # but the workflow must still have produced the sidecar.
    assert "evidentia_version" in meta


def test_audit_success_writes_meta_sidecar(tmp_path: Path, workspace: Path) -> None:
    evidentia._clear_version_cache()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(bindir, stdout='{"run_id":"r1","status":"ok"}\n')
    evidentia._VERSION_CACHE[str(binary.resolve())] = "0.1.0"
    evidentia._VERSION_CACHE[str(binary)] = "0.1.0"

    outcome = evidentia.audit_capability_run(workspace_path=workspace, run_id="r1", binary=str(binary))

    meta = _read_meta(outcome.artifact_path)
    assert meta["evidentia_version"] == "0.1.0"
    assert meta["exit_code"] == 0
    assert "audit" in meta["argv"] and "capability-run" in meta["argv"]


def test_replay_success_writes_meta_sidecar(tmp_path: Path, workspace: Path) -> None:
    evidentia._clear_version_cache()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(bindir, stdout='{"reducers":1,"applied_count":[1]}\n')
    evidentia._VERSION_CACHE[str(binary.resolve())] = "0.1.0"
    evidentia._VERSION_CACHE[str(binary)] = "0.1.0"

    outcome = evidentia.replay(workspace_path=workspace, binary=str(binary))

    meta = _read_meta(outcome.artifact_path)
    assert meta["evidentia_version"] == "0.1.0"
    assert meta["exit_code"] == 0
    assert "replay" in meta["argv"]


# -- Failure-mode hardening (Phase 17D) -----------------------------


def _install_subprocess_spy(
    monkeypatch: pytest.MonkeyPatch,
    *,
    raise_exc: BaseException,
) -> list[tuple]:
    """Replace ``subprocess.run`` (as imported by ``evidentia``) with a
    spy that records each call and raises ``raise_exc``.

    Returns the call-record list so tests can assert on call count
    (no-retry guarantee) and argv shape.
    """
    calls: list[tuple] = []

    def _spy(argv, *args, **kwargs):
        calls.append((tuple(argv), kwargs))
        raise raise_exc

    monkeypatch.setattr(evidentia.subprocess, "run", _spy)
    return calls


def test_run_evidentia_command_filenotfound_is_not_retried(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``subprocess.run`` raising ``FileNotFoundError`` must surface as
    a single ``FileNotFoundError`` carrying the resolved binary path,
    with no retry attempts."""
    calls = _install_subprocess_spy(monkeypatch, raise_exc=FileNotFoundError("simulated exec failure"))

    with pytest.raises(FileNotFoundError) as exc:
        evidentia.run_evidentia_command(
            ["version"],
            workspace_path=workspace,
            binary="/nonexistent/path/to/evidentia",
        )
    # Resolved binary path is included so the operator sees what
    # Empusa actually tried to launch.
    assert "/nonexistent/path/to/evidentia" in str(exc.value).replace("\\", "/")
    # No-retry contract: the wrapper invokes subprocess.run exactly once.
    assert len(calls) == 1


def test_run_evidentia_command_timeout_becomes_evidentia_cli_error(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``subprocess.TimeoutExpired`` must be wrapped in
    :class:`EvidentiaCLIError` (exit 124), captured argv preserved,
    and the call must not be retried."""
    timeout_exc = evidentia.subprocess.TimeoutExpired(
        cmd=["evidentia", "version"],
        timeout=0.5,
        output=b"partial-stdout",
        stderr=b"partial-stderr",
    )
    calls = _install_subprocess_spy(monkeypatch, raise_exc=timeout_exc)

    with pytest.raises(evidentia.EvidentiaCLIError) as exc:
        evidentia.run_evidentia_command(
            ["version"],
            workspace_path=workspace,
            binary="/abs/evidentia",
            timeout=0.5,
        )

    result = exc.value.result
    assert result.exit_code == 124
    assert result.ok is False
    assert result.is_usage_error is False
    assert "timed out" in result.stderr
    assert "0.5" in result.stderr
    # Partial stderr captured before the timeout is preserved.
    assert "partial-stderr" in result.stderr
    # argv built by the wrapper is preserved verbatim.
    assert result.argv[0] == "/abs/evidentia"
    assert "--store" in result.argv and "badger" in result.argv
    assert result.argv[-1] == "version"
    # No-retry contract.
    assert len(calls) == 1


def test_ingest_jsonl_timeout_persists_stderr_artifact(
    workspace: Path, jsonl_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When a timeout occurs during ``ingest_jsonl``, the
    :class:`EvidentiaCLIError` raised by the wrapper propagates out of
    the workflow. No stdout artifact is written (there is no canonical
    document to persist), but the error envelope still carries the
    synthetic exit code 124 so callers route it identically to other
    runtime failures."""
    timeout_exc = evidentia.subprocess.TimeoutExpired(cmd=["evidentia"], timeout=0.25, stderr=b"")
    _install_subprocess_spy(monkeypatch, raise_exc=timeout_exc)

    # Make _resolve_binary trivial so we don't depend on PATH/LAB_ROOT.
    monkeypatch.setattr(evidentia, "_resolve_binary", lambda b: b)

    with pytest.raises(evidentia.EvidentiaCLIError) as exc:
        evidentia.ingest_jsonl(
            workspace_path=workspace,
            jsonl_path=jsonl_file,
            binary="/abs/evidentia",
        )
    assert exc.value.result.exit_code == 124
    # Workflow did not silently fabricate an ingest summary artifact.
    artifacts = list((workspace / evidentia.ARTIFACTS_SUBDIR).glob("ingest-*.json"))
    assert artifacts == []


def test_resolve_binary_no_lab_root_returns_unresolved_name(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit branch: ``shutil.which`` returns ``None`` AND no
    ``LAB_ROOT`` is set. The resolver must return the input verbatim
    so the subsequent ``subprocess.run`` produces a deterministic
    ``FileNotFoundError`` (no silent path fabrication)."""
    # Empty PATH directory guarantees shutil.which returns None.
    empty = workspace / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.delenv("LAB_ROOT", raising=False)

    name = "evidentia-not-on-path-and-no-lab-root"
    assert evidentia._resolve_binary(name) == name


# -- Shared environment contract (Phase 18) -------------------------


def _record_argv_spy(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Replace ``subprocess.run`` (as imported by ``evidentia``) with a
    spy that records the argv of every invocation and returns a
    benign success result. Returns the list captured by the spy.
    """
    captured: list[list[str]] = []

    class _Completed:
        def __init__(self, argv: list[str]) -> None:
            self.returncode = 0
            self.stdout = "{}"
            self.stderr = ""
            self._argv = argv

    def _spy(argv, *args, **kwargs):
        captured.append(list(argv))
        return _Completed(list(argv))

    monkeypatch.setattr(evidentia.subprocess, "run", _spy)
    return captured


def test_effective_binary_explicit_beats_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit non-default ``binary`` argument always wins, even
    when ``EVIDENTIA_BINARY`` is set to something else."""
    monkeypatch.setenv(evidentia.ENV_BINARY, "/from/env/evidentia")
    assert evidentia._effective_binary("/explicit/evidentia") == "/explicit/evidentia"


def test_effective_binary_env_used_when_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the caller passes :data:`DEFAULT_BINARY` (i.e. no
    override), ``EVIDENTIA_BINARY`` is consulted."""
    monkeypatch.setenv(evidentia.ENV_BINARY, "/from/env/evidentia")
    assert evidentia._effective_binary(evidentia.DEFAULT_BINARY) == "/from/env/evidentia"


def test_effective_binary_empty_env_falls_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty / whitespace ``EVIDENTIA_BINARY`` is ignored; the
    default name is returned so the existing PATH / LAB_ROOT
    fallback still runs."""
    monkeypatch.setenv(evidentia.ENV_BINARY, "   ")
    assert evidentia._effective_binary(evidentia.DEFAULT_BINARY) == evidentia.DEFAULT_BINARY


def test_effective_db_path_explicit_beats_env(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit ``db_path`` argument always wins over
    ``EVIDENTIA_DB_PATH``."""
    monkeypatch.setenv(evidentia.ENV_DB_PATH, str(workspace / "from-env.db"))
    explicit = workspace / "explicit.db"
    assert evidentia._effective_db_path(workspace, explicit) == explicit


def test_effective_db_path_env_used_when_none(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When the caller passes ``db_path=None``, ``EVIDENTIA_DB_PATH``
    is honored."""
    target = workspace / "from-env.db"
    monkeypatch.setenv(evidentia.ENV_DB_PATH, str(target))
    assert evidentia._effective_db_path(workspace, None) == target


def test_effective_db_path_default_when_unset(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No explicit value and no env var falls through to the
    canonical per-workspace default."""
    monkeypatch.delenv(evidentia.ENV_DB_PATH, raising=False)
    assert evidentia._effective_db_path(workspace, None) == workspace / evidentia.DEFAULT_DB_DIRNAME


def test_run_evidentia_command_honors_env_binary_and_db_path(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end: when the caller does not override, both
    ``EVIDENTIA_BINARY`` and ``EVIDENTIA_DB_PATH`` flow into the
    final argv exactly once and in the documented positions."""
    env_binary = str(workspace / "env-evidentia")
    env_db = workspace / "env.db"
    monkeypatch.setenv(evidentia.ENV_BINARY, env_binary)
    monkeypatch.setenv(evidentia.ENV_DB_PATH, str(env_db))
    captured = _record_argv_spy(monkeypatch)

    evidentia.run_evidentia_command(["version"], workspace_path=workspace)

    assert len(captured) == 1
    argv = captured[0]
    assert argv[0] == env_binary
    assert argv[1:5] == ["--store", "badger", "--path", str(env_db)]
    assert argv[-1] == "version"


def test_run_evidentia_command_explicit_args_beat_env(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit ``binary`` and ``db_path`` take precedence over both
    env vars (CLI flag > env var rule)."""
    monkeypatch.setenv(evidentia.ENV_BINARY, str(workspace / "env-evidentia"))
    monkeypatch.setenv(evidentia.ENV_DB_PATH, str(workspace / "env.db"))
    captured = _record_argv_spy(monkeypatch)

    explicit_bin = str(workspace / "cli-evidentia")
    explicit_db = workspace / "cli.db"
    evidentia.run_evidentia_command(
        ["version"],
        workspace_path=workspace,
        binary=explicit_bin,
        db_path=explicit_db,
    )

    argv = captured[0]
    assert argv[0] == explicit_bin
    assert argv[4] == str(explicit_db)


def test_run_evidentia_command_env_db_path_unset_uses_workspace_default(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When neither ``--db-path`` nor ``EVIDENTIA_DB_PATH`` is set,
    the per-workspace default still applies (regression guard)."""
    monkeypatch.delenv(evidentia.ENV_BINARY, raising=False)
    monkeypatch.delenv(evidentia.ENV_DB_PATH, raising=False)
    captured = _record_argv_spy(monkeypatch)

    evidentia.run_evidentia_command(
        ["version"],
        workspace_path=workspace,
        binary=str(workspace / "ev"),
    )

    argv = captured[0]
    assert argv[4] == str(workspace / evidentia.DEFAULT_DB_DIRNAME)


def test_consumer_does_not_import_evidentia_source() -> None:
    """The integration contract forbids importing Evidentia source.

    Evidentia is a Go module — there is no Python package to import —
    but this test still pins the rule by asserting that nothing in the
    consumer module references a hypothetical ``evidentia_pkg`` or
    similar bridge. Any future bridge MUST go through the CLI.
    """
    src = Path(evidentia.__file__).read_text(encoding="utf-8")
    forbidden = ("import evidentia_pkg", "from evidentia_pkg", "import _evidentia_ffi")
    for needle in forbidden:
        assert needle not in src, f"consumer must not bypass the CLI: {needle}"


# -- inspect_directory (Phase 23) ------------------------------------


def test_inspect_directory_unknown_subject_rejected(workspace: Path) -> None:
    with pytest.raises(ValueError, match="unknown directory inspect subject"):
        evidentia.inspect_directory(workspace_path=workspace, subject="frobnicate")


def test_inspect_directory_negative_limit_rejected(workspace: Path) -> None:
    with pytest.raises(ValueError, match="limit must be >= 0"):
        evidentia.inspect_directory(workspace_path=workspace, subject="users", limit=-1)


def test_inspect_directory_persists_artifact_and_counts(tmp_path: Path, workspace: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stdout = '[{"entity_id":{"value":"a"}},{"entity_id":{"value":"b"}}]\n'
    binary = _write_fake_binary(bindir, stdout=stdout)

    outcome = evidentia.inspect_directory(
        workspace_path=workspace,
        subject="users",
        binary=str(binary),
    )

    assert outcome.subject == "users"
    assert outcome.record_count == 2
    assert outcome.artifact_path.exists()
    # Artifact MUST be byte-identical to evidentia stdout.
    assert outcome.artifact_path.read_text(encoding="utf-8") == stdout
    # Filename carries the subject so concurrent inspects do not collide.
    assert "users" in outcome.artifact_path.name


def test_inspect_directory_forwards_limit_and_pretty(
    tmp_path: Path,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(cmd, *, workspace_path, binary=evidentia.DEFAULT_BINARY, db_path=None):
        captured["cmd"] = list(cmd)
        return evidentia.EvidentiaResult(argv=["evidentia", *cmd], exit_code=0, stdout="[]\n", stderr="")

    monkeypatch.setattr(evidentia, "run_evidentia_command", fake_run)

    evidentia.inspect_directory(
        workspace_path=workspace,
        subject="relationships",
        limit=10,
        pretty=True,
    )
    assert captured["cmd"] == [
        "inspect",
        "directory",
        "relationships",
        "--limit",
        "10",
        "--pretty",
    ]


def test_inspect_directory_zero_limit_omits_flag(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(cmd, *, workspace_path, binary=evidentia.DEFAULT_BINARY, db_path=None):
        captured["cmd"] = list(cmd)
        return evidentia.EvidentiaResult(argv=["evidentia", *cmd], exit_code=0, stdout="[]\n", stderr="")

    monkeypatch.setattr(evidentia, "run_evidentia_command", fake_run)

    evidentia.inspect_directory(workspace_path=workspace, subject="groups", limit=0, pretty=False)
    assert "--limit" not in captured["cmd"]
    assert "--pretty" not in captured["cmd"]


def test_inspect_directory_failure_raises_without_artifact(tmp_path: Path, workspace: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(bindir, stdout="", stderr="boom\n", exit_code=1)

    with pytest.raises(evidentia.EvidentiaCLIError):
        evidentia.inspect_directory(workspace_path=workspace, subject="users", binary=str(binary))

    art_dir = workspace / evidentia.ARTIFACTS_SUBDIR
    assert list(art_dir.glob("inspect-directory-*.json")) == []


def test_inspect_directory_record_count_handles_non_array_payload(tmp_path: Path, workspace: Path) -> None:
    """A non-array stdout (defensive case) must report 0 records, not crash."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(bindir, stdout='{"not":"an array"}\n')

    outcome = evidentia.inspect_directory(workspace_path=workspace, subject="users", binary=str(binary))
    assert outcome.record_count == 0


# -- inspect_directory_view (Phase 24) -------------------------------


def test_inspect_view_unknown_view_rejected(workspace: Path) -> None:
    with pytest.raises(ValueError, match="unknown directory view"):
        evidentia.inspect_directory_view(workspace_path=workspace, view="frobnicate", key="dn:cn=alice")


def test_inspect_view_empty_key_rejected(workspace: Path) -> None:
    with pytest.raises(ValueError, match="key must be a non-empty"):
        evidentia.inspect_directory_view(workspace_path=workspace, view="neighbors", key="   ")


def test_inspect_view_negative_limit_rejected(workspace: Path) -> None:
    with pytest.raises(ValueError, match="limit must be >= 0"):
        evidentia.inspect_directory_view(
            workspace_path=workspace,
            view="neighbors",
            key="dn:cn=alice",
            limit=-1,
        )


def test_inspect_view_persists_artifact_byte_for_byte(tmp_path: Path, workspace: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stdout = (
        '[{"entity_id":{"value":"e1"},"source":"dn:cn=alice,dc=corp,dc=local",'
        '"target":"dn:cn=admins,dc=corp,dc=local","relationship_type":"member_of",'
        '"observation_count":1,"last_event_seq":7}]\n'
    )
    binary = _write_fake_binary(bindir, stdout=stdout)

    outcome = evidentia.inspect_directory_view(
        workspace_path=workspace,
        view="memberships",
        key="dn:CN=Alice,DC=corp,DC=local",
        binary=str(binary),
    )

    assert outcome.view == "memberships"
    assert outcome.key == "dn:CN=Alice,DC=corp,DC=local"
    assert outcome.record_count == 1
    assert outcome.artifact_path.exists()
    assert outcome.artifact_path.read_text(encoding="utf-8") == stdout
    # Both the view and a sanitized key segment land in the filename.
    assert "memberships" in outcome.artifact_path.name


def test_inspect_view_argv_assembly_with_limit_and_pretty(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(cmd, *, workspace_path, binary=evidentia.DEFAULT_BINARY, db_path=None):
        captured["cmd"] = list(cmd)
        return evidentia.EvidentiaResult(argv=["evidentia", *cmd], exit_code=0, stdout="[]\n", stderr="")

    monkeypatch.setattr(evidentia, "run_evidentia_command", fake_run)

    evidentia.inspect_directory_view(
        workspace_path=workspace,
        view="neighbors",
        key="dn:cn=alice,dc=corp,dc=local",
        limit=5,
        pretty=True,
    )
    # The key MUST be the trailing positional, after any flags, so
    # operators (and the test harness) can rely on stable argv shape.
    assert captured["cmd"] == [
        "inspect",
        "directory",
        "neighbors",
        "--limit",
        "5",
        "--pretty",
        "dn:cn=alice,dc=corp,dc=local",
    ]


def test_inspect_view_zero_limit_omits_flag(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(cmd, *, workspace_path, binary=evidentia.DEFAULT_BINARY, db_path=None):
        captured["cmd"] = list(cmd)
        return evidentia.EvidentiaResult(argv=["evidentia", *cmd], exit_code=0, stdout="[]\n", stderr="")

    monkeypatch.setattr(evidentia, "run_evidentia_command", fake_run)

    evidentia.inspect_directory_view(
        workspace_path=workspace,
        view="memberships",
        key="dn:cn=alice",
        limit=0,
        pretty=False,
    )
    assert "--limit" not in captured["cmd"]
    assert "--pretty" not in captured["cmd"]
    assert captured["cmd"][-1] == "dn:cn=alice"


def test_inspect_view_failure_raises_without_artifact(tmp_path: Path, workspace: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(bindir, stdout="", stderr="boom\n", exit_code=1)

    with pytest.raises(evidentia.EvidentiaCLIError):
        evidentia.inspect_directory_view(
            workspace_path=workspace,
            view="neighbors",
            key="dn:cn=alice",
            binary=str(binary),
        )

    art_dir = workspace / evidentia.ARTIFACTS_SUBDIR
    assert list(art_dir.glob("inspect-directory-neighbors-*.json")) == []


def test_inspect_view_record_count_handles_empty_array(tmp_path: Path, workspace: Path) -> None:
    """Unknown key returns ``[]`` (exit 0) -> 0 records, not an error."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(bindir, stdout="[]\n")

    outcome = evidentia.inspect_directory_view(
        workspace_path=workspace,
        view="neighbors",
        key="dn:cn=ghost,dc=corp,dc=local",
        binary=str(binary),
    )
    assert outcome.record_count == 0


def test_inspect_view_record_count_handles_non_array_payload(tmp_path: Path, workspace: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(bindir, stdout='{"not":"an array"}\n')

    outcome = evidentia.inspect_directory_view(
        workspace_path=workspace,
        view="memberships",
        key="dn:cn=alice",
        binary=str(binary),
    )
    assert outcome.record_count == 0


# -- inspect_directory_aliases (Phase 32) ----------------------------


def test_inspect_aliases_empty_value_rejected(workspace: Path) -> None:
    with pytest.raises(ValueError, match="value must be a non-empty"):
        evidentia.inspect_directory_aliases(workspace_path=workspace, value="   ")


def test_inspect_aliases_unknown_kind_rejected(workspace: Path) -> None:
    with pytest.raises(ValueError, match="unknown alias kind"):
        evidentia.inspect_directory_aliases(
            workspace_path=workspace,
            value="alice",
            kind="frobnicate",
        )


def test_inspect_aliases_negative_limit_rejected(workspace: Path) -> None:
    with pytest.raises(ValueError, match="limit must be >= 0"):
        evidentia.inspect_directory_aliases(
            workspace_path=workspace,
            value="alice",
            limit=-1,
        )


def test_inspect_aliases_persists_artifact_byte_for_byte(tmp_path: Path, workspace: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stdout = (
        '[{"alias_kind":"sid","alias_value":"S-1-5-21-1-2-3-1001",'
        '"canonical_keys":["dn:cn=alice,dc=corp,dc=local"],'
        '"principal_kinds":["user"],"claim_count":2,'
        '"evidence_sources":["adapter:a"],"last_event_seq":7}]\n'
    )
    binary = _write_fake_binary(bindir, stdout=stdout)

    outcome = evidentia.inspect_directory_aliases(
        workspace_path=workspace,
        value="S-1-5-21-1-2-3-1001",
        kind="sid",
        binary=str(binary),
    )

    assert outcome.value == "S-1-5-21-1-2-3-1001"
    assert outcome.kind == "sid"
    assert outcome.record_count == 1
    assert outcome.artifact_path.exists()
    assert outcome.artifact_path.read_text(encoding="utf-8") == stdout
    assert "aliases" in outcome.artifact_path.name


def test_inspect_aliases_argv_assembly_with_kind_limit_pretty(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(cmd, *, workspace_path, binary=evidentia.DEFAULT_BINARY, db_path=None):
        captured["cmd"] = list(cmd)
        return evidentia.EvidentiaResult(argv=["evidentia", *cmd], exit_code=0, stdout="[]\n", stderr="")

    monkeypatch.setattr(evidentia, "run_evidentia_command", fake_run)

    evidentia.inspect_directory_aliases(
        workspace_path=workspace,
        value="S-1-5-21-1-2-3-1001",
        kind="sid",
        limit=5,
        pretty=True,
    )
    # Value is the trailing positional after subcommands; flags follow.
    assert captured["cmd"] == [
        "inspect",
        "directory",
        "aliases",
        "S-1-5-21-1-2-3-1001",
        "--kind",
        "sid",
        "--limit",
        "5",
        "--pretty",
    ]


def test_inspect_aliases_omits_optional_flags_when_unset(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(cmd, *, workspace_path, binary=evidentia.DEFAULT_BINARY, db_path=None):
        captured["cmd"] = list(cmd)
        return evidentia.EvidentiaResult(argv=["evidentia", *cmd], exit_code=0, stdout="[]\n", stderr="")

    monkeypatch.setattr(evidentia, "run_evidentia_command", fake_run)

    evidentia.inspect_directory_aliases(workspace_path=workspace, value="alice")
    assert captured["cmd"] == ["inspect", "directory", "aliases", "alice"]


def test_inspect_aliases_unknown_value_returns_empty(tmp_path: Path, workspace: Path) -> None:
    """Unknown alias -> ``[]`` (exit 0) -> 0 records, not an error."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(bindir, stdout="[]\n")

    outcome = evidentia.inspect_directory_aliases(
        workspace_path=workspace,
        value="S-1-5-21-9-9-9-9999",
        kind="sid",
        binary=str(binary),
    )
    assert outcome.record_count == 0
    assert outcome.artifact_path.exists()


def test_inspect_aliases_failure_raises_without_artifact(tmp_path: Path, workspace: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(bindir, stdout="", stderr="boom\n", exit_code=1)

    with pytest.raises(evidentia.EvidentiaCLIError):
        evidentia.inspect_directory_aliases(
            workspace_path=workspace,
            value="alice",
            binary=str(binary),
        )

    art_dir = workspace / evidentia.ARTIFACTS_SUBDIR
    assert list(art_dir.glob("inspect-directory-aliases-*.json")) == []


def test_inspect_aliases_record_count_handles_non_array_payload(tmp_path: Path, workspace: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = _write_fake_binary(bindir, stdout='{"not":"an array"}\n')

    outcome = evidentia.inspect_directory_aliases(
        workspace_path=workspace,
        value="alice",
        binary=str(binary),
    )
    assert outcome.record_count == 0
