"""Empusa - Non-interactive Evidentia workflow CLI commands.

Subcommands::

    empusa evidentia ingest             --workspace PATH --jsonl FILE   [--binary BIN] [--db-path DIR]
    empusa evidentia ingest-provenance  --workspace PATH --file  FILE   [--binary BIN] [--db-path DIR]
    empusa evidentia inspect-provenance --workspace PATH                [--binary BIN] [--db-path DIR]
    empusa evidentia inspect-build-runs --workspace PATH                [--binary BIN] [--db-path DIR]
    empusa evidentia inspect-failures   --workspace PATH                [--limit N] [--pretty] [--binary BIN] [--db-path DIR]
    empusa evidentia workspace-summary  --workspace PATH                [--binary BIN] [--db-path DIR]
    empusa evidentia report             --workspace PATH                [--binary BIN] [--db-path DIR]
    empusa evidentia replay             --workspace PATH                [--binary BIN] [--db-path DIR] [--write --confirm-write]
    empusa evidentia audit              --workspace PATH --run-id ID    [--binary BIN] [--db-path DIR]
    empusa evidentia status             --workspace PATH
    empusa evidentia quickflow          --workspace PATH --jsonl FILE   [--binary BIN] [--db-path DIR]
    empusa evidentia run                --workspace PATH --jsonl FILE   [--binary BIN] [--db-path DIR]   (deprecated alias for quickflow)

These commands are an operator-facing wrapper around
:mod:`empusa.evidentia` -- the *only* module allowed to invoke the
``evidentia`` binary. Per the integration contract
(``Evidentia/docs/integration/empusa-evidentia.md``) this wrapper:

- never imports Evidentia source or opens the Badger store,
- never reshapes Evidentia's stdout (artifacts are byte-for-byte),
- only inspects top-level summary fields (``accepted`` / ``failed`` /
  ``diffs``) for operator-visible counts,
- never retries on a usage error (exit 2).

Phase 19 adds output clarity, error-class triage, a ``status`` summary
command (workspace artifact roll-up, no subprocess), and a ``run``
quick-flow helper (ingest then replay, summary only). Existing line
markers consumed by scripts (``Exit code``, ``Artifact``, ``Diff
count``, ``ALERT``) are preserved verbatim.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from empusa import evidentia
from empusa.cli_common import (
    log_action,
    log_error,
    log_info,
    log_success,
    render_group_heading,
    render_kv,
)


def _resolve_workspace(raw: str) -> Path | None:
    """Validate and return the workspace path, or ``None`` on failure."""
    if not raw:
        log_error("--workspace is required")
        return None
    ws = Path(raw)
    if not ws.is_dir():
        log_error(f"Workspace not found: {ws}")
        return None
    return ws


def _classify_failure(result: evidentia.EvidentiaResult) -> str:
    """Return a short human label for the failure category (Phase 19).

    Categories are operator-facing only; they do not change the
    exit-code contract. Codes:

    - ``2``        -> ``invalid usage`` (Empusa-side argv mistake;
                      contract says never auto-retry).
    - ``124``      -> ``runtime failure (timeout)`` (synthetic code
                      assigned by :func:`run_evidentia_command`).
    - any other    -> ``runtime failure``.
    """
    if result.exit_code == 2:
        return "invalid usage"
    if result.exit_code == 124:
        return "runtime failure (timeout)"
    return "runtime failure"


def _render_failure(exc: evidentia.EvidentiaCLIError) -> None:
    """Surface exit code + stderr path (when present) to the operator."""
    result = exc.result
    log_error(f"Evidentia exit code: {result.exit_code}")
    render_kv("Failure type", _classify_failure(result))
    if exc.stderr_path is not None:
        render_kv("Stderr artifact", str(exc.stderr_path))
    if result.stderr:
        # Show the stderr stream verbatim; do NOT parse it.
        log_info(result.stderr.rstrip("\n"), "yellow")


def _render_binary_not_found(binary: str, exc: FileNotFoundError) -> None:
    """Surface a ``FileNotFoundError`` from the wrapper as a clear failure.

    The wrapper raises :class:`FileNotFoundError` with the resolved
    binary path it actually tried to launch (Phase 17D). We classify
    this distinctly from runtime failures so operators can tell
    "Evidentia is not installed" apart from "Evidentia ran and
    failed".
    """
    log_error("Evidentia binary not found")
    render_kv("Failure type", "binary not found")
    render_kv("Binary", binary)
    log_info(str(exc), "yellow")


def _top_level_int(stdout: str, key: str) -> int | None:
    """Return ``stdout[key]`` if it is a non-negative ``int``, else ``None``.

    Top-level only, no schema interpretation: matches the existing
    ``_diff_count`` policy in :mod:`empusa.evidentia` (Phase 19 reuses
    the same restraint for the ingest accepted/failed counts).
    """
    try:
        doc = json.loads(stdout)
    except (TypeError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    value = doc.get(key)
    if isinstance(value, bool):  # ``bool`` is a subclass of ``int``.
        return None
    if isinstance(value, int) and value >= 0:
        return value
    return None


# -- Subcommand implementations ------------------------------------


def cmd_evidentia_ingest(args: argparse.Namespace) -> int:
    """``empusa evidentia ingest`` - ingest a JSONL file via Evidentia."""
    ws = _resolve_workspace(args.workspace)
    if ws is None:
        return 1

    jsonl_path = Path(args.jsonl)
    if not jsonl_path.is_file():
        log_error(f"JSONL input not found: {jsonl_path}")
        return 1

    binary: str = args.binary or evidentia.DEFAULT_BINARY
    db_path = Path(args.db_path) if args.db_path else None

    log_action("Evidentia Ingest", str(jsonl_path))
    try:
        outcome = evidentia.ingest_jsonl(
            workspace_path=ws,
            jsonl_path=jsonl_path,
            binary=binary,
            db_path=db_path,
        )
    except FileNotFoundError as exc:
        _render_binary_not_found(binary, exc)
        return 1
    except evidentia.EvidentiaCLIError as exc:
        _render_failure(exc)
        return 1

    render_kv("Exit code", str(outcome.result.exit_code))
    render_kv("Artifact", str(outcome.artifact_path))
    accepted = _top_level_int(outcome.result.stdout, "accepted")
    failed = _top_level_int(outcome.result.stdout, "failed")
    if accepted is not None:
        render_kv("Accepted", str(accepted))
    if failed is not None:
        render_kv("Failed", str(failed))
    log_success("[PASS] Evidentia ingest complete")
    return 0


def cmd_evidentia_ingest_provenance(args: argparse.Namespace) -> int:
    """``empusa evidentia ingest-provenance`` - hand a build envelope to Evidentia.

    Mirrors :func:`cmd_evidentia_ingest` for the
    ``build.provenance_envelope`` input shape: the operator points
    Empusa at a previously-emitted envelope JSON file (typically under
    ``<workspace>/artifacts/provenance/``) and Empusa shells out to
    ``evidentia ingest build-provenance <file>``. The wrapper
    persists stdout byte-for-byte; on failure it surfaces the stderr
    artifact path returned by the wrapper.
    """
    ws = _resolve_workspace(args.workspace)
    if ws is None:
        return 1

    file_path = Path(args.file)
    if not file_path.is_file():
        log_error(f"Provenance envelope not found: {file_path}")
        return 1

    binary: str = args.binary or evidentia.DEFAULT_BINARY
    db_path = Path(args.db_path) if args.db_path else None

    log_action("Evidentia Ingest Provenance", str(file_path))
    try:
        outcome = evidentia.ingest_build_provenance(
            workspace_path=ws,
            provenance_path=file_path,
            binary=binary,
            db_path=db_path,
        )
    except FileNotFoundError as exc:
        _render_binary_not_found(binary, exc)
        return 1
    except evidentia.EvidentiaCLIError as exc:
        _render_failure(exc)
        return 1

    render_kv("Exit code", str(outcome.result.exit_code))
    render_kv("Artifact", str(outcome.artifact_path))
    accepted = _top_level_int(outcome.result.stdout, "accepted")
    failed = _top_level_int(outcome.result.stdout, "failed")
    if accepted is not None:
        render_kv("Accepted", str(accepted))
    if failed is not None:
        render_kv("Failed", str(failed))
    log_success("[PASS] Evidentia ingest-provenance complete")
    return 0


def cmd_evidentia_inspect_provenance(args: argparse.Namespace) -> int:
    """``empusa evidentia inspect-provenance`` - surface ingested envelopes.

    Shells out to ``evidentia inspect build-provenance``, persists the
    JSON summary array byte-for-byte under
    ``artifacts/evidentia/inspect-provenance-<timestamp>.json``, and
    prints the artifact path plus the top-level record count. Empusa
    deliberately does not parse per-record fields; the summary
    contract is owned by Evidentia.
    """
    ws = _resolve_workspace(args.workspace)
    if ws is None:
        return 1

    binary: str = args.binary or evidentia.DEFAULT_BINARY
    db_path = Path(args.db_path) if args.db_path else None

    log_action("Evidentia Inspect Provenance", str(ws))
    try:
        outcome = evidentia.inspect_build_provenance(
            workspace_path=ws,
            binary=binary,
            db_path=db_path,
        )
    except FileNotFoundError as exc:
        _render_binary_not_found(binary, exc)
        return 1
    except evidentia.EvidentiaCLIError as exc:
        _render_failure(exc)
        return 1

    render_kv("Exit code", str(outcome.result.exit_code))
    render_kv("Artifact", str(outcome.artifact_path))
    if outcome.record_count is not None:
        render_kv("Records", str(outcome.record_count))
    log_success("[PASS] Evidentia inspect-provenance complete")
    return 0


def cmd_evidentia_inspect_build_runs(args: argparse.Namespace) -> int:
    """``empusa evidentia inspect-build-runs`` - surface materialized runs.

    Shells out to ``evidentia inspect build-runs``, persists the
    JSON summary array byte-for-byte under
    ``artifacts/evidentia/inspect-build-runs-<timestamp>.json``, and
    prints the artifact path plus the top-level record count. Empusa
    deliberately does not parse per-record fields; the
    ``BuildRunSummary`` contract is owned by Evidentia.
    """
    ws = _resolve_workspace(args.workspace)
    if ws is None:
        return 1

    binary: str = args.binary or evidentia.DEFAULT_BINARY
    db_path = Path(args.db_path) if args.db_path else None

    log_action("Evidentia Inspect Build Runs", str(ws))
    try:
        outcome = evidentia.inspect_build_runs(
            workspace_path=ws,
            binary=binary,
            db_path=db_path,
        )
    except FileNotFoundError as exc:
        _render_binary_not_found(binary, exc)
        return 1
    except evidentia.EvidentiaCLIError as exc:
        _render_failure(exc)
        return 1

    render_kv("Exit code", str(outcome.result.exit_code))
    render_kv("Artifact", str(outcome.artifact_path))
    if outcome.record_count is not None:
        render_kv("Records", str(outcome.record_count))
    log_success("[PASS] Evidentia inspect-build-runs complete")
    return 0


def cmd_evidentia_inspect_failures(args: argparse.Namespace) -> int:
    """``empusa evidentia inspect-failures`` - schema validation failures.

    Shells out to ``evidentia inspect failures``, persists the JSON
    array byte-for-byte under
    ``artifacts/evidentia/inspect-failures-<timestamp>.json``, and
    prints the artifact path plus the top-level record count. Empusa
    deliberately does not parse per-event fields; the
    ``schema.validation_failed`` event schema is owned by Evidentia.

    Added in Phase 48 to give operators an Empusa-native entry point
    for the troubleshooting flow described in
    ``docs/troubleshooting-evidentia.md`` (warning code
    ``schema_failures_present``).
    """
    ws = _resolve_workspace(args.workspace)
    if ws is None:
        return 1

    binary: str = args.binary or evidentia.DEFAULT_BINARY
    db_path = Path(args.db_path) if args.db_path else None
    limit: int | None = args.limit if getattr(args, "limit", 0) else None
    pretty: bool = bool(getattr(args, "pretty", False))

    log_action("Evidentia Inspect Failures", str(ws))
    try:
        outcome = evidentia.inspect_failures(
            workspace_path=ws,
            limit=limit,
            pretty=pretty,
            binary=binary,
            db_path=db_path,
        )
    except FileNotFoundError as exc:
        _render_binary_not_found(binary, exc)
        return 1
    except evidentia.EvidentiaCLIError as exc:
        _render_failure(exc)
        return 1

    render_kv("Exit code", str(outcome.result.exit_code))
    render_kv("Artifact", str(outcome.artifact_path))
    if outcome.record_count is not None:
        render_kv("Records", str(outcome.record_count))
    log_success("[PASS] Evidentia inspect-failures complete")
    return 0


def cmd_evidentia_workspace_summary(args: argparse.Namespace) -> int:
    """``empusa evidentia workspace-summary`` - workspace-level snapshot.

    Shells out to ``evidentia inspect workspace-summary``, persists
    the JSON object byte-for-byte under
    ``artifacts/evidentia/inspect-workspace-summary-<timestamp>.json``,
    and prints the scalar counters. Per-field semantics belong to
    Evidentia; the operator surface only echoes the values it
    receives without interpreting any individual key.
    """
    ws = _resolve_workspace(args.workspace)
    if ws is None:
        return 1

    binary: str = args.binary or evidentia.DEFAULT_BINARY
    db_path = Path(args.db_path) if args.db_path else None

    log_action("Evidentia Workspace Summary", str(ws))
    try:
        outcome = evidentia.inspect_workspace_summary(
            workspace_path=ws,
            binary=binary,
            db_path=db_path,
        )
    except FileNotFoundError as exc:
        _render_binary_not_found(binary, exc)
        return 1
    except evidentia.EvidentiaCLIError as exc:
        _render_failure(exc)
        return 1

    render_kv("Exit code", str(outcome.result.exit_code))
    render_kv("Artifact", str(outcome.artifact_path))
    if outcome.scalars is not None:
        for key in sorted(outcome.scalars.keys()):
            render_kv(key, "" if outcome.scalars[key] is None else str(outcome.scalars[key]))
    log_success("[PASS] Evidentia workspace-summary complete")
    return 0


def cmd_evidentia_report(args: argparse.Namespace) -> int:
    """``empusa evidentia report`` - workspace evidence report.

    Composes the workspace-summary and replay wrappers into a
    single Empusa-owned report artifact under
    ``artifacts/evidentia/report-<timestamp>.json``. The underlying
    raw Evidentia stdout artifacts are still written by the
    individual wrappers; this command does not duplicate or rewrite
    them.
    """
    ws = _resolve_workspace(args.workspace)
    if ws is None:
        return 1

    binary: str = args.binary or evidentia.DEFAULT_BINARY
    db_path = Path(args.db_path) if args.db_path else None

    log_action("Evidentia Report", str(ws))
    try:
        outcome = evidentia.generate_workspace_report(
            workspace_path=ws,
            binary=binary,
            db_path=db_path,
        )
    except FileNotFoundError as exc:
        _render_binary_not_found(binary, exc)
        return 1
    except evidentia.EvidentiaCLIError as exc:
        _render_failure(exc)
        return 1

    render_kv("Report artifact", str(outcome.artifact_path))
    render_kv("Summary artifact", str(outcome.summary_outcome.artifact_path))
    render_kv("Replay artifact", str(outcome.replay_outcome.artifact_path))
    render_kv("Replay diff count", str(outcome.replay_outcome.diff_count))
    warnings = outcome.report.get("warnings", [])
    if isinstance(warnings, list):
        render_kv("Warnings", str(len(warnings)))
        for w in warnings:
            log_info(f"[WARN] {w}", "yellow")
    counts = outcome.report.get("counts")
    if isinstance(counts, dict):
        for key in sorted(counts.keys()):
            render_kv(key, "" if counts[key] is None else str(counts[key]))

    if outcome.replay_outcome.divergence:
        log_error("[FAIL] Evidentia report includes replay divergence")
        return 1

    log_success("[PASS] Evidentia report complete")
    return 0


def cmd_evidentia_replay(args: argparse.Namespace) -> int:
    """``empusa evidentia replay`` - replay deterministic state.

    Default mode is read-only: derived state is rebuilt into a scratch
    store and diffed against the live store. ``--write`` opts in to
    materialize the rebuilt state into the live Evidentia store and
    therefore mutates durable truth; per Phase 45 it requires the
    explicit ``--confirm-write`` co-flag. Without ``--confirm-write``
    the command refuses to proceed and returns a non-zero exit code.
    """
    ws = _resolve_workspace(args.workspace)
    if ws is None:
        return 1

    binary: str = args.binary or evidentia.DEFAULT_BINARY
    db_path = Path(args.db_path) if args.db_path else None
    write: bool = bool(getattr(args, "write", False))
    confirm_write: bool = bool(getattr(args, "confirm_write", False))

    if write and not confirm_write:
        log_error(
            "--write materializes reducer state into the live Evidentia store "
            "and is destructive; pass --confirm-write to proceed."
        )
        return 1
    if confirm_write and not write:
        log_error("--confirm-write has no effect without --write")
        return 1

    diverged: list[tuple[Path, int]] = []

    def _alert(artifact: Path, diff_count: int) -> None:
        diverged.append((artifact, diff_count))

    log_action("Evidentia Replay", str(ws))
    try:
        outcome = evidentia.replay(
            workspace_path=ws,
            binary=binary,
            db_path=db_path,
            alert=_alert,
            write=write,
        )
    except FileNotFoundError as exc:
        _render_binary_not_found(binary, exc)
        return 1
    except evidentia.EvidentiaCLIError as exc:
        _render_failure(exc)
        return 1

    render_kv("Exit code", str(outcome.result.exit_code))
    render_kv("Artifact", str(outcome.artifact_path))
    render_kv("Diff count", str(outcome.diff_count))

    if outcome.divergence:
        render_kv("Divergence", f"detected: {outcome.diff_count} diff(s)")
        # Surface the alert without modifying the artifact payload.
        for artifact, count in diverged:
            log_info(
                f"[ALERT] Replay divergence: {count} diff(s) in {artifact}",
                "bold yellow",
            )
        log_error("[FAIL] Evidentia replay diverged")
        return 1

    render_kv("Divergence", "No divergence")
    log_success("[PASS] Evidentia replay deterministic")
    return 0


def cmd_evidentia_audit(args: argparse.Namespace) -> int:
    """``empusa evidentia audit`` - capability-run audit report."""
    ws = _resolve_workspace(args.workspace)
    if ws is None:
        return 1

    run_id: str = args.run_id
    if not run_id:
        log_error("--run-id is required")
        return 1

    binary: str = args.binary or evidentia.DEFAULT_BINARY
    db_path = Path(args.db_path) if args.db_path else None

    log_action("Evidentia Audit", run_id)
    try:
        outcome = evidentia.audit_capability_run(
            workspace_path=ws,
            run_id=run_id,
            binary=binary,
            db_path=db_path,
        )
    except FileNotFoundError as exc:
        _render_binary_not_found(binary, exc)
        return 1
    except evidentia.EvidentiaCLIError as exc:
        _render_failure(exc)
        return 1

    render_kv("Exit code", str(outcome.result.exit_code))
    render_kv("Run ID", outcome.run_id)
    render_kv("Artifact", str(outcome.artifact_path))
    log_success("[PASS] Evidentia audit complete")
    return 0


# -- Phase 19: status & run -----------------------------------------


# Artifact filename prefixes produced by :mod:`empusa.evidentia`.
# Kept in sync with ``_persist_stream`` in that module.
_STATUS_KINDS: tuple[str, ...] = ("ingest", "replay", "audit")


def _latest_artifact(workspace_path: Path, kind: str) -> Path | None:
    """Return the most recent ``<kind>-*.json`` artifact, or ``None``.

    "Most recent" is by filesystem mtime, which matches operator
    intuition ("the last run I did"). The artifacts directory is the
    canonical location used by every Evidentia workflow function in
    :mod:`empusa.evidentia`; this function does not open the file
    contents.
    """
    artifacts_dir = workspace_path / evidentia.ARTIFACTS_SUBDIR
    if not artifacts_dir.is_dir():
        return None
    candidates = [p for p in artifacts_dir.glob(f"{kind}-*.json") if p.is_file() and not p.name.endswith(".meta.json")]
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime)
    return candidates[-1]


def cmd_evidentia_status(args: argparse.Namespace) -> int:
    """``empusa evidentia status`` - artifact-only local status.

    Read-only roll-up over ``<workspace>/artifacts/evidentia/``. This
    command does NOT query the Evidentia store: no subprocess is
    launched, no binary is required, and a workspace whose artifacts
    directory is empty (e.g. a fresh checkout on another host) will
    report ``<none>`` even when the underlying store is populated.
    Per the Phase 19 constraint, only top-level summary fields are
    read from each artifact (``accepted`` / ``failed`` for ingest;
    ``diffs`` length for replay; nothing for audit).
    """
    ws = _resolve_workspace(args.workspace)
    if ws is None:
        return 1

    log_action("Evidentia Status", str(ws))
    log_info(
        "artifact-only local status; does not query Evidentia store.",
        "yellow",
    )
    render_kv("Workspace", str(ws))

    found_any = False
    for kind in _STATUS_KINDS:
        latest = _latest_artifact(ws, kind)
        render_group_heading(f"Latest {kind}")
        if latest is None:
            render_kv("Artifact", "<none>")
            continue
        found_any = True
        render_kv("Artifact", str(latest))
        try:
            payload = latest.read_text(encoding="utf-8")
        except OSError as exc:
            log_info(f"(could not read artifact: {exc})", "yellow")
            continue
        if kind == "ingest":
            accepted = _top_level_int(payload, "accepted")
            failed = _top_level_int(payload, "failed")
            if accepted is not None:
                render_kv("Accepted", str(accepted))
            if failed is not None:
                render_kv("Failed", str(failed))
        elif kind == "replay":
            diff_count = evidentia._diff_count(payload)
            if diff_count > 0:
                render_kv("Divergence", f"detected: {diff_count} diff(s)")
            else:
                render_kv("Divergence", "No divergence")
        # audit: artifact path only; no top-level field is interpreted.

    if not found_any:
        log_info("No Evidentia artifacts found in this workspace.", "yellow")
    log_success("[PASS] Evidentia status")
    return 0


def cmd_evidentia_quickflow(args: argparse.Namespace) -> int:
    """``empusa evidentia quickflow`` - quick ingest + replay flow.

    Convenience wrapper that sequences :func:`cmd_evidentia_ingest`
    then :func:`cmd_evidentia_replay` against the same workspace and
    binary, prints a compact summary, and propagates the first
    non-zero exit code. Artifacts are produced exactly as if each
    command were run individually -- this helper does not bypass the
    standard persistence path.

    Replaces the Phase 19 ``run`` subcommand (the verb collided with
    capability-run language used elsewhere in the surface). The old
    ``empusa evidentia run`` remains as a deprecated alias that emits
    a warning and forwards here.
    """
    ws = _resolve_workspace(args.workspace)
    if ws is None:
        return 1

    jsonl_path = Path(args.jsonl)
    if not jsonl_path.is_file():
        log_error(f"JSONL input not found: {jsonl_path}")
        return 1

    log_action("Evidentia Quickflow", str(jsonl_path))

    # -- Step 1/2: ingest -------------------------------------------
    render_group_heading("Step 1/2: ingest")
    ingest_args = argparse.Namespace(
        workspace=str(ws),
        jsonl=str(jsonl_path),
        binary=args.binary,
        db_path=args.db_path,
    )
    rc_ingest = cmd_evidentia_ingest(ingest_args)
    if rc_ingest != 0:
        log_error("[FAIL] Quick flow aborted at ingest step")
        return rc_ingest

    # -- Step 2/2: replay -------------------------------------------
    render_group_heading("Step 2/2: replay")
    replay_args = argparse.Namespace(
        workspace=str(ws),
        binary=args.binary,
        db_path=args.db_path,
    )
    rc_replay = cmd_evidentia_replay(replay_args)
    if rc_replay != 0:
        log_error("[FAIL] Quick flow aborted at replay step")
        return rc_replay

    log_success("[PASS] Evidentia quickflow (ingest + replay) complete")
    return 0


def cmd_evidentia_run(args: argparse.Namespace) -> int:
    """``empusa evidentia run`` - deprecated alias for ``quickflow`` (Phase 45).

    Behaviour is identical to :func:`cmd_evidentia_quickflow`; this
    handler exists so existing scripts keep working while operators
    migrate. A deprecation notice is printed to stdout before the
    underlying flow runs.
    """
    log_info(
        "empusa evidentia run is deprecated; use empusa evidentia quickflow.",
        "yellow",
    )
    return cmd_evidentia_quickflow(args)


# -- Argparse wiring ------------------------------------------------


def register_evidentia_parser(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Add the ``evidentia`` subcommand and its actions to *subparsers*.

    Called from :func:`empusa.cli.main` during parser construction.
    """
    sp_ev = subparsers.add_parser(
        "evidentia",
        help="Evidentia workflow wrapper (non-interactive)",
    )
    ev_sub = sp_ev.add_subparsers(dest="ev_action")

    # -- evidentia ingest --------------------------------------------
    sp_ingest = ev_sub.add_parser("ingest", help="Ingest a JSONL file via Evidentia")
    sp_ingest.add_argument("--workspace", required=True, help="Workspace root path")
    sp_ingest.add_argument("--jsonl", required=True, help="Path to the JSONL file to ingest")
    sp_ingest.add_argument("--binary", default=None, help="Override the evidentia binary path")
    sp_ingest.add_argument("--db-path", default=None, help="Override the Badger store directory")

    # -- evidentia ingest-provenance --------------------------------
    sp_ingprov = ev_sub.add_parser(
        "ingest-provenance",
        help="Ingest a build.provenance_envelope JSON artifact via Evidentia",
    )
    sp_ingprov.add_argument("--workspace", required=True, help="Workspace root path")
    sp_ingprov.add_argument("--file", required=True, help="Path to the provenance envelope JSON file")
    sp_ingprov.add_argument("--binary", default=None, help="Override the evidentia binary path")
    sp_ingprov.add_argument("--db-path", default=None, help="Override the Badger store directory")

    # -- evidentia inspect-provenance -------------------------------
    sp_inspprov = ev_sub.add_parser(
        "inspect-provenance",
        help="Surface ingested build.provenance_envelope summaries",
    )
    sp_inspprov.add_argument("--workspace", required=True, help="Workspace root path")
    sp_inspprov.add_argument("--binary", default=None, help="Override the evidentia binary path")
    sp_inspprov.add_argument("--db-path", default=None, help="Override the Badger store directory")

    # -- evidentia inspect-build-runs (Phase 41) --------------------
    sp_inspruns = ev_sub.add_parser(
        "inspect-build-runs",
        help="Surface materialized build_run entity summaries",
    )
    sp_inspruns.add_argument("--workspace", required=True, help="Workspace root path")
    sp_inspruns.add_argument("--binary", default=None, help="Override the evidentia binary path")
    sp_inspruns.add_argument("--db-path", default=None, help="Override the Badger store directory")

    # -- evidentia inspect-failures (Phase 48) ----------------------
    sp_inspfail = ev_sub.add_parser(
        "inspect-failures",
        help="Surface schema.validation_failed events (read-only)",
    )
    sp_inspfail.add_argument("--workspace", required=True, help="Workspace root path")
    sp_inspfail.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit the number of records returned (0 = no limit)",
    )
    sp_inspfail.add_argument(
        "--pretty",
        action="store_true",
        help="Request indented JSON output from evidentia",
    )
    sp_inspfail.add_argument("--binary", default=None, help="Override the evidentia binary path")
    sp_inspfail.add_argument("--db-path", default=None, help="Override the Badger store directory")

    # -- evidentia workspace-summary (Phase 42) ---------------------
    sp_wssum = ev_sub.add_parser(
        "workspace-summary",
        help="Workspace-level snapshot of Evidentia state",
    )
    sp_wssum.add_argument("--workspace", required=True, help="Workspace root path")
    sp_wssum.add_argument("--binary", default=None, help="Override the evidentia binary path")
    sp_wssum.add_argument("--db-path", default=None, help="Override the Badger store directory")

    # -- evidentia report (Phase 43) --------------------------------
    sp_report = ev_sub.add_parser(
        "report",
        help="Workspace evidence report (composes workspace-summary + replay)",
    )
    sp_report.add_argument("--workspace", required=True, help="Workspace root path")
    sp_report.add_argument("--binary", default=None, help="Override the evidentia binary path")
    sp_report.add_argument("--db-path", default=None, help="Override the Badger store directory")

    # -- evidentia replay --------------------------------------------
    sp_replay = ev_sub.add_parser("replay", help="Run Evidentia replay and detect divergence")
    sp_replay.add_argument("--workspace", required=True, help="Workspace root path")
    sp_replay.add_argument("--binary", default=None, help="Override the evidentia binary path")
    sp_replay.add_argument("--db-path", default=None, help="Override the Badger store directory")
    sp_replay.add_argument(
        "--write",
        action="store_true",
        help=("Materialize derived entities into the live state store (destructive; requires --confirm-write)"),
    )
    sp_replay.add_argument(
        "--confirm-write",
        action="store_true",
        help="Required co-flag for --write; acknowledges live-store mutation",
    )

    # -- evidentia audit ---------------------------------------------
    sp_audit = ev_sub.add_parser("audit", help="Fetch a capability-run audit report")
    sp_audit.add_argument("--workspace", required=True, help="Workspace root path")
    sp_audit.add_argument("--run-id", required=True, help="Capability run identifier")
    sp_audit.add_argument("--binary", default=None, help="Override the evidentia binary path")
    sp_audit.add_argument("--db-path", default=None, help="Override the Badger store directory")

    # -- evidentia status (Phase 19; clarified Phase 45) ------------
    sp_status = ev_sub.add_parser(
        "status",
        help=(
            "Artifact-only local status; does not query Evidentia store "
            "(roll-up of latest ingest/replay/audit artifacts)"
        ),
    )
    sp_status.add_argument("--workspace", required=True, help="Workspace root path")

    # -- evidentia quickflow (Phase 45; replaces ``run``) -----------
    sp_quickflow = ev_sub.add_parser(
        "quickflow",
        help="Quick flow: ingest then replay (summary only)",
    )
    sp_quickflow.add_argument("--workspace", required=True, help="Workspace root path")
    sp_quickflow.add_argument("--jsonl", required=True, help="Path to the JSONL file to ingest")
    sp_quickflow.add_argument("--binary", default=None, help="Override the evidentia binary path")
    sp_quickflow.add_argument("--db-path", default=None, help="Override the Badger store directory")

    # -- evidentia run (Phase 19; deprecated alias since Phase 45) --
    sp_run = ev_sub.add_parser(
        "run",
        help="DEPRECATED alias for ``quickflow``; will be removed in a future phase",
    )
    sp_run.add_argument("--workspace", required=True, help="Workspace root path")
    sp_run.add_argument("--jsonl", required=True, help="Path to the JSONL file to ingest")
    sp_run.add_argument("--binary", default=None, help="Override the evidentia binary path")
    sp_run.add_argument("--db-path", default=None, help="Override the Badger store directory")
