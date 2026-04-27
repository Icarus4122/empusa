"""Empusa - Non-interactive directory enumeration workflow (Phase 21).

Subcommand::

    empusa directory enumerate --workspace PATH --input FILE --format {powershell,ldap}
                              [--binary BIN] [--db-path DIR] [--no-replay]

Pipeline:

1. ``evidentia ingest powershell-ad|ldap <input>`` via
   :func:`empusa.evidentia.ingest_directory`.
2. ``evidentia replay`` via :func:`empusa.evidentia.replay`
   (skipped when ``--no-replay`` is passed -- present so future
   automation can sequence multiple ingest steps before a single
   replay without paying for an intermediate replay).

This wrapper preserves the same boundary rules as
:mod:`empusa.cli_evidentia`:

- never imports Evidentia source or opens the Badger store,
- never reshapes Evidentia's stdout (artifacts are byte-for-byte),
- only inspects top-level summary fields (``accepted`` / ``failed``
  for ingest; ``diffs`` length for replay) for operator-visible
  counts,
- never retries on a usage error (exit 2).
"""

from __future__ import annotations

import argparse
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
from empusa.cli_evidentia import (
    _classify_failure,
    _render_binary_not_found,
    _render_failure,
    _resolve_workspace,
    _top_level_int,
)

# Format aliases accepted on ``--format``. The keys are what the
# operator types; the values are the Evidentia ``ingest`` subcommand
# names. Mirrors :data:`empusa.evidentia.DIRECTORY_INGEST_SUBCOMMANDS`.
_DIRECTORY_FORMATS: tuple[str, ...] = tuple(evidentia.DIRECTORY_INGEST_SUBCOMMANDS.keys())


def cmd_directory_enumerate(args: argparse.Namespace) -> int:
    """``empusa directory enumerate`` - directory enumeration ingest+replay."""
    ws = _resolve_workspace(args.workspace)
    if ws is None:
        return 1

    input_path = Path(args.input)
    if not input_path.is_file():
        log_error(f"Directory input not found: {input_path}")
        return 1

    fmt: str = args.format
    if fmt not in _DIRECTORY_FORMATS:
        log_error(f"Unknown --format {fmt!r} (expected: {', '.join(_DIRECTORY_FORMATS)})")
        return 2

    binary: str = args.binary or evidentia.DEFAULT_BINARY
    db_path = Path(args.db_path) if args.db_path else None

    log_action("Directory Enumerate", f"{fmt}:{input_path}")

    # -- Step 1: ingest --------------------------------------------
    render_group_heading("Step 1: ingest")
    try:
        ingest_outcome = evidentia.ingest_directory(
            workspace_path=ws,
            input_path=input_path,
            fmt=fmt,
            binary=binary,
            db_path=db_path,
        )
    except FileNotFoundError as exc:
        _render_binary_not_found(binary, exc)
        return 1
    except evidentia.EvidentiaCLIError as exc:
        # Surface stderr plus the failure classification so the
        # operator can tell a usage error from a runtime failure
        # without re-running the wrapper.
        _render_failure(exc)
        # Exit 2 on a usage error keeps the contract: never auto-retry.
        if exc.result.exit_code == 2:
            return 2
        return 1

    render_kv("Exit code", str(ingest_outcome.result.exit_code))
    render_kv("Artifact", str(ingest_outcome.artifact_path))
    accepted = _top_level_int(ingest_outcome.result.stdout, "accepted")
    failed = _top_level_int(ingest_outcome.result.stdout, "failed")
    if accepted is not None:
        render_kv("Accepted", str(accepted))
    if failed is not None:
        render_kv("Failed", str(failed))

    if args.no_replay:
        log_success("[PASS] Directory enumerate ingest complete (replay skipped)")
        return 0

    # -- Step 2: replay --------------------------------------------
    render_group_heading("Step 2: replay")
    diverged: list[tuple[Path, int]] = []

    def _alert(artifact: Path, diff_count: int) -> None:
        diverged.append((artifact, diff_count))

    try:
        replay_outcome = evidentia.replay(
            workspace_path=ws,
            binary=binary,
            db_path=db_path,
            alert=_alert,
        )
    except FileNotFoundError as exc:
        _render_binary_not_found(binary, exc)
        return 1
    except evidentia.EvidentiaCLIError as exc:
        _render_failure(exc)
        log_error(f"Failure type: {_classify_failure(exc.result)}")
        return 1

    render_kv("Exit code", str(replay_outcome.result.exit_code))
    render_kv("Artifact", str(replay_outcome.artifact_path))
    render_kv("Diff count", str(replay_outcome.diff_count))

    if replay_outcome.divergence:
        render_kv("Divergence", f"detected: {replay_outcome.diff_count} diff(s)")
        for artifact, count in diverged:
            log_info(
                f"[ALERT] Replay divergence: {count} diff(s) in {artifact}",
                "bold yellow",
            )
        log_error("[FAIL] Directory enumerate replay diverged")
        return 1

    render_kv("Divergence", "No divergence")
    log_success("[PASS] Directory enumerate complete")
    return 0


# Phase 23: directory inspection. Mirror the
# :data:`empusa.evidentia.DIRECTORY_INSPECT_SUBJECTS` tuple so the
# CLI choices stay in lockstep with the wrapper.
_DIRECTORY_INSPECT_SUBJECTS: tuple[str, ...] = evidentia.DIRECTORY_INSPECT_SUBJECTS


def cmd_directory_inspect(args: argparse.Namespace) -> int:
    """``empusa directory inspect`` - read-only directory entity dump.

    Shells out to ``evidentia inspect directory <type>`` and persists
    stdout as a workspace artifact. Empusa does not decode the
    payload beyond counting records: the artifact file is the
    canonical operator-facing output.
    """
    ws = _resolve_workspace(args.workspace)
    if ws is None:
        return 1

    subject: str = args.type
    if subject not in _DIRECTORY_INSPECT_SUBJECTS:
        log_error(f"Unknown --type {subject!r} (expected: {', '.join(_DIRECTORY_INSPECT_SUBJECTS)})")
        return 2

    binary: str = args.binary or evidentia.DEFAULT_BINARY
    db_path = Path(args.db_path) if args.db_path else None
    limit: int | None = args.limit if args.limit and args.limit > 0 else None

    log_action("Directory Inspect", subject)

    try:
        outcome = evidentia.inspect_directory(
            workspace_path=ws,
            subject=subject,
            limit=limit,
            pretty=bool(args.pretty),
            binary=binary,
            db_path=db_path,
        )
    except FileNotFoundError as exc:
        _render_binary_not_found(binary, exc)
        return 1
    except evidentia.EvidentiaCLIError as exc:
        _render_failure(exc)
        if exc.result.exit_code == 2:
            return 2
        return 1

    render_kv("Exit code", str(outcome.result.exit_code))
    render_kv("Artifact", str(outcome.artifact_path))
    render_kv("Records", str(outcome.record_count))
    log_success(f"[PASS] Directory inspect {subject} complete")
    return 0


def register_directory_parser(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Add the ``directory`` subcommand and its actions to *subparsers*.

    Called from :func:`empusa.cli.main` during parser construction.
    """
    sp_dir = subparsers.add_parser(
        "directory",
        help="Directory enumeration workflows (non-interactive)",
    )
    dir_sub = sp_dir.add_subparsers(dest="dir_action")

    sp_enum = dir_sub.add_parser(
        "enumerate",
        help="Ingest a directory export then replay (Phase 21)",
    )
    sp_enum.add_argument("--workspace", required=True, help="Workspace root path")
    sp_enum.add_argument("--input", required=True, help="Path to the directory export file")
    sp_enum.add_argument(
        "--format",
        required=True,
        choices=_DIRECTORY_FORMATS,
        help="Source format of the export",
    )
    sp_enum.add_argument("--binary", default=None, help="Override the evidentia binary path")
    sp_enum.add_argument("--db-path", default=None, help="Override the Badger store directory")
    sp_enum.add_argument(
        "--no-replay",
        action="store_true",
        help="Skip the replay step (ingest only)",
    )

    sp_inspect = dir_sub.add_parser(
        "inspect",
        help="Inspect materialized directory entities (Phase 23)",
    )
    sp_inspect.add_argument("--workspace", required=True, help="Workspace root path")
    sp_inspect.add_argument(
        "--type",
        required=True,
        choices=_DIRECTORY_INSPECT_SUBJECTS,
        help=(
            "Entity type to inspect; --type relationships returns bulk "
            "relationship summaries, use neighbors/memberships for "
            "one-hop targeted views"
        ),
    )
    sp_inspect.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit the number of records returned (0 = no limit)",
    )
    sp_inspect.add_argument(
        "--pretty",
        action="store_true",
        help="Request indented JSON output from evidentia",
    )
    sp_inspect.add_argument("--binary", default=None, help="Override the evidentia binary path")
    sp_inspect.add_argument("--db-path", default=None, help="Override the Badger store directory")

    # -- Phase 24: relationship views ------------------------------
    for view in evidentia.DIRECTORY_VIEW_SUBJECTS:
        sp_view = dir_sub.add_parser(
            view,
            help=f"Inspect one-hop directory {view} for a canonical key (Phase 24)",
        )
        sp_view.add_argument("--workspace", required=True, help="Workspace root path")
        sp_view.add_argument(
            "--key",
            required=True,
            help="Principal canonical_key (e.g. dn:cn=alice,dc=corp,dc=local)",
        )
        sp_view.add_argument(
            "--limit",
            type=int,
            default=0,
            help="Limit the number of records returned (0 = no limit)",
        )
        sp_view.add_argument(
            "--pretty",
            action="store_true",
            help="Request indented JSON output from evidentia",
        )
        sp_view.add_argument("--binary", default=None, help="Override the evidentia binary path")
        sp_view.add_argument("--db-path", default=None, help="Override the Badger store directory")

    # -- Phase 32: alias-aware lookup ------------------------------
    sp_aliases = dir_sub.add_parser(
        "aliases",
        help="Look up directory identity aliases (Phase 32)",
    )
    sp_aliases.add_argument("--workspace", required=True, help="Workspace root path")
    sp_aliases.add_argument(
        "--value",
        required=True,
        help="Alias value to resolve (SID, GUID, DN, SAM, UPN, DNS host)",
    )
    sp_aliases.add_argument(
        "--kind",
        default=None,
        choices=_DIRECTORY_ALIAS_KINDS,
        help="Filter by alias kind (dn|guid|sid|sam|upn|dns|dnshost)",
    )
    sp_aliases.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit the number of records returned (0 = no limit)",
    )
    sp_aliases.add_argument(
        "--pretty",
        action="store_true",
        help="Request indented JSON output from evidentia",
    )
    sp_aliases.add_argument("--binary", default=None, help="Override the evidentia binary path")
    sp_aliases.add_argument("--db-path", default=None, help="Override the Badger store directory")


def cmd_directory_view(args: argparse.Namespace, view: str) -> int:
    """``empusa directory <neighbors|memberships>`` - one-hop relationship view.

    Shells out to ``evidentia inspect directory <view> <key>`` and
    persists stdout as a workspace artifact. Empusa never parses
    individual records; only the top-level array length is surfaced.
    """
    ws = _resolve_workspace(args.workspace)
    if ws is None:
        return 1

    if view not in evidentia.DIRECTORY_VIEW_SUBJECTS:
        log_error(f"Unknown directory view {view!r} (expected: {', '.join(evidentia.DIRECTORY_VIEW_SUBJECTS)})")
        return 2

    key: str = args.key
    if not isinstance(key, str) or not key.strip():
        log_error("--key must be a non-empty string")
        return 2

    binary: str = args.binary or evidentia.DEFAULT_BINARY
    db_path = Path(args.db_path) if args.db_path else None
    limit: int | None = args.limit if args.limit and args.limit > 0 else None

    log_action(f"Directory {view.title()}", key)

    try:
        outcome = evidentia.inspect_directory_view(
            workspace_path=ws,
            view=view,
            key=key,
            limit=limit,
            pretty=bool(args.pretty),
            binary=binary,
            db_path=db_path,
        )
    except FileNotFoundError as exc:
        _render_binary_not_found(binary, exc)
        return 1
    except evidentia.EvidentiaCLIError as exc:
        _render_failure(exc)
        if exc.result.exit_code == 2:
            return 2
        return 1

    render_kv("Exit code", str(outcome.result.exit_code))
    render_kv("Artifact", str(outcome.artifact_path))
    render_kv("Records", str(outcome.record_count))
    log_success(f"[PASS] Directory {view} complete")
    return 0


def cmd_directory_neighbors(args: argparse.Namespace) -> int:
    """``empusa directory neighbors`` (Phase 24)."""
    return cmd_directory_view(args, "neighbors")


def cmd_directory_memberships(args: argparse.Namespace) -> int:
    """``empusa directory memberships`` (Phase 24)."""
    return cmd_directory_view(args, "memberships")


# Phase 32: alias-aware directory lookup. ``empusa directory aliases``
# is a thin wrapper around ``evidentia inspect directory aliases``;
# Empusa shells out, persists stdout as an artifact, and reports the
# top-level array length. Per the boundary contract the wrapper
# never decodes individual alias records.
_DIRECTORY_ALIAS_KINDS: tuple[str, ...] = evidentia.DIRECTORY_ALIAS_KINDS


def cmd_directory_aliases(args: argparse.Namespace) -> int:
    """``empusa directory aliases`` - alias-aware identity lookup.

    Shells out to ``evidentia inspect directory aliases <value>
    [--kind KIND]`` and persists stdout as a workspace artifact.
    Empusa does not parse individual records; it only counts the
    top-level array length. Conflicting aliases (multiple
    canonical_keys on one entity) are preserved verbatim in the
    artifact -- the wrapper never collapses them.
    """

    ws = _resolve_workspace(args.workspace)
    if ws is None:
        return 1

    value: str = args.value
    if not isinstance(value, str) or not value.strip():
        log_error("--value must be a non-empty string")
        return 2

    kind: str | None = args.kind if args.kind else None
    if kind is not None and kind not in _DIRECTORY_ALIAS_KINDS:
        log_error(f"Unknown --kind {kind!r} (expected: {', '.join(_DIRECTORY_ALIAS_KINDS)})")
        return 2

    binary: str = args.binary or evidentia.DEFAULT_BINARY
    db_path = Path(args.db_path) if args.db_path else None
    limit: int | None = args.limit if args.limit and args.limit > 0 else None

    log_action("Directory Aliases", value if not kind else f"{kind}:{value}")

    try:
        outcome = evidentia.inspect_directory_aliases(
            workspace_path=ws,
            value=value,
            kind=kind,
            limit=limit,
            pretty=bool(args.pretty),
            binary=binary,
            db_path=db_path,
        )
    except FileNotFoundError as exc:
        _render_binary_not_found(binary, exc)
        return 1
    except evidentia.EvidentiaCLIError as exc:
        _render_failure(exc)
        if exc.result.exit_code == 2:
            return 2
        return 1

    render_kv("Exit code", str(outcome.result.exit_code))
    render_kv("Artifact", str(outcome.artifact_path))
    render_kv("Records", str(outcome.record_count))
    log_success("[PASS] Directory aliases complete")
    return 0
