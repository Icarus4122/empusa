"""
Empusa → Evidentia CLI consumer.

This module is the *only* place in Empusa allowed to invoke the
``evidentia`` binary. It implements the consumer side of the contract
documented in
``Evidentia/docs/integration/empusa-evidentia.md``. It deliberately
does NOT:

- import any Evidentia Go package or vendored source,
- open or read Evidentia's Badger store,
- transform or re-shape Evidentia's JSON output,
- retry on a usage error (exit 2),
- assume success from stdout content alone.

All cross-system communication happens through ``subprocess`` and the
exit-code contract:

- ``0``  : success; stdout is canonical JSON
- ``1``  : runtime / not-found; stderr explains
- ``2``  : usage error in Empusa's invocation; never auto-retry
- other : treated as a runtime failure

Stdout from a successful call is persisted byte-for-byte under
``<workspace>/artifacts/evidentia/`` so the resulting file matches
Evidentia's emitted document exactly. Stderr is captured separately
(per §7.1 of the contract) and persisted only on failure.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Default binary name. Hecate installs ``evidentia`` onto PATH; tests
# may override the lookup by passing a different ``binary`` kwarg.
DEFAULT_BINARY = "evidentia"

# Canonical environment variables for the shared Evidentia
# integration contract (Phase 18). Both Empusa and Hecate honor
# these names; they are NEVER read from anywhere except this module
# inside Empusa, and ``scripts/verify-host.sh`` inside Hecate.
#
# Resolution precedence (highest → lowest):
#
#   1. Explicit caller argument (``--binary`` / ``--db-path`` / kwarg)
#   2. ``EVIDENTIA_BINARY`` / ``EVIDENTIA_DB_PATH``
#   3. ``PATH`` lookup (binary only)
#   4. ``${LAB_ROOT}/tools/binaries/evidentia/evidentia[.exe]``
#      (binary only)
#   5. Workspace default (``<workspace>/evidentia.db``, db only)
ENV_BINARY = "EVIDENTIA_BINARY"
ENV_DB_PATH = "EVIDENTIA_DB_PATH"

# Subdirectory (relative to a workspace root) where every Evidentia
# artifact is stored. Kept stable so operators and downstream tooling
# can locate outputs without consulting Empusa internals.
ARTIFACTS_SUBDIR = Path("artifacts") / "evidentia"

# Default Badger directory name inside a workspace.
DEFAULT_DB_DIRNAME = "evidentia.db"

# Hecate's canonical toolchain layout for the evidentia binary. Kept
# in sync with ``hecate-bootstrap/scripts/verify-host.sh`` so an
# operator who follows Hecate's documented install convention does
# not also have to mutate ``PATH`` for Empusa to find the binary.
_LAB_TOOLCHAIN_SUBPATH = ("tools", "binaries", "evidentia")

# Process-lifetime cache of resolved-binary -> version string. Keyed
# by the absolute resolved path so two callers using the same binary
# only pay the ``evidentia version`` cost once. Cleared explicitly by
# tests via :func:`_clear_version_cache`.
_VERSION_CACHE: dict[str, str] = {}


@dataclass(frozen=True)
class EvidentiaResult:
    """Structured result of one ``evidentia`` invocation.

    ``stdout`` and ``stderr`` are returned verbatim (decoded as UTF-8).
    Callers MUST NOT re-encode or re-shape ``stdout`` before persisting
    it; the artifact on disk is the canonical document.
    """

    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def is_usage_error(self) -> bool:
        return self.exit_code == 2


class EvidentiaCLIError(RuntimeError):
    """Raised when an Evidentia invocation fails (exit != 0).

    Carries the full :class:`EvidentiaResult` so callers can decide how
    to surface or persist the failure without re-running the command.
    """

    def __init__(self, result: EvidentiaResult, stderr_path: Path | None = None) -> None:
        super().__init__(
            "evidentia {cmd} exited {code}: {err}".format(
                cmd=" ".join(result.argv[1:]) if len(result.argv) > 1 else "",
                code=result.exit_code,
                err=result.stderr.strip() or "<no stderr>",
            )
        )
        self.result = result
        # Path to the persisted stderr stream, when the workflow chose
        # to capture it (e.g. ingest_jsonl). ``None`` means no file was
        # written for this failure.
        self.stderr_path: Path | None = stderr_path


# -- Core wrapper ----------------------------------------------------


def run_evidentia_command(
    cmd: Sequence[str],
    workspace_path: Path,
    *,
    binary: str = DEFAULT_BINARY,
    db_path: Path | None = None,
    timeout: float | None = None,
) -> EvidentiaResult:
    """Execute one ``evidentia`` invocation and return a structured result.

    ``cmd`` is the command and its arguments *without* the binary or
    backend flags (e.g. ``["ingest", "jsonl", "/path/to/file"]``). The
    Badger backend is selected automatically by passing
    ``--store badger --path <db_path>``.

    Resolution precedence (Phase 18 shared contract):

    - ``binary``: explicit non-default value > ``$EVIDENTIA_BINARY`` >
      ``DEFAULT_BINARY`` (``"evidentia"``). The resolved name is then
      passed through :func:`_resolve_binary` (PATH → ``LAB_ROOT``
      toolchain).
    - ``db_path``: explicit non-``None`` value > ``$EVIDENTIA_DB_PATH``
      > ``<workspace_path>/evidentia.db``.

    The function never decides whether the result is "success" beyond
    surfacing the exit code; higher-level workflows (`ingest`, `audit`,
    `replay`) translate the exit code into artifact / failure /
    bug-report routing.

    Failure modes:

    - :class:`FileNotFoundError` if the ``evidentia`` binary cannot be
      resolved (PATH lookup and Hecate's ``LAB_ROOT`` toolchain both
      fail and ``binary`` is not absolute, or the resolved path no
      longer exists at exec time). The message includes the path
      Empusa actually tried to launch.
    - :class:`EvidentiaCLIError` wrapping a synthetic
      :class:`EvidentiaResult` (``exit_code = 124``) if the call
      exceeds ``timeout`` seconds. The command is **never** retried
      automatically; callers decide whether a retry is appropriate.
    """

    if not cmd:
        raise ValueError("cmd must not be empty")

    workspace_path = Path(workspace_path)
    if not workspace_path.is_dir():
        raise FileNotFoundError(f"workspace_path does not exist or is not a directory: {workspace_path}")

    binary = _effective_binary(binary)
    db = _effective_db_path(workspace_path, db_path)

    resolved = _resolve_binary(binary)

    argv: list[str] = [
        resolved,
        "--store",
        "badger",
        "--path",
        str(db),
        *cmd,
    ]

    try:
        completed = subprocess.run(  # noqa: S603 - argv is built from typed inputs only
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        # Re-raise with the resolved binary so the operator sees what
        # Empusa actually tried to launch.
        raise FileNotFoundError(f"evidentia binary not found: {resolved}") from exc
    except subprocess.TimeoutExpired as exc:
        # Convert into the standard EvidentiaCLIError envelope so
        # callers route timeouts identically to other runtime failures
        # (no retry, no auto-recovery). 124 is the conventional
        # timeout exit code; stderr text mirrors what the operator
        # would see in a shell.
        stderr_text = (
            exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, (bytes, bytearray)) else (exc.stderr or "")
        )
        stdout_text = (
            exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, (bytes, bytearray)) else (exc.stdout or "")
        )
        timeout_msg = f"evidentia timed out after {exc.timeout}s"
        synthetic = EvidentiaResult(
            argv=argv,
            exit_code=124,
            stdout=stdout_text,
            stderr=(stderr_text + ("\n" if stderr_text and not stderr_text.endswith("\n") else "") + timeout_msg).strip(
                "\n"
            )
            if stderr_text
            else timeout_msg,
        )
        raise EvidentiaCLIError(synthetic) from exc

    return EvidentiaResult(
        argv=argv,
        exit_code=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )


# -- Binary resolution & version provenance -------------------------


def _effective_binary(binary: str) -> str:
    """Apply the env-var fallback for ``binary`` (Phase 18 contract).

    Caller-supplied values that differ from :data:`DEFAULT_BINARY`
    win unconditionally (the CLI flag and explicit kwargs always
    beat the environment). When the caller does not override, the
    ``EVIDENTIA_BINARY`` environment variable is consulted. Empty
    or whitespace-only values are ignored so an unset-style export
    does not poison resolution.
    """
    if binary != DEFAULT_BINARY:
        return binary
    env_value = (os.environ.get(ENV_BINARY) or "").strip()
    return env_value or DEFAULT_BINARY


def _effective_db_path(workspace_path: Path, db_path: Path | None) -> Path:
    """Apply the env-var fallback for ``db_path`` (Phase 18 contract).

    Explicit ``db_path`` arguments win unconditionally. Otherwise the
    ``EVIDENTIA_DB_PATH`` environment variable is consulted; if unset
    or empty, the per-workspace default
    (``<workspace_path>/evidentia.db``) is used.
    """
    if db_path is not None:
        return Path(db_path)
    env_value = (os.environ.get(ENV_DB_PATH) or "").strip()
    if env_value:
        return Path(env_value)
    return workspace_path / DEFAULT_DB_DIRNAME


def _resolve_binary(binary: str) -> str:
    """Resolve ``binary`` to an executable path.

    Resolution order:

    1. If ``binary`` is an absolute path, return it verbatim.
    2. Otherwise consult :pyfunc:`shutil.which` (i.e. ``PATH``).
    3. If still unresolved and ``LAB_ROOT`` is set in the environment,
       check Hecate's canonical toolchain location
       (``${LAB_ROOT}/tools/binaries/evidentia/evidentia``; on Windows
       also ``evidentia.exe``).
    4. Otherwise return ``binary`` unchanged so the eventual
       ``subprocess.run`` raises :class:`FileNotFoundError` with a
       clear message via the wrapper's existing error path.
    """

    if Path(binary).is_absolute():
        return binary

    found = shutil.which(binary)
    if found:
        return found

    lab_root = os.environ.get("LAB_ROOT")
    if lab_root:
        base = Path(lab_root, *_LAB_TOOLCHAIN_SUBPATH)
        candidates: list[Path] = []
        if os.name == "nt":
            # Prefer the .exe form on Windows; some operators may
            # still drop a no-extension build alongside it.
            candidates.append(base / "evidentia.exe")
            candidates.append(base / "evidentia")
        else:
            candidates.append(base / "evidentia")
        for cand in candidates:
            if cand.is_file() and os.access(cand, os.X_OK):
                return str(cand)

    return binary


def _clear_version_cache() -> None:
    """Reset the resolved-binary version cache (test helper)."""
    _VERSION_CACHE.clear()


def _capture_version(resolved_binary: str, *, timeout: float | None = 10.0) -> tuple[str | None, str | None]:
    """Run ``evidentia version`` once per resolved binary and cache it.

    Returns ``(version, error)``. On success ``error`` is ``None``;
    on failure ``version`` is ``None`` and ``error`` carries a short
    diagnostic string. Failure to capture the version MUST NOT abort
    the calling workflow — provenance is recorded as ``null`` instead.
    The version subprocess does not pass backend flags because the
    Evidentia ``version`` command is stateless and per the contract
    must not require store access.
    """

    cached = _VERSION_CACHE.get(resolved_binary)
    if cached is not None:
        return cached, None

    try:
        completed = subprocess.run(  # noqa: S603 - argv built from resolved path only
            [resolved_binary, "version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        return None, f"binary not found: {exc}"
    except subprocess.TimeoutExpired:
        return None, "version command timed out"

    if completed.returncode != 0:
        return None, f"version exited {completed.returncode}: {completed.stderr.strip() or '<no stderr>'}"

    try:
        doc = json.loads(completed.stdout)
    except (TypeError, ValueError):
        return None, "version stdout is not valid JSON"

    if not isinstance(doc, dict):
        return None, "version stdout is not a JSON object"

    value = doc.get("version")
    if not isinstance(value, str) or not value:
        return None, "version stdout missing top-level string 'version' field"

    _VERSION_CACHE[resolved_binary] = value
    return value, None


# -- Artifact persistence -------------------------------------------


def _utc_timestamp() -> str:
    # 20260426T143012Z — filesystem-safe, sortable, no separators.
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _utc_iso() -> str:
    # Sidecar metadata uses ISO-8601 with UTC ``Z`` suffix so callers
    # never have to guess at timezone semantics.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _artifacts_dir(workspace_path: Path) -> Path:
    d = Path(workspace_path) / ARTIFACTS_SUBDIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def _persist_stream(
    workspace_path: Path,
    *,
    kind: str,
    suffix: str,
    payload: str,
    ref: str | None = None,
) -> Path:
    """Write ``payload`` byte-for-byte (UTF-8) to a workspace artifact.

    The filename is ``<kind>[-<ref>]-<timestamp>.<suffix>`` so multiple
    runs of the same kind do not collide and each artifact carries the
    correlating Evidentia id (when applicable) in its name.
    """

    d = _artifacts_dir(workspace_path)
    parts = [kind]
    if ref:
        parts.append(_safe_ref(ref))
    parts.append(_utc_timestamp())
    name = "-".join(parts) + "." + suffix
    path = d / name
    # write_bytes preserves the payload exactly: no newline
    # translation, no re-encoding round trip.
    path.write_bytes(payload.encode("utf-8"))
    return path


def _safe_ref(ref: str) -> str:
    return "".join(c if (c.isalnum() or c in "-_") else "_" for c in ref)


def _write_meta_sidecar(
    artifact_path: Path,
    result: EvidentiaResult,
    *,
    stderr_path: Path | None = None,
) -> Path:
    """Write a ``<artifact>.meta.json`` sidecar with provenance fields.

    The main artifact file (``stdout`` or ``stderr`` stream) is never
    touched by this function — the sidecar lives alongside it so the
    primary artifact remains a byte-for-byte copy of what Evidentia
    emitted. ``argv[0]`` is the resolved binary path, which is what
    :func:`_capture_version` keys the cache on.
    """

    resolved_binary = result.argv[0] if result.argv else ""
    version, version_error = _capture_version(resolved_binary)

    meta: dict[str, object] = {
        "evidentia_version": version,
        "argv": list(result.argv),
        "exit_code": result.exit_code,
        "artifact_path": str(artifact_path),
        "created_at": _utc_iso(),
    }
    if stderr_path is not None:
        meta["stderr_path"] = str(stderr_path)
    if version_error is not None:
        meta["evidentia_version_error"] = version_error

    meta_path = artifact_path.with_suffix(artifact_path.suffix + ".meta.json")
    meta_path.write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return meta_path


# -- Workflows -------------------------------------------------------


@dataclass(frozen=True)
class IngestOutcome:
    """Result of an ``ingest jsonl`` workflow run."""

    artifact_path: Path
    stderr_path: Path | None
    result: EvidentiaResult


def ingest_jsonl(
    workspace_path: Path,
    jsonl_path: Path,
    *,
    binary: str = DEFAULT_BINARY,
    db_path: Path | None = None,
) -> IngestOutcome:
    """Ingest an Empusa-built JSONL file via Evidentia.

    The JSONL file MUST already exist under ``workspace_path`` (the
    caller is responsible for producing it; this function does not
    fabricate observation payloads). On success the JSON summary is
    persisted as an artifact; on failure the stderr stream is
    persisted instead. In both cases the :class:`IngestOutcome`
    carries the raw :class:`EvidentiaResult` so workflow code can
    route by exit code without re-running the command.
    """

    jsonl_path = Path(jsonl_path)
    if not jsonl_path.is_file():
        raise FileNotFoundError(f"jsonl input not found: {jsonl_path}")

    result = run_evidentia_command(
        ["ingest", "jsonl", str(jsonl_path)],
        workspace_path=workspace_path,
        binary=binary,
        db_path=db_path,
    )

    if result.ok:
        artifact = _persist_stream(workspace_path, kind="ingest", suffix="json", payload=result.stdout)
        _write_meta_sidecar(artifact, result)
        return IngestOutcome(artifact_path=artifact, stderr_path=None, result=result)

    stderr_path = _persist_stream(workspace_path, kind="ingest", suffix="stderr", payload=result.stderr)
    _write_meta_sidecar(stderr_path, result, stderr_path=stderr_path)
    raise EvidentiaCLIError(result, stderr_path=stderr_path)


# Phase 21 directory ingest formats. Mapped 1:1 onto the
# corresponding ``evidentia ingest`` subcommands. Empusa does not
# fabricate or rewrite directory payloads -- the operator hands the
# adapter the verbatim bytes and the wrapper passes the path through.
DIRECTORY_INGEST_SUBCOMMANDS: dict[str, str] = {
    "powershell": "powershell-ad",
    "ldap": "ldap",
}


def ingest_directory(
    workspace_path: Path,
    input_path: Path,
    *,
    fmt: str,
    binary: str = DEFAULT_BINARY,
    db_path: Path | None = None,
) -> IngestOutcome:
    """Ingest a directory enumeration export via Evidentia (Phase 21).

    ``fmt`` selects the Evidentia ``ingest`` subcommand:

    - ``"powershell"`` -> ``evidentia ingest powershell-ad <file>``
    - ``"ldap"``       -> ``evidentia ingest ldap <file>``

    The wrapper persists the JSON summary as an ingest artifact on
    success, the stderr stream on failure -- identical to
    :func:`ingest_jsonl`. The two paths share :class:`IngestOutcome`
    so callers (CLI or workflow) route by exit code uniformly.
    """

    subcmd = DIRECTORY_INGEST_SUBCOMMANDS.get(fmt)
    if subcmd is None:
        raise ValueError(
            f"unknown directory ingest format: {fmt!r} (expected one of {sorted(DIRECTORY_INGEST_SUBCOMMANDS)})"
        )

    input_path = Path(input_path)
    if not input_path.is_file():
        raise FileNotFoundError(f"directory input not found: {input_path}")

    result = run_evidentia_command(
        ["ingest", subcmd, str(input_path)],
        workspace_path=workspace_path,
        binary=binary,
        db_path=db_path,
    )

    if result.ok:
        artifact = _persist_stream(workspace_path, kind="ingest", suffix="json", payload=result.stdout)
        _write_meta_sidecar(artifact, result)
        return IngestOutcome(artifact_path=artifact, stderr_path=None, result=result)

    stderr_path = _persist_stream(workspace_path, kind="ingest", suffix="stderr", payload=result.stderr)
    _write_meta_sidecar(stderr_path, result, stderr_path=stderr_path)
    raise EvidentiaCLIError(result, stderr_path=stderr_path)


def ingest_build_provenance(
    workspace_path: Path,
    provenance_path: Path,
    *,
    binary: str = DEFAULT_BINARY,
    db_path: Path | None = None,
    timeout: float | None = None,
) -> IngestOutcome:
    """Ingest an Empusa-emitted ``build.provenance_envelope`` artifact.

    The envelope JSON file is the verbatim document Empusa produced
    via :mod:`empusa.provenance` (typically under
    ``<workspace>/artifacts/provenance/<envelope_id>.provenance.json``).
    Empusa never re-shapes the document before handing it back to
    Evidentia: this wrapper passes the file path through to
    ``evidentia ingest build-provenance <file>``, which validates the
    envelope against the ``build.provenance_envelope`` schema on the
    Evidentia side.

    On success the JSON summary is persisted as a workspace artifact
    under ``artifacts/evidentia/`` with a ``provenance-`` filename
    prefix so it does not collide with regular JSONL ingest summaries
    and is easy to roll up. On failure the stderr stream is persisted
    instead and :class:`EvidentiaCLIError` is raised carrying the
    stderr artifact path so the operator can investigate without
    re-running the command.
    """

    provenance_path = Path(provenance_path)
    if not provenance_path.is_file():
        raise FileNotFoundError(f"provenance input not found: {provenance_path}")

    result = run_evidentia_command(
        ["ingest", "build-provenance", str(provenance_path)],
        workspace_path=workspace_path,
        binary=binary,
        db_path=db_path,
        timeout=timeout,
    )

    if result.ok:
        artifact = _persist_stream(workspace_path, kind="provenance", suffix="json", payload=result.stdout)
        _write_meta_sidecar(artifact, result)
        return IngestOutcome(artifact_path=artifact, stderr_path=None, result=result)

    stderr_path = _persist_stream(workspace_path, kind="provenance", suffix="stderr", payload=result.stderr)
    _write_meta_sidecar(stderr_path, result, stderr_path=stderr_path)
    raise EvidentiaCLIError(result, stderr_path=stderr_path)


@dataclass(frozen=True)
class InspectProvenanceOutcome:
    """Result of ``evidentia inspect build-provenance``.

    ``artifact_path`` points to the verbatim stdout (a JSON array of
    flat summaries) persisted under ``artifacts/evidentia/`` with a
    ``inspect-provenance-`` prefix.

    ``record_count`` is the length of the top-level JSON array, or
    ``None`` if the body was not an array (for example ``null`` from
    an empty event log). Empusa intentionally does not parse any
    per-record fields: the summary contract belongs to Evidentia, and
    the operator-facing CLI command renders only the count.
    """

    artifact_path: Path
    record_count: int | None
    result: EvidentiaResult


def inspect_build_provenance(
    workspace_path: Path,
    *,
    binary: str = DEFAULT_BINARY,
    db_path: Path | None = None,
    timeout: float | None = None,
) -> InspectProvenanceOutcome:
    """Run ``evidentia inspect build-provenance`` and persist the output.

    The wrapper invokes the inspect surface added in Evidentia
    Phase 39 and stores stdout byte-for-byte as a workspace artifact
    under ``artifacts/evidentia/inspect-provenance-<timestamp>.json``.
    On failure the stderr stream is persisted under the same prefix
    with a ``.stderr`` suffix and :class:`EvidentiaCLIError` is
    raised.

    The wrapper does not interpret per-record fields. It only
    inspects the top-level JSON shape to derive ``record_count`` for
    the operator summary; the underlying summary contract is owned by
    Evidentia.
    """

    result = run_evidentia_command(
        ["inspect", "build-provenance"],
        workspace_path=workspace_path,
        binary=binary,
        db_path=db_path,
        timeout=timeout,
    )

    if not result.ok:
        stderr_path = _persist_stream(
            workspace_path,
            kind="inspect-provenance",
            suffix="stderr",
            payload=result.stderr,
        )
        _write_meta_sidecar(stderr_path, result, stderr_path=stderr_path)
        raise EvidentiaCLIError(result, stderr_path=stderr_path)

    artifact = _persist_stream(
        workspace_path,
        kind="inspect-provenance",
        suffix="json",
        payload=result.stdout,
    )
    _write_meta_sidecar(artifact, result)

    record_count: int | None = None
    try:
        decoded = json.loads(result.stdout)
    except (ValueError, TypeError):
        decoded = None
    if isinstance(decoded, list):
        record_count = len(decoded)

    return InspectProvenanceOutcome(
        artifact_path=artifact,
        record_count=record_count,
        result=result,
    )


@dataclass(frozen=True)
class InspectBuildRunsOutcome:
    """Result of ``evidentia inspect build-runs`` (Phase 41).

    ``artifact_path`` points to the verbatim stdout (a JSON array of
    flat ``BuildRunSummary`` records) persisted under
    ``artifacts/evidentia/`` with an ``inspect-build-runs-`` prefix.

    ``record_count`` is the length of the top-level JSON array, or
    ``None`` if the body was not an array (for example ``null`` from
    a state store with no materialized build_run entities). Empusa
    intentionally does not parse any per-record fields; the summary
    contract is owned by Evidentia.
    """

    artifact_path: Path
    record_count: int | None
    result: EvidentiaResult


def inspect_build_runs(
    workspace_path: Path,
    *,
    binary: str = DEFAULT_BINARY,
    db_path: Path | None = None,
    timeout: float | None = None,
) -> InspectBuildRunsOutcome:
    """Run ``evidentia inspect build-runs`` and persist the output.

    The wrapper invokes the Phase-41 inspect surface and stores
    stdout byte-for-byte as a workspace artifact under
    ``artifacts/evidentia/inspect-build-runs-<timestamp>.json``. On
    failure the stderr stream is persisted under the same prefix
    with a ``.stderr`` suffix and :class:`EvidentiaCLIError` is
    raised.

    The wrapper does not interpret per-record fields. It only
    inspects the top-level JSON shape to derive ``record_count`` for
    the operator summary; the underlying ``BuildRunSummary``
    contract is owned by Evidentia.
    """

    result = run_evidentia_command(
        ["inspect", "build-runs"],
        workspace_path=workspace_path,
        binary=binary,
        db_path=db_path,
        timeout=timeout,
    )

    if not result.ok:
        stderr_path = _persist_stream(
            workspace_path,
            kind="inspect-build-runs",
            suffix="stderr",
            payload=result.stderr,
        )
        _write_meta_sidecar(stderr_path, result, stderr_path=stderr_path)
        raise EvidentiaCLIError(result, stderr_path=stderr_path)

    artifact = _persist_stream(
        workspace_path,
        kind="inspect-build-runs",
        suffix="json",
        payload=result.stdout,
    )
    _write_meta_sidecar(artifact, result)

    record_count: int | None = None
    try:
        decoded = json.loads(result.stdout)
    except (ValueError, TypeError):
        decoded = None
    if isinstance(decoded, list):
        record_count = len(decoded)

    return InspectBuildRunsOutcome(
        artifact_path=artifact,
        record_count=record_count,
        result=result,
    )


@dataclass(frozen=True)
class InspectFailuresOutcome:
    """Result of ``evidentia inspect failures`` (Phase 48).

    ``artifact_path`` points to the verbatim stdout (a JSON array of
    ``schema.validation_failed`` event records) persisted under
    ``artifacts/evidentia/`` with an ``inspect-failures-`` prefix.

    ``record_count`` is the length of the top-level JSON array, or
    ``None`` if the body was not an array (for example ``null`` from
    a workspace with no validation failures). Empusa intentionally
    does not parse any per-record fields; the underlying event
    schema is owned by Evidentia.
    """

    artifact_path: Path
    record_count: int | None
    result: EvidentiaResult


def inspect_failures(
    workspace_path: Path,
    *,
    limit: int | None = None,
    pretty: bool = False,
    binary: str = DEFAULT_BINARY,
    db_path: Path | None = None,
    timeout: float | None = None,
) -> InspectFailuresOutcome:
    """Run ``evidentia inspect failures`` and persist the output.

    The wrapper invokes the read-only failures inspection surface
    and stores stdout byte-for-byte as a workspace artifact under
    ``artifacts/evidentia/inspect-failures-<ts>.json``. On
    failure the stderr stream is persisted under the same prefix
    with a ``.stderr`` suffix and :class:`EvidentiaCLIError` is
    raised.

    ``limit`` and ``pretty`` map directly onto Evidentia's
    ``--limit`` / ``--pretty`` flags; both are forwarded only when
    set so the wrapper does not change Evidentia's defaults.

    The wrapper does not interpret per-record fields. It only
    inspects the top-level JSON shape to derive ``record_count`` for
    the operator summary; the underlying event schema is owned by
    Evidentia.
    """

    if limit is not None and limit < 0:
        raise ValueError(f"limit must be >= 0, got {limit}")

    argv: list[str] = ["inspect", "failures"]
    if limit is not None and limit > 0:
        argv.extend(["--limit", str(limit)])
    if pretty:
        argv.append("--pretty")

    result = run_evidentia_command(
        argv,
        workspace_path=workspace_path,
        binary=binary,
        db_path=db_path,
        timeout=timeout,
    )

    if not result.ok:
        stderr_path = _persist_stream(
            workspace_path,
            kind="inspect-failures",
            suffix="stderr",
            payload=result.stderr,
        )
        _write_meta_sidecar(stderr_path, result, stderr_path=stderr_path)
        raise EvidentiaCLIError(result, stderr_path=stderr_path)

    artifact = _persist_stream(
        workspace_path,
        kind="inspect-failures",
        suffix="json",
        payload=result.stdout,
    )
    _write_meta_sidecar(artifact, result)

    record_count: int | None = None
    try:
        decoded = json.loads(result.stdout)
    except (ValueError, TypeError):
        decoded = None
    if isinstance(decoded, list):
        record_count = len(decoded)

    return InspectFailuresOutcome(
        artifact_path=artifact,
        record_count=record_count,
        result=result,
    )


@dataclass(frozen=True)
class InspectWorkspaceSummaryOutcome:
    """Result of ``evidentia inspect workspace-summary`` (Phase 42).

    ``artifact_path`` points to the verbatim stdout (a single flat
    JSON object of scalar counters and timestamp anchors) persisted
    under ``artifacts/evidentia/`` with an ``inspect-workspace-summary-``
    prefix.

    ``scalars`` is the parsed top-level mapping. The wrapper accepts
    the body only if it decodes to a JSON object whose values are
    scalars (numbers, strings, booleans, or ``null``); nested
    objects or arrays would imply Evidentia changed the workspace
    summary contract from "flat scalar object" to something else
    and Empusa must surface that as an error rather than silently
    project a partial view. ``scalars`` is ``None`` if the body did
    not decode to such an object (for example a JSON ``null``); the
    artifact is still persisted.
    """

    artifact_path: Path
    scalars: dict[str, object] | None
    result: EvidentiaResult


def inspect_workspace_summary(
    workspace_path: Path,
    *,
    binary: str = DEFAULT_BINARY,
    db_path: Path | None = None,
    timeout: float | None = None,
) -> InspectWorkspaceSummaryOutcome:
    """Run ``evidentia inspect workspace-summary`` and persist output.

    The wrapper invokes the Phase-42 inspect surface and stores
    stdout byte-for-byte as a workspace artifact under
    ``artifacts/evidentia/inspect-workspace-summary-<timestamp>.json``.
    On failure the stderr stream is persisted under the same prefix
    with a ``.stderr`` suffix and :class:`EvidentiaCLIError` is
    raised.

    The wrapper parses only top-level scalar fields. Per-field
    semantics belong to Evidentia; the operator surface is free to
    display them but the wrapper itself does not interpret any
    individual key.
    """

    result = run_evidentia_command(
        ["inspect", "workspace-summary"],
        workspace_path=workspace_path,
        binary=binary,
        db_path=db_path,
        timeout=timeout,
    )

    if not result.ok:
        stderr_path = _persist_stream(
            workspace_path,
            kind="inspect-workspace-summary",
            suffix="stderr",
            payload=result.stderr,
        )
        _write_meta_sidecar(stderr_path, result, stderr_path=stderr_path)
        raise EvidentiaCLIError(result, stderr_path=stderr_path)

    artifact = _persist_stream(
        workspace_path,
        kind="inspect-workspace-summary",
        suffix="json",
        payload=result.stdout,
    )
    _write_meta_sidecar(artifact, result)

    scalars: dict[str, object] | None = None
    try:
        decoded = json.loads(result.stdout)
    except (ValueError, TypeError):
        decoded = None
    if isinstance(decoded, dict) and all(
        value is None or isinstance(value, (bool, int, float, str)) for value in decoded.values()
    ):
        scalars = decoded

    return InspectWorkspaceSummaryOutcome(
        artifact_path=artifact,
        scalars=scalars,
        result=result,
    )


@dataclass(frozen=True)
class WorkspaceReportOutcome:
    """Result of :func:`generate_workspace_report` (Phase 43).

    ``artifact_path`` points to ``artifacts/evidentia/report-<timestamp>.json``,
    a NEW Empusa-owned artifact distinct from the underlying raw
    Evidentia stdout artifacts (which are still persisted unchanged
    by the underlying wrappers).

    ``report`` is the parsed JSON body for in-process callers
    (operator CLI, future hooks). It is the same content written to
    ``artifact_path``.

    ``summary_outcome`` and ``replay_outcome`` are the wrapper
    outcomes the report is composed from, so callers do not need to
    re-shell the binary to recover the underlying provenance.
    """

    artifact_path: Path
    report: dict[str, object]
    summary_outcome: InspectWorkspaceSummaryOutcome
    replay_outcome: ReplayOutcome


# Warning codes emitted by :func:`generate_workspace_report`. Stable
# strings so downstream tooling (and the Empusa report-rendering
# code path) can switch on them without parsing prose.
REPORT_WARNING_SCHEMA_FAILURES = "schema_failures_present"
REPORT_WARNING_REPLAY_DIVERGED = "replay_diverged"
REPORT_WARNING_NO_BUILD_RUNS = "no_build_runs"
REPORT_WARNING_DIRECTORY_EMPTY = "directory_empty"

# Directory-entity counter keys whose collective zero state triggers
# the ``directory_empty`` warning. Defined here so the report stays
# in sync with the workspace-summary contract without re-deriving
# the field names anywhere else.
_REPORT_DIRECTORY_COUNT_KEYS: tuple[str, ...] = (
    "directory_user_count",
    "directory_group_count",
    "directory_computer_count",
    "directory_relationship_count",
    "directory_alias_count",
)


def generate_workspace_report(
    workspace_path: Path,
    *,
    binary: str = DEFAULT_BINARY,
    db_path: Path | None = None,
) -> WorkspaceReportOutcome:
    """Compose an operator-facing workspace evidence report.

    The report is a strict composition of two existing wrappers:
    :func:`inspect_workspace_summary` and :func:`replay`. No new
    Evidentia subcommand is invoked, no schema is transformed, and
    no Evidentia store is read directly. The underlying wrappers
    persist their own raw stdout artifacts unchanged; this function
    additionally writes a NEW Empusa-owned artifact under
    ``artifacts/evidentia/report-<timestamp>.json`` whose body
    references the raw artifact paths and surfaces a small set of
    operator-relevant warnings.

    ``replay`` is invoked with ``write=False`` so the report stays
    read-only with respect to the live state store.

    Failure modes:

    - if the underlying ``inspect workspace-summary`` or ``replay``
      call fails, the matching :class:`EvidentiaCLIError` is
      propagated unchanged so the operator surface keeps the same
      classification semantics it has elsewhere.
    """

    summary_outcome = inspect_workspace_summary(
        workspace_path=workspace_path,
        binary=binary,
        db_path=db_path,
    )
    replay_outcome = replay(
        workspace_path=workspace_path,
        binary=binary,
        db_path=db_path,
        write=False,
    )

    counts: dict[str, object] = dict(summary_outcome.scalars) if summary_outcome.scalars else {}

    warnings: list[str] = []
    schema_failures = counts.get("schema_failure_count")
    if isinstance(schema_failures, (int, float)) and schema_failures > 0:
        warnings.append(REPORT_WARNING_SCHEMA_FAILURES)
    if replay_outcome.diff_count > 0:
        warnings.append(REPORT_WARNING_REPLAY_DIVERGED)
    build_runs = counts.get("build_run_count")
    if isinstance(build_runs, (int, float)) and build_runs == 0:
        warnings.append(REPORT_WARNING_NO_BUILD_RUNS)
    directory_values = [counts.get(k) for k in _REPORT_DIRECTORY_COUNT_KEYS]
    if directory_values and all(isinstance(v, (int, float)) and v == 0 for v in directory_values):
        warnings.append(REPORT_WARNING_DIRECTORY_EMPTY)

    report: dict[str, object] = {
        "generated_at": _utc_iso(),
        "workspace_path": str(Path(workspace_path)),
        "summary_artifact": str(summary_outcome.artifact_path),
        "replay_artifact": str(replay_outcome.artifact_path),
        "replay_diff_count": replay_outcome.diff_count,
        "counts": counts,
        "warnings": warnings,
    }

    artifact_dir = _artifacts_dir(workspace_path)
    artifact = artifact_dir / f"report-{_utc_timestamp()}.json"
    artifact.write_bytes((json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))

    return WorkspaceReportOutcome(
        artifact_path=artifact,
        report=report,
        summary_outcome=summary_outcome,
        replay_outcome=replay_outcome,
    )


@dataclass(frozen=True)
class AuditOutcome:
    """Result of an ``audit capability-run`` workflow run."""

    run_id: str
    artifact_path: Path
    result: EvidentiaResult


def audit_capability_run(
    workspace_path: Path,
    run_id: str,
    *,
    binary: str = DEFAULT_BINARY,
    db_path: Path | None = None,
) -> AuditOutcome:
    """Fetch and persist an Evidentia capability-run audit report.

    Exit ``1`` (typically "not found") is raised as
    :class:`EvidentiaCLIError`; the caller decides whether to surface
    it as a workflow failure or a soft "no such run" event.
    """

    if not run_id:
        raise ValueError("run_id must not be empty")

    result = run_evidentia_command(
        ["audit", "capability-run", run_id],
        workspace_path=workspace_path,
        binary=binary,
        db_path=db_path,
    )

    if not result.ok:
        raise EvidentiaCLIError(result)

    artifact = _persist_stream(workspace_path, kind="audit", suffix="json", payload=result.stdout, ref=run_id)
    _write_meta_sidecar(artifact, result)
    return AuditOutcome(run_id=run_id, artifact_path=artifact, result=result)


@dataclass(frozen=True)
class ReplayOutcome:
    """Result of a ``replay`` workflow run.

    ``divergence`` is True when Evidentia's reported ``diffs`` array is
    non-empty. The diff payload itself is preserved verbatim in the
    artifact; Empusa never edits or summarizes it.
    """

    artifact_path: Path
    divergence: bool
    diff_count: int
    result: EvidentiaResult


def replay(
    workspace_path: Path,
    *,
    binary: str = DEFAULT_BINARY,
    db_path: Path | None = None,
    alert: Callable[[Path, int], None] | None = None,
    write: bool = False,
) -> ReplayOutcome:
    """Run Evidentia ``replay`` and detect divergence.

    Parsing is intentionally minimal: only the top-level ``diffs``
    array length is inspected, matching the contract's "no schema
    transformation" rule. If ``alert`` is provided and divergence is
    detected, ``alert(artifact_path, diff_count)`` is invoked. Empusa
    never mutates the artifact.

    When ``write=True`` the wrapper invokes ``evidentia replay
    --write``, which materializes derived entities into the live
    state store. The output schema in that mode omits ``diffs`` (the
    live store IS the result), so ``diff_count`` is always zero and
    ``divergence`` is always False. This is the binary surface the
    operator scenarios use to move data from "ingested" to
    "inspectable" without standing up a separate runtime process.
    """

    cmd: list[str] = ["replay"]
    if write:
        cmd.append("--write")
    result = run_evidentia_command(
        cmd,
        workspace_path=workspace_path,
        binary=binary,
        db_path=db_path,
    )

    if not result.ok:
        raise EvidentiaCLIError(result)

    artifact = _persist_stream(workspace_path, kind="replay", suffix="json", payload=result.stdout)
    _write_meta_sidecar(artifact, result)

    diff_count = _diff_count(result.stdout)
    divergence = diff_count > 0
    if divergence and alert is not None:
        alert(artifact, diff_count)

    return ReplayOutcome(
        artifact_path=artifact,
        divergence=divergence,
        diff_count=diff_count,
        result=result,
    )


def _diff_count(stdout: str) -> int:
    """Top-level decision only: count entries in ``.diffs``.

    A missing or null ``diffs`` field is treated as zero. Any deeper
    interpretation of the payload is out of scope for Empusa per the
    integration contract.
    """

    try:
        doc = json.loads(stdout)
    except (TypeError, ValueError):
        return 0
    if not isinstance(doc, dict):
        return 0
    diffs = doc.get("diffs")
    if not isinstance(diffs, list):
        return 0
    return len(diffs)


# Phase 23 directory inspection. Mapped 1:1 onto
# ``evidentia inspect directory <subject>`` -- Empusa never decodes
# the JSON beyond counting the top-level array length for an
# operator-visible "records" field.
DIRECTORY_INSPECT_SUBJECTS: tuple[str, ...] = (
    "users",
    "groups",
    "computers",
    "relationships",
)


@dataclass(frozen=True)
class InspectOutcome:
    """Result of an ``inspect directory <subject>`` workflow run.

    ``record_count`` is the length of the top-level JSON array in
    ``stdout``. Per the integration contract, Empusa never inspects
    individual records; the count is surfaced only as an operator
    convenience.
    """

    subject: str
    artifact_path: Path
    record_count: int
    result: EvidentiaResult


def inspect_directory(
    workspace_path: Path,
    *,
    subject: str,
    limit: int | None = None,
    pretty: bool = False,
    binary: str = DEFAULT_BINARY,
    db_path: Path | None = None,
) -> InspectOutcome:
    """Run ``evidentia inspect directory <subject>`` and persist stdout.

    ``subject`` must be one of :data:`DIRECTORY_INSPECT_SUBJECTS`.
    ``limit`` and ``pretty`` map directly onto Evidentia's
    ``--limit`` / ``--pretty`` flags; both are forwarded only when set
    so the wrapper does not change Evidentia's defaults.
    """

    if subject not in DIRECTORY_INSPECT_SUBJECTS:
        raise ValueError(
            f"unknown directory inspect subject: {subject!r} (expected one of {sorted(DIRECTORY_INSPECT_SUBJECTS)})"
        )
    if limit is not None and limit < 0:
        raise ValueError(f"limit must be >= 0, got {limit}")

    argv: list[str] = ["inspect", "directory", subject]
    if limit is not None and limit > 0:
        argv.extend(["--limit", str(limit)])
    if pretty:
        argv.append("--pretty")

    result = run_evidentia_command(
        argv,
        workspace_path=workspace_path,
        binary=binary,
        db_path=db_path,
    )

    if not result.ok:
        raise EvidentiaCLIError(result)

    artifact = _persist_stream(
        workspace_path,
        kind="inspect-directory",
        suffix="json",
        payload=result.stdout,
        ref=subject,
    )
    _write_meta_sidecar(artifact, result)
    return InspectOutcome(
        subject=subject,
        artifact_path=artifact,
        record_count=_record_count(result.stdout),
        result=result,
    )


def _record_count(stdout: str) -> int:
    """Length of the top-level JSON array in ``stdout``.

    A missing, null, or non-array document is treated as zero. This
    is the only inspection Empusa performs on the inspect-directory
    payload -- record contents stay opaque per the contract.
    """

    try:
        doc = json.loads(stdout)
    except (TypeError, ValueError):
        return 0
    if not isinstance(doc, list):
        return 0
    return len(doc)


# Phase 24: directory relationship views. ``neighbors`` and
# ``memberships`` both take a positional canonical_key and produce
# a flat one-hop projection. The wrapper does not interpret the
# records beyond counting the top-level array.
DIRECTORY_VIEW_SUBJECTS: tuple[str, ...] = ("neighbors", "memberships")


@dataclass(frozen=True)
class InspectViewOutcome:
    """Result of an ``inspect directory <view> <key>`` workflow run."""

    view: str
    key: str
    artifact_path: Path
    record_count: int
    result: EvidentiaResult


def inspect_directory_view(
    workspace_path: Path,
    *,
    view: str,
    key: str,
    limit: int | None = None,
    pretty: bool = False,
    binary: str = DEFAULT_BINARY,
    db_path: Path | None = None,
) -> InspectViewOutcome:
    """Run ``evidentia inspect directory <view> <key>`` and persist stdout.

    ``view`` must be one of :data:`DIRECTORY_VIEW_SUBJECTS`. ``key``
    is forwarded verbatim -- Evidentia is responsible for normalizing
    casing per identifier kind. Empusa never edits the key or the
    payload.
    """

    if view not in DIRECTORY_VIEW_SUBJECTS:
        raise ValueError(f"unknown directory view: {view!r} (expected one of {sorted(DIRECTORY_VIEW_SUBJECTS)})")
    if not isinstance(key, str) or not key.strip():
        raise ValueError("key must be a non-empty string")
    if limit is not None and limit < 0:
        raise ValueError(f"limit must be >= 0, got {limit}")

    argv: list[str] = ["inspect", "directory", view]
    if limit is not None and limit > 0:
        argv.extend(["--limit", str(limit)])
    if pretty:
        argv.append("--pretty")
    argv.append(key)

    result = run_evidentia_command(
        argv,
        workspace_path=workspace_path,
        binary=binary,
        db_path=db_path,
    )

    if not result.ok:
        raise EvidentiaCLIError(result)

    artifact = _persist_stream(
        workspace_path,
        kind="inspect-directory",
        suffix="json",
        payload=result.stdout,
        ref=f"{view}-{key}",
    )
    _write_meta_sidecar(artifact, result)
    return InspectViewOutcome(
        view=view,
        key=key,
        artifact_path=artifact,
        record_count=_record_count(result.stdout),
        result=result,
    )


# Phase 32: alias-aware directory lookup. Mapped 1:1 onto
# ``evidentia inspect directory aliases <value> [--kind KIND]``.
# Accepted kinds mirror the Evidentia CLI surface; ``dns`` is
# accepted as an operator-friendly alias for ``dnshost``.
DIRECTORY_ALIAS_KINDS: tuple[str, ...] = (
    "dn",
    "guid",
    "sid",
    "sam",
    "upn",
    "dns",
    "dnshost",
)


@dataclass(frozen=True)
class InspectAliasOutcome:
    """Result of an ``inspect directory aliases <value>`` workflow run.

    ``record_count`` is the length of the top-level JSON array in
    ``stdout``. Per the integration contract, Empusa never decodes
    individual alias records beyond the array length; the artifact
    file is the canonical operator-facing payload.
    """

    value: str
    kind: str | None
    artifact_path: Path
    record_count: int
    result: EvidentiaResult


def inspect_directory_aliases(
    workspace_path: Path,
    *,
    value: str,
    kind: str | None = None,
    limit: int | None = None,
    pretty: bool = False,
    binary: str = DEFAULT_BINARY,
    db_path: Path | None = None,
) -> InspectAliasOutcome:
    """Run ``evidentia inspect directory aliases <value>`` and persist stdout.

    ``value`` is the operator-supplied alias value (SID/GUID/DN/etc.)
    forwarded verbatim -- Evidentia is responsible for normalizing
    casing per identifier kind. ``kind`` is optional; when supplied
    it must be one of :data:`DIRECTORY_ALIAS_KINDS`.

    Empusa never edits the value, the kind, or the payload; the
    contract is "shell out, persist, count". Conflicting alias
    records (multiple ``canonical_keys`` on a single entity) are
    preserved verbatim in the artifact and are NOT collapsed.
    """

    if not isinstance(value, str) or not value.strip():
        raise ValueError("value must be a non-empty string")
    if kind is not None and kind not in DIRECTORY_ALIAS_KINDS:
        raise ValueError(f"unknown alias kind: {kind!r} (expected one of {sorted(DIRECTORY_ALIAS_KINDS)})")
    if limit is not None and limit < 0:
        raise ValueError(f"limit must be >= 0, got {limit}")

    argv: list[str] = ["inspect", "directory", "aliases", value]
    if kind is not None:
        argv.extend(["--kind", kind])
    if limit is not None and limit > 0:
        argv.extend(["--limit", str(limit)])
    if pretty:
        argv.append("--pretty")

    result = run_evidentia_command(
        argv,
        workspace_path=workspace_path,
        binary=binary,
        db_path=db_path,
    )

    if not result.ok:
        raise EvidentiaCLIError(result)

    ref = f"aliases-{kind or 'any'}-{value}"
    artifact = _persist_stream(
        workspace_path,
        kind="inspect-directory",
        suffix="json",
        payload=result.stdout,
        ref=ref,
    )
    _write_meta_sidecar(artifact, result)
    return InspectAliasOutcome(
        value=value,
        kind=kind,
        artifact_path=artifact,
        record_count=_record_count(result.stdout),
        result=result,
    )
