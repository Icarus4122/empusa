"""Empusa Evidentia integration plugin.

This plugin is a thin first-class wrapper around
:mod:`empusa.evidentia` -- the *only* module allowed to invoke the
``evidentia`` binary. It registers three capabilities under the
``analyzer`` category:

- ``evidentia.ingest_jsonl``       -> :func:`empusa.evidentia.ingest_jsonl`
- ``evidentia.replay``             -> :func:`empusa.evidentia.replay`
- ``evidentia.audit_capability_run`` -> :func:`empusa.evidentia.audit_capability_run`

Per the integration contract (see
``Evidentia/docs/integration/empusa-evidentia.md``) this plugin:

- imports nothing from Evidentia source / Go packages,
- never opens or reads Evidentia's Badger store,
- never reshapes or re-encodes Evidentia stdout (artifacts are
  byte-for-byte from the wrapper),
- never retries on a usage error (exit 2),
- exposes no autonomous behavior; capabilities run only when invoked.

Each handler returns a small, fully-derived status dict so callers
can route on ``exit_code`` / ``stderr_path`` without re-parsing
artifacts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# The ONLY permitted bridge to Evidentia. Do not add imports from
# Evidentia source, vendored Go packages, or Badger.
from empusa import evidentia

PLUGIN_NAME = "evidentia"
CAPABILITY_CATEGORY = "analyzer"

CAP_INGEST_JSONL = "evidentia.ingest_jsonl"
CAP_REPLAY = "evidentia.replay"
CAP_AUDIT_CAPABILITY_RUN = "evidentia.audit_capability_run"

_services: Any = None


def _coerce_path(value: str | Path) -> Path:
    return value if isinstance(value, Path) else Path(value)


def _failure_payload(exc: evidentia.EvidentiaCLIError) -> dict[str, Any]:
    """Shape an ``EvidentiaCLIError`` into a status dict.

    No JSON parsing, no schema interpretation. Stderr is forwarded as
    a raw string from the wrapper's :class:`EvidentiaResult`.
    """
    return {
        "ok": False,
        "exit_code": exc.result.exit_code,
        "is_usage_error": exc.result.is_usage_error,
        "stderr_path": exc.stderr_path,
        "stderr": exc.result.stderr,
    }


def ingest_jsonl(
    workspace_path: str | Path,
    jsonl_path: str | Path,
    *,
    binary: str = evidentia.DEFAULT_BINARY,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Capability handler for ``evidentia.ingest_jsonl``.

    Returns a status dict with ``artifact_path`` on success or
    ``stderr_path`` + ``exit_code`` on failure. Never retries.
    """
    db = _coerce_path(db_path) if db_path is not None else None
    try:
        outcome = evidentia.ingest_jsonl(
            workspace_path=_coerce_path(workspace_path),
            jsonl_path=_coerce_path(jsonl_path),
            binary=binary,
            db_path=db,
        )
    except evidentia.EvidentiaCLIError as exc:
        return _failure_payload(exc)

    return {
        "ok": True,
        "exit_code": outcome.result.exit_code,
        "artifact_path": outcome.artifact_path,
        "stderr_path": outcome.stderr_path,
    }


def replay(
    workspace_path: str | Path,
    *,
    binary: str = evidentia.DEFAULT_BINARY,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Capability handler for ``evidentia.replay``.

    Surfaces ``divergence`` and ``diff_count`` directly from the
    wrapper. Plugin does NOT inspect or rewrite the diff payload.
    """
    db = _coerce_path(db_path) if db_path is not None else None
    diverged: list[tuple[Path, int]] = []

    def _alert(artifact: Path, diff_count: int) -> None:
        diverged.append((artifact, diff_count))

    try:
        outcome = evidentia.replay(
            workspace_path=_coerce_path(workspace_path),
            binary=binary,
            db_path=db,
            alert=_alert,
        )
    except evidentia.EvidentiaCLIError as exc:
        return _failure_payload(exc)

    return {
        "ok": True,
        "exit_code": outcome.result.exit_code,
        "artifact_path": outcome.artifact_path,
        "divergence": outcome.divergence,
        "diff_count": outcome.diff_count,
        "alerts": list(diverged),
    }


def audit_capability_run(
    workspace_path: str | Path,
    run_id: str,
    *,
    binary: str = evidentia.DEFAULT_BINARY,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Capability handler for ``evidentia.audit_capability_run``."""
    db = _coerce_path(db_path) if db_path is not None else None
    try:
        outcome = evidentia.audit_capability_run(
            workspace_path=_coerce_path(workspace_path),
            run_id=run_id,
            binary=binary,
            db_path=db,
        )
    except evidentia.EvidentiaCLIError as exc:
        return _failure_payload(exc)

    return {
        "ok": True,
        "exit_code": outcome.result.exit_code,
        "run_id": outcome.run_id,
        "artifact_path": outcome.artifact_path,
    }


# -- Plugin lifecycle ----------------------------------------------


def activate(services: Any, registry: Any, bus: Any) -> None:
    """Register the three Evidentia capabilities.

    The registry stores callables; framework code invokes them via
    ``registry.get_by_name(category, name).handler(...)``.
    """
    global _services
    _services = services

    if registry is None:
        return

    registry.register(
        CAPABILITY_CATEGORY,
        CAP_INGEST_JSONL,
        ingest_jsonl,
        plugin_name=PLUGIN_NAME,
        description="Ingest a JSONL file via Evidentia (wrapper-only).",
    )
    registry.register(
        CAPABILITY_CATEGORY,
        CAP_REPLAY,
        replay,
        plugin_name=PLUGIN_NAME,
        description="Run Evidentia replay; surfaces divergence + diff count.",
    )
    registry.register(
        CAPABILITY_CATEGORY,
        CAP_AUDIT_CAPABILITY_RUN,
        audit_capability_run,
        plugin_name=PLUGIN_NAME,
        description="Fetch and persist an Evidentia capability-run audit report.",
    )


def deactivate() -> None:
    """No-op: plugin owns no background state.

    Capability entries are removed by the plugin manager via
    ``registry.unregister_plugin(name)``.
    """
    global _services
    _services = None
