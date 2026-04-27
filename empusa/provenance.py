"""
Empusa - Build/workshop provenance envelope emission.

Source-neutral, schema-pinned record of *what was executed, where, by whom,
and with what result*. The on-disk JSON shape is wire-compatible with the
Evidentia ``build.provenance_envelope`` schema (Evidentia/pkg/build) so that
a future ingest path can wrap an envelope into a typed Evidentia ``Payload``
without translation.

Boundary discipline
-------------------
This module:

- does **not** import from Evidentia
- does **not** call any Evidentia binary
- does **not** alter build/workshop execution behavior
- only writes a JSON artifact under the workspace logs directory

If writing the envelope fails for any reason, the build flow continues; the
envelope is provenance, not control.

Wire shape
----------
The emitted JSON object carries every Evidentia ``ProvenanceEnvelope`` field
plus two self-describing keys::

    {
      "schema_id":      "build.provenance_envelope",
      "schema_version": "1.0.0",
      "envelope_id":    {"value": "<uuid>"},
      "workspace_id":   {"value": "<uuid>"},
      ...
      "started_at":     {"time": "2026-04-26T12:34:56.789Z"},
      "evidence_source": {"source_id": {"value": "..."}, ...},
      "confidence":     {"value": 1.0}
    }

``ID``, ``Timestamp``, ``Confidence``, and ``SourceAttribution`` are emitted
in the exact JSON shape used by ``Evidentia/pkg/common`` so the artifact
round-trips through ``schema.Codec.Decode`` once an Evidentia ingest adapter
exists.
"""

from __future__ import annotations

import getpass
import json
import os
import platform
import socket
import sys
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from empusa import __version__ as _EMPUSA_VERSION

# -- Schema constants ------------------------------------------------

SCHEMA_ID: str = "build.provenance_envelope"
SCHEMA_VERSION: str = "1.0.0"
SOURCE_REPO: str = "empusa"

# UUID namespace used to derive a stable workspace_id from a workspace path
# when no explicit id is supplied. Random fixed UUID; do not change.
_WORKSPACE_ID_NAMESPACE = uuid.UUID("8e9d3a4b-2c01-4f7e-9b45-2d6f1c0a17a3")

# Argv keys whose *immediately following* value should be redacted. The list
# is intentionally minimal; producers must redact domain-specific secrets
# before passing argv in.
_DEFAULT_REDACT_KEYS: frozenset[str] = frozenset(
    {
        "--password",
        "--pass",
        "-p",
        "--secret",
        "--token",
        "--api-key",
        "--apikey",
    }
)
_REDACTED_PLACEHOLDER: str = "***REDACTED***"


# -- Dataclasses -----------------------------------------------------


@dataclass(frozen=True)
class EvidenceSource:
    """Mirror of Evidentia ``common.SourceAttribution`` JSON shape."""

    source_id: str
    source_type: str
    source_name: str
    collected_at: datetime

    def to_json(self) -> dict[str, Any]:
        return {
            "source_id": {"value": self.source_id},
            "source_type": self.source_type,
            "source_name": self.source_name,
            "collected_at": {"time": _iso_utc(self.collected_at)},
        }


@dataclass
class ProvenanceEnvelope:
    """Empusa-side mirror of Evidentia ``build.ProvenanceEnvelope``.

    Field names and JSON shapes match Evidentia exactly so the artifact is
    wire-compatible without translation.
    """

    envelope_id: str
    workspace_id: str
    run_id: str

    source_repo: str
    source_tool: str
    command_name: str
    hostname: str
    started_at: datetime
    evidence_source: EvidenceSource
    confidence: float

    # Optional / context fields
    source_tool_version: str = ""
    argv_redacted: list[str] = field(default_factory=list)
    working_directory: str = ""
    executable_name: str = ""
    executable_path: str = ""
    username: str = ""
    pid: int = 0
    uid_or_sid: str = ""
    completed_at: datetime | None = None
    exit_code: int | None = None
    environment_refs: list[str] = field(default_factory=list)
    input_artifact_refs: list[str] = field(default_factory=list)
    output_artifact_refs: list[str] = field(default_factory=list)
    log_artifact_refs: list[str] = field(default_factory=list)

    # -- Serialisation ---------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        """Render the envelope as a JSON-serialisable dict.

        Field ordering, key names, and nested object shapes match Evidentia's
        Go struct encoding for ``build.ProvenanceEnvelope``.
        """
        body: dict[str, Any] = {
            "schema_id": SCHEMA_ID,
            "schema_version": SCHEMA_VERSION,
            "envelope_id": {"value": self.envelope_id},
            "workspace_id": {"value": self.workspace_id},
            "run_id": {"value": self.run_id},
            "source_repo": self.source_repo,
            "source_tool": self.source_tool,
            "command_name": self.command_name,
            "hostname": self.hostname,
            "started_at": {"time": _iso_utc(self.started_at)},
            "evidence_source": self.evidence_source.to_json(),
            "confidence": {"value": self.confidence},
        }
        if self.source_tool_version:
            body["source_tool_version"] = self.source_tool_version
        if self.argv_redacted:
            body["argv_redacted"] = list(self.argv_redacted)
        if self.working_directory:
            body["working_directory"] = self.working_directory
        if self.executable_name:
            body["executable_name"] = self.executable_name
        if self.executable_path:
            body["executable_path"] = self.executable_path
        if self.username:
            body["username"] = self.username
        if self.pid:
            body["pid"] = self.pid
        if self.uid_or_sid:
            body["uid_or_sid"] = self.uid_or_sid
        if self.completed_at is not None:
            body["completed_at"] = {"time": _iso_utc(self.completed_at)}
        if self.exit_code is not None:
            body["exit_code"] = self.exit_code
        for key, refs in (
            ("environment_refs", self.environment_refs),
            ("input_artifact_refs", self.input_artifact_refs),
            ("output_artifact_refs", self.output_artifact_refs),
            ("log_artifact_refs", self.log_artifact_refs),
        ):
            if refs:
                body[key] = [{"value": r} for r in refs]
        return body

    def validate(self) -> None:
        """Mirror Evidentia ``ProvenanceEnvelope.Validate`` semantics.

        Raises ``ValueError`` on any rule violation so callers can fail fast
        in tests.
        """
        if not self.envelope_id:
            raise ValueError("envelope_id is required")
        if not self.workspace_id:
            raise ValueError("workspace_id is required")
        if not self.run_id:
            raise ValueError("run_id is required")
        if not self.source_repo:
            raise ValueError("source_repo is required")
        if not self.source_tool:
            raise ValueError("source_tool is required")
        if not self.command_name:
            raise ValueError("command_name is required")
        if not self.hostname:
            raise ValueError("hostname is required")
        if self.started_at is None:
            raise ValueError("started_at is required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence {self.confidence} out of range [0.0, 1.0]")
        if not self.evidence_source.source_id:
            raise ValueError("evidence_source.source_id is required")
        if not self.evidence_source.source_type:
            raise ValueError("evidence_source.source_type is required")
        if self.evidence_source.collected_at is None:
            raise ValueError("evidence_source.collected_at is required")
        if self.completed_at is not None:
            if self.completed_at < self.started_at:
                raise ValueError("completed_at is before started_at")
            if self.exit_code is None:
                raise ValueError("exit_code is required when completed_at is set")


# -- Factory ---------------------------------------------------------


def build_envelope(
    *,
    command_name: str,
    workspace_path: Path | None,
    workspace_id: str | None = None,
    run_id: str | None = None,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    exit_code: int | None = None,
    argv: Iterable[str] | None = None,
    redact_keys: Iterable[str] | None = None,
    input_artifact_refs: Iterable[str] = (),
    output_artifact_refs: Iterable[str] = (),
    log_artifact_refs: Iterable[str] = (),
    environment_refs: Iterable[str] = (),
    confidence: float = 1.0,
) -> ProvenanceEnvelope:
    """Construct a fully-populated ``ProvenanceEnvelope`` for the current process.

    Defaults for host/process context are derived from stdlib ``socket``,
    ``getpass``, ``os``, ``sys``, and ``platform``. ``workspace_id`` is
    derived deterministically from ``workspace_path`` (UUID5) when not given.

    The constructed envelope is validated before return; ``ValueError`` is
    raised on any contract violation.
    """
    started = started_at or datetime.now(timezone.utc)
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)

    if completed_at is not None and completed_at.tzinfo is None:
        completed_at = completed_at.replace(tzinfo=timezone.utc)

    ws_id = workspace_id or _derive_workspace_id(workspace_path)
    rid = run_id or str(uuid.uuid4())
    eid = str(uuid.uuid4())

    argv_list = _redact_argv(list(argv or []), set(redact_keys or _DEFAULT_REDACT_KEYS))

    exe_path = sys.executable or ""
    exe_name = Path(exe_path).name if exe_path else ""

    uid_or_sid = ""
    if hasattr(os, "geteuid"):
        try:
            uid_or_sid = str(os.geteuid())  # type: ignore[attr-defined]
        except OSError:
            uid_or_sid = ""
    else:
        # Windows: best-effort SID via env var; avoids a hard ctypes dep.
        uid_or_sid = os.environ.get("USERDOMAIN_ROAMINGPROFILE", "") or os.environ.get("USERNAME", "")

    try:
        username = getpass.getuser()
    except Exception:
        username = ""

    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = platform.node() or "unknown-host"
    if not hostname:
        hostname = "unknown-host"

    evidence = EvidenceSource(
        source_id=str(uuid.uuid4()),
        source_type="empusa.build",
        source_name=f"empusa@{_EMPUSA_VERSION}",
        collected_at=started,
    )

    env = ProvenanceEnvelope(
        envelope_id=eid,
        workspace_id=ws_id,
        run_id=rid,
        source_repo=SOURCE_REPO,
        source_tool="empusa",
        source_tool_version=_EMPUSA_VERSION,
        command_name=command_name,
        argv_redacted=argv_list,
        working_directory=str(workspace_path) if workspace_path else os.getcwd(),
        executable_name=exe_name,
        executable_path=exe_path,
        hostname=hostname,
        username=username,
        pid=os.getpid(),
        uid_or_sid=uid_or_sid,
        started_at=started,
        completed_at=completed_at,
        exit_code=exit_code,
        environment_refs=list(environment_refs),
        input_artifact_refs=list(input_artifact_refs),
        output_artifact_refs=list(output_artifact_refs),
        log_artifact_refs=list(log_artifact_refs),
        evidence_source=evidence,
        confidence=confidence,
    )
    env.validate()
    return env


# -- Writer ----------------------------------------------------------


def write_envelope(envelope: ProvenanceEnvelope, artifacts_dir: Path) -> Path:
    """Write *envelope* as JSON under ``<artifacts_dir>/provenance/``.

    Creates the ``provenance/`` subdirectory if necessary. Returns the
    absolute path to the written file. Filename is
    ``<envelope_id>.provenance.json`` so concurrent emits never collide.

    The envelope is validated before write; an invalid envelope raises
    ``ValueError`` and no file is written.
    """
    envelope.validate()
    target_dir = Path(artifacts_dir) / "provenance"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{envelope.envelope_id}.provenance.json"
    payload = json.dumps(envelope.to_json(), indent=2, sort_keys=False) + "\n"
    target.write_text(payload, encoding="utf-8")
    return target


def emit_build_envelope(
    *,
    command_name: str,
    workspace_path: Path | None,
    artifacts_dir: Path,
    started_at: datetime,
    completed_at: datetime | None = None,
    exit_code: int | None = None,
    argv: Iterable[str] | None = None,
    output_artifact_refs: Iterable[str] = (),
    log_artifact_refs: Iterable[str] = (),
    workspace_id: str | None = None,
    run_id: str | None = None,
) -> Path:
    """Convenience: build, validate, and write an envelope in one call.

    Returns the path to the written artifact. Callers in non-critical paths
    should wrap this in ``try/except`` so envelope-emission failure cannot
    abort the underlying build.
    """
    env = build_envelope(
        command_name=command_name,
        workspace_path=workspace_path,
        workspace_id=workspace_id,
        run_id=run_id,
        started_at=started_at,
        completed_at=completed_at,
        exit_code=exit_code,
        argv=argv,
        output_artifact_refs=output_artifact_refs,
        log_artifact_refs=log_artifact_refs,
    )
    return write_envelope(env, artifacts_dir)


# -- Helpers ---------------------------------------------------------


def _redact_argv(argv: list[str], redact_keys: set[str]) -> list[str]:
    """Return a copy of *argv* with values for known secret keys masked.

    Only the immediately following positional value is masked. ``--key=value``
    forms are masked by replacing the value portion. Order is preserved.
    """
    out: list[str] = []
    skip_next = False
    for token in argv:
        if skip_next:
            out.append(_REDACTED_PLACEHOLDER)
            skip_next = False
            continue
        if "=" in token:
            key, _, _val = token.partition("=")
            if key in redact_keys:
                out.append(f"{key}={_REDACTED_PLACEHOLDER}")
                continue
        if token in redact_keys:
            out.append(token)
            skip_next = True
            continue
        out.append(token)
    return out


def _derive_workspace_id(workspace_path: Path | None) -> str:
    """Derive a stable workspace UUID from its absolute path.

    When *workspace_path* is None (standalone build), generate a fresh UUID4
    so the envelope is still valid. Same workspace path always produces the
    same UUID5; callers that need explicit control should pass ``workspace_id``.
    """
    if workspace_path is None:
        return str(uuid.uuid4())
    abs_path = str(Path(workspace_path).expanduser().resolve())
    return str(uuid.uuid5(_WORKSPACE_ID_NAMESPACE, abs_path))


def _iso_utc(ts: datetime) -> str:
    """Render *ts* as an RFC3339 UTC timestamp matching Go ``time.Time`` JSON."""
    ts = ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)
    # Go encodes time.Time with nanosecond precision; Python only carries
    # microseconds. Use isoformat with 'Z' suffix to match RFC3339.
    return ts.isoformat().replace("+00:00", "Z")


__all__ = [
    "SCHEMA_ID",
    "SCHEMA_VERSION",
    "SOURCE_REPO",
    "EvidenceSource",
    "ProvenanceEnvelope",
    "build_envelope",
    "write_envelope",
    "emit_build_envelope",
]
