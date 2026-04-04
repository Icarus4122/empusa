"""
Empusa - Typed Event Payloads

Strongly typed dataclasses for every lifecycle event in the framework.
Replaces freeform context dicts with predictable, documented schemas.

Legacy hooks still receive ``dict`` via the bus adapter layer;
new-style plugins receive the dataclass instance directly.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, cast

# -- Base -----------------------------------------------------------


@dataclass
class EmpusaEvent:
    """Base class for all Empusa events.

    Every event carries at minimum:
    - ``event``      - the event name string (matches HOOK_EVENTS key)
    - ``timestamp``  - ISO-style timestamp of when the event was created
    - ``session_env``- the currently active environment name (may be empty)
    """

    event: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    session_env: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to a plain dict for legacy hook compatibility."""
        data: dict[str, Any] = {}
        for k, v in asdict(self).items():
            # Convert Path objects to strings for JSON compat
            if isinstance(v, Path):
                data[k] = str(v)
            elif isinstance(v, list):
                data[k] = [str(i) if isinstance(i, Path) else i for i in cast(list[Any], v)]
            else:
                data[k] = v
        return data


# -- Startup / Shutdown ---------------------------------------------


@dataclass
class StartupEvent(EmpusaEvent):
    """Fired when Empusa launches."""

    event: str = "on_startup"


@dataclass
class ShutdownEvent(EmpusaEvent):
    """Fired during graceful shutdown."""

    event: str = "on_shutdown"
    killed_pids: list[str] = field(default_factory=lambda: cast(list[str], []))
    cleaned_hooks: list[str] = field(default_factory=lambda: cast(list[str], []))


# -- Environment ----------------------------------------------------


@dataclass
class EnvSelectEvent(EmpusaEvent):
    """Fired when the user selects or switches an environment."""

    event: str = "on_env_select"
    env_name: str = ""


@dataclass
class PreBuildEvent(EmpusaEvent):
    """Fired *before* an environment build starts."""

    event: str = "pre_build"
    env_name: str = ""
    ips: list[str] = field(default_factory=lambda: cast(list[str], []))


@dataclass
class PostBuildEvent(EmpusaEvent):
    """Fired *after* an environment build completes."""

    event: str = "post_build"
    env_name: str = ""
    env_path: str = ""
    ips: list[str] = field(default_factory=lambda: cast(list[str], []))


# -- Scanning -------------------------------------------------------


@dataclass
class PreScanHostEvent(EmpusaEvent):
    """Fired *before* scanning an individual host."""

    event: str = "pre_scan_host"
    ip: str = ""
    env_name: str = ""


@dataclass
class PostScanEvent(EmpusaEvent):
    """Fired *after* an individual host scan completes."""

    event: str = "post_scan"
    ip: str = ""
    scan_output: str = ""
    os_type: str = ""
    ports_dir: str = ""


# -- Loot -----------------------------------------------------------


@dataclass
class LootAddedEvent(EmpusaEvent):
    """Fired when a loot entry is saved."""

    event: str = "on_loot_add"
    host: str = ""
    cred_type: str = ""
    username: str = ""
    secret: str = ""
    source: str = ""
    env_name: str = ""
    env_path: str = ""


# -- Reporting ------------------------------------------------------


@dataclass
class PreReportWriteEvent(EmpusaEvent):
    """Fired *before* the report file is written."""

    event: str = "pre_report_write"
    env_name: str = ""
    env_path: str = ""
    standalone_count: int = 0
    ad_count: int = 0


@dataclass
class ReportGeneratedEvent(EmpusaEvent):
    """Fired *after* a report has been written to disk."""

    event: str = "on_report_generated"
    report_path: str = ""
    env_name: str = ""
    env_path: str = ""
    standalone_count: int = 0
    ad_count: int = 0


# -- Module Workshop ------------------------------------------------


@dataclass
class PostCompileEvent(EmpusaEvent):
    """Fired after a module compiles successfully."""

    event: str = "post_compile"
    module_name: str = ""
    language: str = ""
    output_path: str = ""
    build_dir: str = ""
    source: str = ""


# -- Command Execution (granular) -----------------------------------


@dataclass
class PreCommandEvent(EmpusaEvent):
    """Fired *before* a subprocess command executes."""

    event: str = "pre_command"
    command: str = ""
    args: list[str] = field(default_factory=lambda: cast(list[str], []))
    working_dir: str = ""


@dataclass
class PostCommandEvent(EmpusaEvent):
    """Fired *after* a subprocess command completes."""

    event: str = "post_command"
    command: str = ""
    args: list[str] = field(default_factory=lambda: cast(list[str], []))
    return_code: int = 0
    stdout: str = ""
    stderr: str = ""


# -- Test Fire ------------------------------------------------------


@dataclass
class TestFireEvent(EmpusaEvent):
    """Synthetic event used by the hook manager's test-fire feature."""

    __test__ = False  # prevent pytest from collecting this dataclass

    event: str = "test_fire"
    _test_fire: bool = True
    ip: str = "10.10.10.10"
    host: str = "10.10.10.10"
    env_name: str = ""
    env_path: str = ""
    username: str = "test_user"
    secret: str = "test_secret"
    cred_type: str = "plaintext"
    source: str = "test"


# -- Registry of event name -> dataclass -----------------------------

EVENT_MAP: dict[str, type] = {
    "on_startup": StartupEvent,
    "on_shutdown": ShutdownEvent,
    "on_env_select": EnvSelectEvent,
    "pre_build": PreBuildEvent,
    "post_build": PostBuildEvent,
    "pre_scan_host": PreScanHostEvent,
    "post_scan": PostScanEvent,
    "on_loot_add": LootAddedEvent,
    "pre_report_write": PreReportWriteEvent,
    "on_report_generated": ReportGeneratedEvent,
    "post_compile": PostCompileEvent,
    "pre_command": PreCommandEvent,
    "post_command": PostCommandEvent,
    "test_fire": TestFireEvent,
}

# All known event names (superset of the original HOOK_EVENTS)
ALL_EVENTS: list[str] = list(EVENT_MAP.keys())
