"""
Empusa - Runtime Services (Layer 5)

Shared utilities exposed to plugins so they do not need to
re-implement core behaviour.  Plugins receive a ``Services`` instance
as part of their activation context.

Provided services:

- **logger**           - structured logging through Rich console
- **artifact_writer**  - safe file creation inside the active environment
- **loot_accessor**    - read / append loot entries (JSON-backed)
- **env_resolver**     - resolve environment paths and metadata
- **command_runner**    - execute subprocesses with event hooks
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, cast

from rich.console import Console

# -- Logger Service --------------------------------------------------


class LoggerService:
    """Structured logging through a Rich console.

    Plugins should use this instead of raw ``print()`` so output stays
    consistent with the rest of the framework.
    """

    def __init__(self, console: Console, verbose: bool = False, quiet: bool = False) -> None:
        self._console = console
        self._verbose = verbose
        self._quiet = quiet

    def info(self, message: str, style: str = "") -> None:
        if not self._quiet:
            if style:
                self._console.print(message, style=style)
            else:
                self._console.print(message)

    def verbose(self, message: str, style: str = "dim") -> None:
        if self._verbose and not self._quiet:
            self._console.print(message, style=style)

    def error(self, message: str) -> None:
        self._console.print(message, style="bold red")

    def success(self, message: str) -> None:
        if not self._quiet:
            self._console.print(message, style="bold green")

    def warn(self, message: str) -> None:
        if not self._quiet:
            self._console.print(message, style="bold yellow")


# -- Artifact Writer -------------------------------------------------


class ArtifactWriter:
    """Safe file creation scoped to the active environment directory.

    All writes are relative to the environment root to prevent plugins
    from accidentally writing to arbitrary filesystem locations.

    Paths are resolved and verified to stay within the environment
    boundary - traversal attempts (e.g. ``../../etc/passwd``) raise
    ``ValueError``.
    """

    def __init__(self, env_resolver: EnvResolver) -> None:
        self._env = env_resolver

    def _safe_target(self, relative_path: str) -> Path:
        """Resolve *relative_path* and verify it stays under the env root.

        Raises ``RuntimeError`` if no environment is active.
        Raises ``ValueError`` if the resolved path escapes the env root.
        """
        base = self._env.env_path()
        if base is None:
            raise RuntimeError("No active environment - cannot write artifact.")
        resolved_base = base.resolve()
        resolved_target = (base / relative_path).resolve()
        # os.path.commonpath would also work, but string-prefix on
        # resolved POSIX/NT paths is reliable after .resolve().
        try:
            resolved_target.relative_to(resolved_base)
        except ValueError as err:
            raise ValueError(
                f"Path escape denied: {relative_path!r} resolves outside the environment root ({resolved_base})"
            ) from err
        return resolved_target

    def write(self, relative_path: str, content: str, encoding: str = "utf-8") -> Path:
        """Write *content* to *relative_path* inside the active environment.

        Creates parent directories as needed. Returns the absolute path.

        Raises ``ValueError`` if the path escapes the environment root.
        """
        target = self._safe_target(relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding=encoding)
        return target

    def write_bytes(self, relative_path: str, data: bytes) -> Path:
        """Write raw bytes to *relative_path* inside the active environment.

        Raises ``ValueError`` if the path escapes the environment root.
        """
        target = self._safe_target(relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target

    def exists(self, relative_path: str) -> bool:
        """Check if *relative_path* exists inside the active environment.

        Returns ``False`` if the path would escape the env root.
        """
        base = self._env.env_path()
        if base is None:
            return False
        resolved_base = base.resolve()
        resolved_target = (base / relative_path).resolve()
        try:
            resolved_target.relative_to(resolved_base)
        except ValueError:
            return False
        return resolved_target.exists()


# -- Loot Accessor ---------------------------------------------------


class LootAccessor:
    """Read / append loot entries for the active environment.

    Loot is stored as ``loot.json`` at the environment root.
    """

    def __init__(self, env_resolver: EnvResolver) -> None:
        self._env = env_resolver

    def _loot_path(self) -> Path | None:
        base = self._env.env_path()
        if base is None:
            return None
        return base / "loot.json"

    def read_all(self) -> list[dict[str, Any]]:
        """Return all loot entries (empty list if none)."""
        path = self._loot_path()
        if path is None or not path.exists():
            return []
        try:
            raw = path.read_text(encoding="utf-8")
            parsed: Any = json.loads(raw)
            if isinstance(parsed, list):
                return cast(list[dict[str, Any]], parsed)
        except (json.JSONDecodeError, OSError):
            pass
        return []

    def append(self, entry: dict[str, Any]) -> None:
        """Append a single loot entry and flush to disk."""
        path = self._loot_path()
        if path is None:
            raise RuntimeError("No active environment - cannot write loot.")
        entries = self.read_all()
        entry.setdefault("added_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        entries.append(entry)
        path.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")

    def count(self) -> int:
        return len(self.read_all())

    def search(self, key: str, value: str) -> list[dict[str, Any]]:
        """Return entries where *key* contains *value* (case-insensitive)."""
        value_lower = value.lower()
        return [e for e in self.read_all() if value_lower in str(e.get(key, "")).lower()]


# -- Environment Resolver --------------------------------------------


class EnvResolver:
    """Resolves environment paths and metadata.

    Reads the ``session_env`` value from the global CONFIG dict
    (injected at init) to determine the active environment.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config

    def env_name(self) -> str:
        """Return the active environment name (may be empty)."""
        return str(self._config.get("session_env", ""))

    def env_path(self) -> Path | None:
        """Return the absolute path to the active environment, or ``None``."""
        name = self.env_name()
        if not name:
            return None
        p = Path(name)
        if p.is_absolute():
            return p
        return Path.cwd() / p

    def hosts(self) -> list[str]:
        """Return a list of host directory names inside the environment."""
        base = self.env_path()
        if base is None or not base.is_dir():
            return []
        return sorted(d.name for d in base.iterdir() if d.is_dir() and "-" in d.name and not d.name.startswith("."))

    def is_active(self) -> bool:
        return bool(self.env_name())


# -- Command Runner --------------------------------------------------


class CommandRunner:
    """Execute subprocesses with optional pre/post event hooks.

    If an ``emit_fn`` is provided it is called with PreCommandEvent /
    PostCommandEvent dataclass names before and after execution.
    The runner does NOT import events directly to avoid circular deps -
    it accepts a plain callable that the bus wires up.
    """

    def __init__(
        self,
        logger: LoggerService,
        dry_run: bool = False,
        emit_fn: Callable[..., None] | None = None,
    ) -> None:
        self._log = logger
        self._dry_run = dry_run
        self._emit = emit_fn

    def run(
        self,
        cmd: list[str] | str,
        cwd: str | None = None,
        timeout: int | None = None,
        capture: bool = True,
        shell: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        """Run *cmd* and return the ``CompletedProcess``.

        *cmd* may be a ``List[str]`` (default) or a plain ``str`` when
        *shell* is ``True`` (e.g. templated compiler invocations).

        In dry-run mode the command is logged but not executed.
        """
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            cmd_first = cmd[0] if cmd else ""
            cmd_rest: list[str] = cmd[1:] if cmd else []
        else:
            cmd_str = str(cmd)
            cmd_first = cmd_str.split()[0] if cmd_str.strip() else ""
            cmd_rest = []

        working_dir = cwd or str(Path.cwd())

        # Fire pre-command event
        if self._emit:
            self._emit("pre_command", {
                "command": cmd_first,
                "args": cmd_rest,
                "working_dir": working_dir,
            })

        if self._dry_run:
            self._log.info(f"[DRY-RUN] {cmd_str}", "dim")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self._log.verbose(f"$ {cmd_str}", "dim")

        try:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                timeout=timeout,
                capture_output=capture,
                text=True,
                shell=shell,
            )
        except FileNotFoundError:
            self._log.error(f"Command not found: {cmd_first}")
            result = subprocess.CompletedProcess(cmd, 127, stdout="", stderr=f"{cmd_first}: command not found")
        except subprocess.TimeoutExpired:
            self._log.error(f"Command timed out after {timeout}s: {cmd_str}")
            result = subprocess.CompletedProcess(cmd, 124, stdout="", stderr="timeout")

        # Fire post-command event
        if self._emit:
            self._emit("post_command", {
                "command": cmd_first,
                "args": cmd_rest,
                "return_code": result.returncode,
                "stdout": (result.stdout or "")[:2048],
                "stderr": (result.stderr or "")[:2048],
            })

        return result


# -- Service Container -----------------------------------------------


class Services:
    """Aggregates all runtime services into a single object that
    plugins receive during activation.

    Usage inside a plugin::

        def activate(services: Services) -> None:
            services.logger.info("Hello from my plugin!")
            loot = services.loot.read_all()
    """

    def __init__(
        self,
        logger: LoggerService,
        artifact: ArtifactWriter,
        loot: LootAccessor,
        env: EnvResolver,
        runner: CommandRunner,
    ) -> None:
        self.logger = logger
        self.artifact = artifact
        self.loot = loot
        self.env = env
        self.runner = runner


# -- Permission-scoped service wrappers ------------------------------


class PermissionError(RuntimeError):
    """Raised when a plugin lacks the required permission."""


class _GatedLoot:
    """Wraps LootAccessor with permission checks.

    ``loot_read``  gates ``read_all()``, ``count()``, ``search()``
    ``loot_write`` gates ``append()``
    """

    def __init__(self, loot: LootAccessor, perms: frozenset[str], plugin_name: str) -> None:
        self._loot = loot
        self._perms = perms
        self._name = plugin_name

    def _require(self, perm: str) -> None:
        if perm not in self._perms:
            raise PermissionError(f"Plugin {self._name!r} lacks '{perm}' permission")

    def read_all(self) -> list[dict[str, Any]]:
        self._require("loot_read")
        return self._loot.read_all()

    def append(self, entry: dict[str, Any]) -> None:
        self._require("loot_write")
        self._loot.append(entry)

    def count(self) -> int:
        self._require("loot_read")
        return self._loot.count()

    def search(self, key: str, value: str) -> list[dict[str, Any]]:
        self._require("loot_read")
        return self._loot.search(key, value)


class _GatedArtifact:
    """Wraps ArtifactWriter with ``filesystem`` permission check."""

    def __init__(self, artifact: ArtifactWriter, perms: frozenset[str], plugin_name: str) -> None:
        self._artifact = artifact
        self._perms = perms
        self._name = plugin_name

    def _require(self) -> None:
        if "filesystem" not in self._perms:
            raise PermissionError(f"Plugin {self._name!r} lacks 'filesystem' permission")

    def write(self, relative_path: str, content: str, encoding: str = "utf-8") -> Path:
        self._require()
        return self._artifact.write(relative_path, content, encoding)

    def write_bytes(self, relative_path: str, data: bytes) -> Path:
        self._require()
        return self._artifact.write_bytes(relative_path, data)

    def exists(self, relative_path: str) -> bool:
        # Read-only check - no permission needed
        return self._artifact.exists(relative_path)


class _GatedRunner:
    """Wraps CommandRunner with ``subprocess`` permission check."""

    def __init__(self, runner: CommandRunner, perms: frozenset[str], plugin_name: str) -> None:
        self._runner = runner
        self._perms = perms
        self._name = plugin_name

    def run(
        self,
        cmd: list[str] | str,
        cwd: str | None = None,
        timeout: int | None = None,
        capture: bool = True,
        shell: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        if "subprocess" not in self._perms:
            raise PermissionError(f"Plugin {self._name!r} lacks 'subprocess' permission")
        return self._runner.run(cmd, cwd=cwd, timeout=timeout, capture=capture, shell=shell)


class ScopedServices:
    """Permission-gated view of the runtime services for a single plugin.

    Each plugin receives a ``ScopedServices`` instance built from its
    manifest ``permissions`` list.  Accessing a service that requires a
    permission the plugin does not hold raises ``PermissionError``.

    Permission mapping:

    - ``loot_read``  -> ``loot.read_all()``, ``loot.count()``, ``loot.search()``
    - ``loot_write`` -> ``loot.append()``
    - ``filesystem`` -> ``artifact.write()``, ``artifact.write_bytes()``
    - ``subprocess`` -> ``runner.run()``
    - ``registry``   -> checked at activation time (not runtime)
    - ``network``    -> advisory only (Python cannot sandbox sockets)

    ``logger`` and ``env`` are always available with no permission
    requirement because they are read-only / output-only.
    """

    def __init__(self, base: Services, permissions: list[str], plugin_name: str) -> None:
        perms = frozenset(permissions)
        self.logger: LoggerService = base.logger
        self.env: EnvResolver = base.env
        self.loot: _GatedLoot = _GatedLoot(base.loot, perms, plugin_name)
        self.artifact: _GatedArtifact = _GatedArtifact(base.artifact, perms, plugin_name)
        self.runner: _GatedRunner = _GatedRunner(base.runner, perms, plugin_name)
