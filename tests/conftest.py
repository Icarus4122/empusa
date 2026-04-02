"""
Shared pytest fixtures for the Empusa test suite.

Provides temporary directory helpers, pre-built ``Services`` containers,
minimal ``PluginManager`` instances, and a quiet ``Console`` so tests
never produce visible terminal output.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
from rich.console import Console

from empusa.registry import CapabilityRegistry
from empusa.bus import EventBus
from empusa.services import (
    ArtifactWriter,
    CommandRunner,
    EnvResolver,
    LoggerService,
    LootAccessor,
    Services,
)


# -- Console ---------------------------------------------------------

@pytest.fixture()
def quiet_console() -> Console:
    """A Rich console that produces no output."""
    return Console(quiet=True)


# -- Temporary directories ------------------------------------------

@pytest.fixture()
def tmp_path_factory_custom(tmp_path: Path) -> Path:
    """Alias for the built-in tmp_path with a shorter name."""
    return tmp_path


@pytest.fixture()
def plugins_dir(tmp_path: Path) -> Path:
    d = tmp_path / "plugins"
    d.mkdir()
    return d


@pytest.fixture()
def hooks_dir(tmp_path: Path) -> Path:
    d = tmp_path / "hooks"
    d.mkdir()
    return d


@pytest.fixture()
def env_dir(tmp_path: Path) -> Path:
    """An environment directory pre-created in *tmp_path*."""
    d = tmp_path / "test_env"
    d.mkdir()
    return d


# -- Services --------------------------------------------------------

@pytest.fixture()
def make_services(tmp_path: Path, quiet_console: Console):
    """Factory fixture: call with an optional env path to get a Services container."""

    def _factory(env_path: Path | None = None) -> Services:
        env = env_path or tmp_path
        config: Dict[str, Any] = {"session_env": str(env)}
        logger = LoggerService(quiet_console, verbose=False, quiet=True)
        env_resolver = EnvResolver(config)
        artifact = ArtifactWriter(env_resolver)
        loot = LootAccessor(env_resolver)
        runner = CommandRunner(logger, dry_run=True)
        return Services(
            logger=logger,
            artifact=artifact,
            loot=loot,
            env=env_resolver,
            runner=runner,
        )

    return _factory


# -- Plugin helpers --------------------------------------------------

def write_plugin(
    plugins_dir: Path,
    name: str,
    *,
    events: List[str] | None = None,
    requires: List[str] | None = None,
    permissions: List[str] | None = None,
    enabled: bool = True,
    plugin_py: str | None = None,
) -> Path:
    """Create a minimal plugin directory with manifest.json + plugin.py."""
    d = plugins_dir / name
    d.mkdir(parents=True, exist_ok=True)
    manifest: Dict[str, Any] = {
        "name": name,
        "version": "0.1.0",
        "description": f"test plugin {name}",
        "events": events or [],
        "requires": requires or [],
        "permissions": permissions or [],
        "enabled": enabled,
    }
    (d / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    code = plugin_py or (
        "def activate(s, r, b): pass\n"
        "def deactivate(): pass\n"
    )
    (d / "plugin.py").write_text(code, encoding="utf-8")
    return d


@pytest.fixture()
def registry() -> CapabilityRegistry:
    """A fresh, empty CapabilityRegistry."""
    return CapabilityRegistry()


@pytest.fixture()
def event_bus(hooks_dir: Path) -> EventBus:
    """An EventBus pointed at the temporary hooks dir."""
    return EventBus(
        hooks_dir=hooks_dir,
        verbose=False,
        quiet=True,
    )
