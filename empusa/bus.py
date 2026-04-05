"""
Empusa - Event Bus (Layer 1 + 2)

The bus is the central nervous system of the plugin framework:

- **Layer 1 - Event emission**: Core code calls ``bus.emit(event)`` with
  a typed ``EmpusaEvent`` dataclass (or an event-name string + dict fo
  backward compatibility).
- **Layer 2 - Hook adapter**: Legacy ``run(context)`` scripts in
  ``empusa/hooks/<event>/`` are discovered and invoked automatically,
  receiving the event payload as a plain dict.
- **Layer 3 bridge**: If a ``PluginManager`` is attached the bus also
  routes events to every enabled plugin that subscribes to that event.

Usage::

    from empusa.bus import EventBus
    bus = EventBus(hooks_dir=Path("empusa/hooks"))

    # Typed emission (preferred)
    bus.emit(PostScanEvent(ip="10.10.10.5", os_type="Linux"))

    # Legacy string emission (backward compatible)
    bus.emit_legacy("post_scan", {"ip": "10.10.10.5", "os_type": "Linux"})
"""

from __future__ import annotations

import importlib.util
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from empusa.events import EVENT_MAP, EmpusaEvent, make_event

if TYPE_CHECKING:
    from empusa.plugins import PluginManager


# Type alias for a bus subscriber callback
Subscriber = Callable[[EmpusaEvent], None]


# No-op fallback for optional log callables
def _noop(*_args: Any, **_kwargs: Any) -> None:
    pass


class EventBus:
    """Central event bus for the Empusa framework.

    Supports three listener categories:

    1. **Legacy hooks** - ``run(context: dict)`` scripts in the hooks di
    2. **Native subscribers** - callables registered via ``.subscribe()``
    3. **Plugins** - routed through an attached ``PluginManager``
    """

    def __init__(
        self,
        hooks_dir: Path,
        verbose: bool = False,
        quiet: bool = False,
        log_verbose: Callable[..., None] | None = None,
        log_error: Callable[..., None] | None = None,
        session_env_fn: Callable[[], str] | None = None,
    ) -> None:
        self._hooks_dir = hooks_dir
        self._verbose = verbose
        self._quiet = quiet
        self._log_verbose = log_verbose or _noop
        self._log_error = log_error or _noop
        self._session_env_fn = session_env_fn or (lambda: "")

        # Native subscribers: event_name -> [callable, …]
        self._subscribers: dict[str, list[Subscriber]] = {}

        # Optional plugin manager (attached after init to avoid circular deps)
        self._plugin_manager: PluginManager | None = None

        # Collected return values from the last emission
        self._last_results: list[dict[str, Any]] = []

    # -- Plugin manager attachment -----------------------------------

    def attach_plugin_manager(self, pm: PluginManager) -> None:
        """Attach a PluginManager so events are routed to plugins."""
        self._plugin_manager = pm

    # -- Native subscriber API ---------------------------------------

    def subscribe(self, event: str, callback: Subscriber) -> None:
        """Register a native callback for *event*."""
        self._subscribers.setdefault(event, []).append(callback)

    def unsubscribe(self, event: str, callback: Subscriber) -> bool:
        """Remove a native callback.  Returns True if found."""
        subs = self._subscribers.get(event, [])
        try:
            subs.remove(callback)
            return True
        except ValueError:
            return False

    # -- Emission ----------------------------------------------------

    def emit(self, event: EmpusaEvent) -> list[dict[str, Any]]:
        """Emit a typed event to all listeners.

        1. Legacy hooks receive ``event.to_dict()``
        2. Native subscribers receive the dataclass instance
        3. Plugins receive the dataclass instance

        Returns a list of result dicts from plugins that return values.
        """
        # Ensure defaults
        if not event.timestamp:
            event.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if not event.session_env:
            event.session_env = self._session_env_fn()

        name = event.event
        results: list[dict[str, Any]] = []

        # Layer 2 - legacy hook adapte
        self._fire_legacy_hooks(name, event.to_dict())

        # Native subscribers
        for cb in self._subscribers.get(name, []):
            try:
                cb(event)
            except Exception as exc:
                self._log_error(f"Subscriber error [{name}]: {exc}")

        # Layer 3 - plugin routing
        if self._plugin_manager is not None:
            plugin_results = self._plugin_manager.dispatch_event(name, event)
            results.extend(plugin_results)

        self._last_results = results
        return results

    def emit_legacy(self, event_name: str, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Emit using a plain event-name string + dict (backward-compat).

        Constructs the appropriate typed event via :func:`make_event`,
        then delegates to :meth:`emit`.
        """
        ctx = context.copy() if context else {}
        ctx.setdefault("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        ctx.setdefault("session_env", self._session_env_fn())

        event_obj = make_event(event_name, **ctx)
        return self.emit(event_obj)

    # -- Last results accessor ---------------------------------------

    @property
    def last_results(self) -> list[dict[str, Any]]:
        """Return results from the most recent ``emit()`` call."""
        return list(self._last_results)

    # -- Legacy hook adapter (Layer 2) -------------------------------

    def _fire_legacy_hooks(self, event_name: str, context: dict[str, Any]) -> None:
        """Discover and execute ``run(context)`` scripts in hooks/<event>/."""
        evt_dir = self._hooks_dir / event_name
        if not evt_dir.is_dir():
            return

        scripts = sorted(p for p in evt_dir.iterdir() if p.suffix == ".py" and p.is_file())
        for script in scripts:
            try:
                spec = importlib.util.spec_from_file_location(
                    f"empusa_hook_{event_name}_{script.stem}",
                    script,
                )
                if spec is None or spec.loader is None:
                    self._log_verbose(f"Warning: Could not load hook {script.name}", "yellow")
                    continue
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)  # type: ignore[union-attr]
                if hasattr(mod, "run") and callable(mod.run):
                    self._log_verbose(f"Running hook: {event_name}/{script.name}", "cyan")
                    mod.run(context)
                else:
                    self._log_verbose(
                        f"Warning: {script.name} has no run(context) function - skipped",
                        "yellow",
                    )
            except Exception as exc:
                self._log_error(f"Hook error [{event_name}/{script.name}]: {exc}")

    # -- Introspection -----------------------------------------------

    def list_legacy_hooks(self) -> dict[str, list[str]]:
        """Return a dict of event -> list of hook script filenames."""
        result: dict[str, list[str]] = {}
        for evt_name in EVENT_MAP:
            evt_dir = self._hooks_dir / evt_name
            if evt_dir.is_dir():
                scripts = sorted(p.name for p in evt_dir.iterdir() if p.suffix == ".py" and p.is_file())
                result[evt_name] = scripts
            else:
                result[evt_name] = []
        return result

    def subscriber_count(self, event: str) -> int:
        """Number of native subscribers for *event*."""
        return len(self._subscribers.get(event, []))
