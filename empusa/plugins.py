"""
Empusa - Plugin Manager (Layer 3)

Handles the full plugin lifecycle:

- **Discovery** - scans ``empusa/plugins/<name>/`` for ``manifest.json``
- **Validation** - checks required fields, permissions, dependencies
- **Loading** - imports ``plugin.py`` and calls ``activate(services, registry, bus)``
- **Config** - per-plugin ``config.json`` with defaults + user overrides
- **Enable / Disable** - toggled via manifest ``enabled`` field
- **Dependency resolution** - topological sort, missing-dep warnings
- **Uninstall** - removes capabilities, deactivates, deletes directory

Directory layout for a plugin::

    empusa/plugins/
    -> loot_slack_notifier/
        - manifest.json
        - config.json      (optional - user overrides)
        - plugin.py        (must define activate / deactivate)
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, cast

if TYPE_CHECKING:
    from empusa.bus import EventBus
    from empusa.events import EmpusaEvent
    from empusa.registry import CapabilityRegistry
    from empusa.services import Services


# No-op fallback for optional log callables
def _noop(*_args: Any, **_kwargs: Any) -> None:
    pass


# -- Manifest schema -------------------------------------------------

REQUIRED_MANIFEST_FIELDS = ("name", "version", "description", "events")

DEFAULT_MANIFEST: dict[str, Any] = {
    "name": "",
    "version": "0.1.0",
    "author": "",
    "description": "",
    "events": [],
    "requires": [],
    "permissions": [],
    "enabled": True,
}

VALID_PERMISSIONS = frozenset(
    {
        "network",  # outbound HTTP/socket access
        "filesystem",  # read/write outside the env dir
        "subprocess",  # spawn child processes
        "loot_read",  # read loot entries
        "loot_write",  # append loot entries
        "registry",  # register capabilities
    }
)


# -- Plugin descriptor ----------------------------------------------


class PluginDescriptor:
    """In-memory representation of a discovered plugin."""

    __slots__ = (
        "name",
        "version",
        "author",
        "description",
        "events",
        "requires",
        "permissions",
        "enabled",
        "path",
        "manifest_path",
        "config_path",
        "config",
        "module",
        "activated",
        "activatable",
    )

    def __init__(self, manifest: dict[str, Any], plugin_dir: Path) -> None:
        self.name: str = manifest.get("name", plugin_dir.name)
        self.version: str = manifest.get("version", "0.1.0")
        self.author: str = manifest.get("author", "")
        self.description: str = manifest.get("description", "")
        self.events: list[str] = manifest.get("events", [])
        self.requires: list[str] = manifest.get("requires", [])
        self.permissions: list[str] = manifest.get("permissions", [])
        self.enabled: bool = manifest.get("enabled", True)

        self.path: Path = plugin_dir
        self.manifest_path: Path = plugin_dir / "manifest.json"
        self.config_path: Path = plugin_dir / "config.json"
        self.config: dict[str, Any] = {}
        self.module: Any = None
        self.activated: bool = False
        self.activatable: bool = True  # set False by resolve_dependencies / permission check

    def __repr__(self) -> str:
        if self.activated:
            status = "active"
        elif not self.activatable:
            status = "blocked"
        elif self.enabled:
            status = "enabled"
        else:
            status = "disabled"
        return f"<Plugin {self.name!r} v{self.version} [{status}]>"


# -- Plugin Manager --------------------------------------------------


class PluginManager:
    """Discovers, loads, and manages the lifecycle of plugins.

    Typical usage::

        pm = PluginManager(plugins_dir, services, registry, bus)
        pm.discover()
        pm.resolve_dependencies()
        pm.activate_all()
    """

    def __init__(
        self,
        plugins_dir: Path,
        services: Services | None = None,
        registry: CapabilityRegistry | None = None,
        bus: EventBus | None = None,
        log_verbose: Callable[..., None] | None = None,
        log_error: Callable[..., None] | None = None,
        log_info: Callable[..., None] | None = None,
        log_success: Callable[..., None] | None = None,
    ) -> None:
        self._dir = plugins_dir
        self._services = services
        self._registry = registry
        self._bus = bus
        self._log_verbose = log_verbose or _noop
        self._log_error = log_error or _noop
        self._log_info = log_info or _noop
        self._log_success = log_success or _noop

        self._plugins: dict[str, PluginDescriptor] = {}

    # -- Directory init ----------------------------------------------

    def init_dirs(self) -> None:
        """Create the plugins directory and a README if missing."""
        self._dir.mkdir(parents=True, exist_ok=True)
        readme = self._dir / "README.md"
        if not readme.exists():
            readme.write_text(
                "# Empusa Plugins\n\n"
                "Each subdirectory is a plugin.  Minimum structure:\n\n"
                "```\n"
                "my_plugin/\n"
                "├-- manifest.json   (required)\n"
                "├-- config.json     (optional)\n"
                "└-- plugin.py       (required - defines activate/deactivate)\n"
                "```\n\n"
                "## manifest.json\n\n"
                "```json\n"
                "{\n"
                '  "name": "my_plugin",\n'
                '  "version": "1.0.0",\n'
                '  "author": "Your Name",\n'
                '  "description": "What this plugin does",\n'
                '  "events": ["post_scan", "on_loot_add"],\n'
                '  "requires": [],\n'
                '  "permissions": ["loot_read"],\n'
                '  "enabled": true\n'
                "}\n"
                "```\n\n"
                "## plugin.py\n\n"
                "```python\n"
                "def activate(services, registry, bus):\n"
                '    """Called when the plugin is loaded."""\n'
                "    services.logger.info('My plugin activated!')\n\n"
                "def deactivate():\n"
                '    """Called on shutdown or disable."""\n'
                "    pass\n\n"
                "def on_event(event):\n"
                '    """Called for each subscribed event."""\n'
                "    pass\n"
                "```\n",
                encoding="utf-8",
            )

    # -- Discovery ---------------------------------------------------

    def discover(self) -> list[PluginDescriptor]:
        """Scan the plugins directory for valid plugins.

        Returns the list of discovered descriptors (enabled + disabled).
        """
        self._plugins.clear()

        if not self._dir.is_dir():
            return []

        for child in sorted(self._dir.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            manifest_path = child / "manifest.json"
            if not manifest_path.exists():
                self._log_verbose(f"Skipping {child.name}/ - no manifest.json", "yellow")
                continue

            try:
                raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                self._log_error(f"Plugin {child.name}: bad manifest - {exc}")
                continue

            # Validate required fields
            missing = [f for f in REQUIRED_MANIFEST_FIELDS if f not in raw]
            if missing:
                self._log_error(f"Plugin {child.name}: manifest missing {', '.join(missing)}")
                continue

            desc = PluginDescriptor(raw, child)

            # Validate permissions
            bad_perms = [p for p in desc.permissions if p not in VALID_PERMISSIONS]
            if bad_perms:
                self._log_error(
                    f"Plugin {child.name}: unknown permissions: {', '.join(bad_perms)}. "
                    f"Valid: {', '.join(sorted(VALID_PERMISSIONS))}"
                )
                desc.activatable = False

            # Load config.json if present
            if desc.config_path.exists():
                try:
                    desc.config = json.loads(desc.config_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    desc.config = {}

            self._plugins[desc.name] = desc

        return list(self._plugins.values())

    # -- Dependency resolution ---------------------------------------

    def resolve_dependencies(self) -> list[str]:
        """Validate plugin dependencies and permissions.

        - Plugins with missing dependencies are marked non-activatable.
        - Dependency cycles are detected and reported as hard errors.
        - Transitive failures propagate: if A depends on B and B is
          non-activatable, A is also marked non-activatable.

        Returns a list of warning/error strings.
        """
        known_names = set(self._plugins.keys())
        warnings: list[str] = []

        # 1. Check for missing dependencies
        for desc in self._plugins.values():
            for dep in desc.requires:
                if dep not in known_names:
                    msg = f"Plugin {desc.name!r} requires {dep!r} which is not installed"
                    warnings.append(msg)
                    self._log_error(msg)
                    desc.activatable = False

        # 2. Detect cycles (DFS with temp/perm marks)
        #    UNMARKED = not in either set
        #    TEMP     = in temp_marks  (currently being visited)
        #    PERM     = in perm_marks  (fully processed)
        temp_marks: set[str] = set()
        perm_marks: set[str] = set()
        cycle_members: set[str] = set()

        def _visit_cycle(name: str) -> None:
            if name in perm_marks:
                return
            if name in temp_marks:
                cycle_members.add(name)
                return
            desc = self._plugins.get(name)
            if desc is None:
                return
            temp_marks.add(name)
            for dep in desc.requires:
                _visit_cycle(dep)
                if dep in cycle_members:
                    cycle_members.add(name)
            temp_marks.discard(name)
            perm_marks.add(name)

        for plugin_name in self._plugins:
            _visit_cycle(plugin_name)

        for name in cycle_members:
            desc = self._plugins.get(name)
            if desc is not None:
                desc.activatable = False
            msg = f"Plugin {name!r} is part of a dependency cycle - disabled"
            warnings.append(msg)
            self._log_error(msg)

        # 3. Propagate: if a dependency is non-activatable, so is the dependent
        changed = True
        while changed:
            changed = False
            for desc in self._plugins.values():
                if not desc.activatable:
                    continue
                for dep_name in desc.requires:
                    dep_desc = self._plugins.get(dep_name)
                    if dep_desc is not None and not dep_desc.activatable:
                        desc.activatable = False
                        msg = f"Plugin {desc.name!r} disabled - dependency {dep_name!r} is non-activatable"
                        warnings.append(msg)
                        self._log_error(msg)
                        changed = True
                        break

        return warnings

    def _topological_order(self) -> list[PluginDescriptor]:
        """Return activatable plugins sorted so dependencies come first.

        Uses temp/perm marks so cycles (already caught by
        ``resolve_dependencies``) are silently skipped rather than
        causing infinite recursion.
        """
        perm: set[str] = set()
        temp: set[str] = set()
        order: list[PluginDescriptor] = []

        def visit(name: str) -> None:
            if name in perm or name in temp:
                return
            desc = self._plugins.get(name)
            if desc is None:
                return
            temp.add(name)
            for dep in desc.requires:
                visit(dep)
            temp.discard(name)
            perm.add(name)
            order.append(desc)

        for name in self._plugins:
            visit(name)
        return order

    # -- Activation / Deactivation -----------------------------------

    def activate_all(self) -> int:
        """Activate all enabled, activatable plugins in dependency order.

        Returns the count of successfully activated plugins.
        """
        count = 0
        for desc in self._topological_order():
            if not desc.enabled:
                self._log_verbose(f"Plugin {desc.name!r} is disabled - skipping", "yellow")
                continue
            if not desc.activatable:
                self._log_verbose(
                    f"Plugin {desc.name!r} is non-activatable (unmet deps, cycle, or bad permissions) - skipping",
                    "yellow",
                )
                continue
            if self._activate_one(desc):
                count += 1
        return count

    def _activate_one(self, desc: PluginDescriptor) -> bool:
        """Load ``plugin.py`` and call ``activate(services, registry, bus)``.

        The plugin receives a ``ScopedServices`` wrapper that enforces
        its declared permissions at runtime.
        """
        plugin_py = desc.path / "plugin.py"
        if not plugin_py.exists():
            self._log_error(f"Plugin {desc.name}: missing plugin.py")
            return False

        try:
            spec = importlib.util.spec_from_file_location(
                f"empusa_plugin_{desc.name}",
                plugin_py,
            )
            if spec is None or spec.loader is None:
                self._log_error(f"Plugin {desc.name}: could not create import spec")
                return False

            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            desc.module = mod

            # Build permission-scoped services for this plugin
            scoped_svc: Any
            if self._services is not None:
                from empusa.services import ScopedServices as _ScopedSvc

                scoped_svc = _ScopedSvc(self._services, desc.permissions, desc.name)
            else:
                scoped_svc = None

            # Call activate
            if hasattr(mod, "activate") and callable(mod.activate):
                mod.activate(scoped_svc, self._registry, self._bus)

            desc.activated = True
            self._log_verbose(f"Activated plugin: {desc.name} v{desc.version}", "green")
            return True

        except Exception as exc:
            self._log_error(f"Plugin {desc.name} activation failed: {exc}")
            return False

    def deactivate_all(self) -> int:
        """Deactivate all active plugins (reverse order). Returns count."""
        count = 0
        for desc in reversed(self._topological_order()):
            if desc.activated:
                self._deactivate_one(desc)
                count += 1
        return count

    def _deactivate_one(self, desc: PluginDescriptor) -> None:
        """Call ``deactivate()`` on the plugin module if present."""
        if desc.module and hasattr(desc.module, "deactivate") and callable(desc.module.deactivate):
            try:
                desc.module.deactivate()
            except Exception as exc:
                self._log_error(f"Plugin {desc.name} deactivate error: {exc}")
        desc.activated = False
        # Remove capabilities registered by this plugin
        if self._registry:
            self._registry.unregister_plugin(desc.name)

    # -- Safe refresh ------------------------------------------------

    def refresh(self) -> list[str]:
        """Full lifecycle refresh: deactivate -> discover -> resolve -> activate.

        This is the **safe** way to re-sync in-memory plugin state after
        any on-disk change (create, uninstall, manifest edit, config
        change).  UI code should call this instead of bare ``discover()``.

        Returns dependency-resolution warnings (same as
        ``resolve_dependencies()``).
        """
        self.deactivate_all()
        self.discover()
        warnings = self.resolve_dependencies()
        self.activate_all()
        return warnings

    def reload_plugin(self, name: str) -> list[str]:
        """Reload a single plugin by name (full lifecycle refresh).

        Convenience wrapper that still performs a full refresh because
        dependency graphs may have changed.  Returns warnings.
        """
        return self.refresh()

    # -- Event dispatch (called by bus) ------------------------------

    def dispatch_event(self, event_name: str, event: EmpusaEvent) -> list[dict[str, Any]]:
        """Route *event* to every active plugin subscribed to *event_name*.

        Returns structured result dicts from plugins that return values.
        """
        results: list[dict[str, Any]] = []
        for desc in self._plugins.values():
            if not desc.activated:
                continue
            if event_name not in desc.events:
                continue
            mod = desc.module
            if mod is None:
                continue

            handler_name = "on_event"
            # Check for event-specific handler first: on_post_scan, on_loot_add, etc.
            specific = f"on_{event_name}"
            if hasattr(mod, specific) and callable(getattr(mod, specific)):
                handler_name = specific

            handler = getattr(mod, handler_name, None)
            if handler is None or not callable(handler):
                continue

            try:
                raw_result = handler(event)
                if isinstance(raw_result, dict):
                    typed_result: dict[str, Any] = cast(dict[str, Any], raw_result)
                    typed_result.setdefault("plugin", desc.name)
                    results.append(typed_result)
            except Exception as exc:
                self._log_error(f"Plugin {desc.name} event handler error [{event_name}]: {exc}")

        return results

    # -- Enable / Disable --------------------------------------------

    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin and persist the change to manifest.json."""
        desc = self._plugins.get(name)
        if desc is None:
            return False
        if not desc.activatable:
            self._log_error(f"Cannot enable {name!r} - non-activatable (unmet deps, cycle, or bad permissions)")
            return False
        desc.enabled = True
        self._update_manifest_field(desc, "enabled", True)
        # Activate if not already
        if not desc.activated:
            self._activate_one(desc)
        return True

    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin and persist the change."""
        desc = self._plugins.get(name)
        if desc is None:
            return False
        if desc.activated:
            self._deactivate_one(desc)
        desc.enabled = False
        self._update_manifest_field(desc, "enabled", False)
        return True

    def _update_manifest_field(self, desc: PluginDescriptor, key: str, value: Any) -> None:
        """Update a single field in the plugin's manifest.json."""
        try:
            raw = json.loads(desc.manifest_path.read_text(encoding="utf-8"))
            raw[key] = value
            desc.manifest_path.write_text(
                json.dumps(raw, indent=2) + "\n",
                encoding="utf-8",
            )
        except (json.JSONDecodeError, OSError) as exc:
            self._log_error(f"Could not update manifest for {desc.name}: {exc}")

    # -- Config management -------------------------------------------

    def get_plugin_config(self, name: str) -> dict[str, Any]:
        """Return the merged config for plugin *name*."""
        desc = self._plugins.get(name)
        if desc is None:
            return {}
        return dict(desc.config)

    def set_plugin_config(self, name: str, key: str, value: Any) -> bool:
        """Set a config key and persist to config.json."""
        desc = self._plugins.get(name)
        if desc is None:
            return False
        desc.config[key] = value
        try:
            desc.config_path.write_text(
                json.dumps(desc.config, indent=2) + "\n",
                encoding="utf-8",
            )
            return True
        except OSError as exc:
            self._log_error(f"Could not write config for {desc.name}: {exc}")
            return False

    # -- Scaffold a new plugin ---------------------------------------

    def create_plugin_scaffold(
        self,
        name: str,
        description: str = "",
        events: list[str] | None = None,
        permissions: list[str] | None = None,
        author: str = "",
    ) -> Path:
        """Create a new plugin directory with boilerplate files.

        Returns the path to the new plugin directory.
        """
        plugin_dir = self._dir / name
        plugin_dir.mkdir(parents=True, exist_ok=True)

        manifest: dict[str, Any] = {
            "name": name,
            "version": "0.1.0",
            "author": author,
            "description": description or f"Empusa plugin: {name}",
            "events": events or [],
            "requires": [],
            "permissions": permissions or [],
            "enabled": True,
        }
        (plugin_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n",
            encoding="utf-8",
        )

        # Default config
        (plugin_dir / "config.json").write_text(
            json.dumps({"enabled": True}, indent=2) + "\n",
            encoding="utf-8",
        )

        # Plugin module
        events_str = ", ".join(events or [])
        (plugin_dir / "plugin.py").write_text(
            f'"""\nEmpusa Plugin - {name}\n\n'
            f"{description or 'TODO: describe this plugin'}\n"
            f'Subscribed events: {events_str or "none"}\n"""\n\n'
            f"from typing import Any, Optional, Dict\n\n\n"
            f"def activate(services: Any, registry: Any, bus: Any) -> None:\n"
            f'    """Called when the plugin is loaded by Empusa."""\n'
            f'    services.logger.info("[Plugin] {name} activated")\n\n\n'
            f"def deactivate() -> None:\n"
            f'    """Called on shutdown or when the plugin is disabled."""\n'
            f"    pass\n\n\n"
            f"def on_event(event: Any) -> Optional[Dict[str, Any]]:\n"
            f'    """Handle a subscribed event.\n\n'
            f"    Return a dict with structured results, or None.\n"
            f'    """\n'
            f"    # event is a typed EmpusaEvent dataclass\n"
            f"    # Access fields like: event.host, event.ip, event.username\n"
            f"    return None\n",
            encoding="utf-8",
        )

        return plugin_dir

    # -- Uninstall ---------------------------------------------------

    def uninstall_plugin(self, name: str) -> bool:
        """Deactivate and remove a plugin directory entirely."""
        desc = self._plugins.get(name)
        if desc is None:
            return False

        if desc.activated:
            self._deactivate_one(desc)

        import shutil as _shutil

        try:
            _shutil.rmtree(desc.path)
        except OSError as exc:
            self._log_error(f"Could not remove {desc.path}: {exc}")
            return False

        del self._plugins[name]
        return True

    # -- Introspection -----------------------------------------------

    @property
    def plugins(self) -> dict[str, PluginDescriptor]:
        """All discovered plugins (enabled and disabled)."""
        return dict(self._plugins)

    @property
    def active_plugins(self) -> list[PluginDescriptor]:
        """Only currently activated plugins."""
        return [d for d in self._plugins.values() if d.activated]

    def plugin_count(self) -> int:
        return len(self._plugins)

    def active_count(self) -> int:
        return len(self.active_plugins)
