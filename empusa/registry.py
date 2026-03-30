"""
Empusa - Capability Registry

Plugins register capabilities here so the framework can discover and
compose them at runtime.  Six capability types are supported:

- **analyzer**       - enriches scan/service data
- **notifier**       - fires alerts (Slack, Discord, webhook, …)
- **report_section** - injects a section into generated reports
- **exporter**       - outputs data in a custom format
- **tunnel_template**- adds a new tunneling method
- **recon_strategy** - provides additional recon workflows

The registry is a singleton-import and use ``registry`` directly.
"""

from typing import Any, Callable, Dict, List, Optional, Tuple


# Type alias for a capability handler - any callable.
Handler = Callable[..., Any]


class _CapabilityEntry:
    """Internal wrapper for a registered capability."""

    __slots__ = ("name", "handler", "plugin_name", "description", "meta")

    def __init__(
        self,
        name: str,
        handler: Handler,
        plugin_name: str = "",
        description: str = "",
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.name = name
        self.handler = handler
        self.plugin_name = plugin_name
        self.description = description
        self.meta = meta or {}

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Capability {self.name!r} from {self.plugin_name!r}>"


class CapabilityRegistry:
    """Central registry where plugins advertise their capabilities.

    Usage::

        from empusa.registry import registry

        registry.register_analyzer("http_headers", analyze_headers, plugin_name="my_plugin")
        registry.register_notifier("slack", send_slack_alert, plugin_name="slack_notifier")

        # Framework queries:
        for entry in registry.get_analyzers():
            entry.handler(service_data)
    """

    # The six capability categories
    CATEGORIES: Tuple[str, ...] = (
        "analyzer",
        "notifier",
        "report_section",
        "exporter",
        "tunnel_template",
        "recon_strategy",
    )

    def __init__(self) -> None:
        self._store: Dict[str, List[_CapabilityEntry]] = {cat: [] for cat in self.CATEGORIES}

    # -- Generic register / get --------------------------------------

    def register(
        self,
        category: str,
        name: str,
        handler: Handler,
        plugin_name: str = "",
        description: str = "",
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Register a capability under *category*.

        Raises ``ValueError`` if *category* is unknown.
        """
        if category not in self._store:
            raise ValueError(
                f"Unknown capability category {category!r}.  "
                f"Valid: {', '.join(self.CATEGORIES)}"
            )
        entry = _CapabilityEntry(
            name=name,
            handler=handler,
            plugin_name=plugin_name,
            description=description,
            meta=meta,
        )
        self._store[category].append(entry)

    def get(self, category: str) -> List[_CapabilityEntry]:
        """Return all entries for *category*."""
        return list(self._store.get(category, []))

    def get_by_name(self, category: str, name: str) -> Optional[_CapabilityEntry]:
        """Return a specific entry by category + name, or ``None``."""
        for entry in self._store.get(category, []):
            if entry.name == name:
                return entry
        return None

    def unregister(self, category: str, name: str, plugin_name: str = "") -> bool:
        """Remove a capability entry.  Returns ``True`` if removed."""
        entries = self._store.get(category, [])
        for i, entry in enumerate(entries):
            if entry.name == name and (not plugin_name or entry.plugin_name == plugin_name):
                entries.pop(i)
                return True
        return False

    def unregister_plugin(self, plugin_name: str) -> int:
        """Remove *all* capabilities registered by *plugin_name*.

        Returns the number of entries removed.
        """
        removed = 0
        for cat in self.CATEGORIES:
            before = len(self._store[cat])
            self._store[cat] = [e for e in self._store[cat] if e.plugin_name != plugin_name]
            removed += before - len(self._store[cat])
        return removed

    def clear(self) -> None:
        """Remove all registered capabilities."""
        for cat in self.CATEGORIES:
            self._store[cat].clear()

    # -- Convenience registration helpers ----------------------------

    def register_analyzer(
        self, name: str, handler: Handler, plugin_name: str = "", description: str = "", meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.register("analyzer", name, handler, plugin_name, description, meta)

    def register_notifier(
        self, name: str, handler: Handler, plugin_name: str = "", description: str = "", meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.register("notifier", name, handler, plugin_name, description, meta)

    def register_report_section(
        self, name: str, handler: Handler, plugin_name: str = "", description: str = "", meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.register("report_section", name, handler, plugin_name, description, meta)

    def register_exporter(
        self, name: str, handler: Handler, plugin_name: str = "", description: str = "", meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.register("exporter", name, handler, plugin_name, description, meta)

    def register_tunnel_template(
        self, name: str, handler: Handler, plugin_name: str = "", description: str = "", meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.register("tunnel_template", name, handler, plugin_name, description, meta)

    def register_recon_strategy(
        self, name: str, handler: Handler, plugin_name: str = "", description: str = "", meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.register("recon_strategy", name, handler, plugin_name, description, meta)

    # -- Convenience getters -----------------------------------------

    def get_analyzers(self) -> List[_CapabilityEntry]:
        return self.get("analyzer")

    def get_notifiers(self) -> List[_CapabilityEntry]:
        return self.get("notifier")

    def get_report_sections(self) -> List[_CapabilityEntry]:
        return self.get("report_section")

    def get_exporters(self) -> List[_CapabilityEntry]:
        return self.get("exporter")

    def get_tunnel_templates(self) -> List[_CapabilityEntry]:
        return self.get("tunnel_template")

    def get_recon_strategies(self) -> List[_CapabilityEntry]:
        return self.get("recon_strategy")

    # -- Introspection -----------------------------------------------

    def summary(self) -> Dict[str, int]:
        """Return a dict of category → count."""
        return {cat: len(entries) for cat, entries in self._store.items()}

    def all_entries(self) -> List[_CapabilityEntry]:
        """Flat list of every registered capability."""
        result: List[_CapabilityEntry] = []
        for entries in self._store.values():
            result.extend(entries)
        return result


# -- Module-level singleton ------------------------------------------

registry = CapabilityRegistry()
