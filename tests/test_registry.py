"""
Tests for empusa.registry

Covers: register / get / get_by_name / unregister / unregister_plugin /
        clear / summary / all_entries / convenience helpers / unknown category.
"""

from __future__ import annotations

import pytest

from empusa.registry import CapabilityRegistry


def _handler() -> str:
    return "ok"


class TestRegisterAndGet:
    def test_register_and_get(self) -> None:
        reg = CapabilityRegistry()
        reg.register("analyzer", "test_cap", _handler, plugin_name="p1")
        entries = reg.get("analyzer")
        assert len(entries) == 1
        assert entries[0].name == "test_cap"
        assert entries[0].plugin_name == "p1"

    def test_get_returns_copy(self) -> None:
        reg = CapabilityRegistry()
        reg.register("notifier", "slack", _handler)
        lst = reg.get("notifier")
        lst.clear()  # mutating the returned list should not affect internal state
        assert len(reg.get("notifier")) == 1

    def test_get_empty_category(self) -> None:
        reg = CapabilityRegistry()
        assert reg.get("exporter") == []

    def test_get_unknown_category_returns_empty(self) -> None:
        reg = CapabilityRegistry()
        assert reg.get("does_not_exist") == []


class TestGetByName:
    def test_found(self) -> None:
        reg = CapabilityRegistry()
        reg.register("analyzer", "http", _handler, plugin_name="p")
        entry = reg.get_by_name("analyzer", "http")
        assert entry is not None
        assert entry.handler is _handler

    def test_not_found(self) -> None:
        reg = CapabilityRegistry()
        assert reg.get_by_name("analyzer", "missing") is None


class TestUnregister:
    def test_unregister_by_name(self) -> None:
        reg = CapabilityRegistry()
        reg.register("exporter", "csv", _handler, plugin_name="p1")
        assert reg.unregister("exporter", "csv") is True
        assert reg.get("exporter") == []

    def test_unregister_nonexistent(self) -> None:
        reg = CapabilityRegistry()
        assert reg.unregister("exporter", "nope") is False

    def test_unregister_plugin_removes_all(self) -> None:
        reg = CapabilityRegistry()
        reg.register("analyzer", "a1", _handler, plugin_name="p1")
        reg.register("notifier", "n1", _handler, plugin_name="p1")
        reg.register("analyzer", "a2", _handler, plugin_name="p2")
        removed = reg.unregister_plugin("p1")
        assert removed == 2
        assert len(reg.get("analyzer")) == 1
        assert reg.get("analyzer")[0].plugin_name == "p2"


class TestClear:
    def test_clear_empties_all(self) -> None:
        reg = CapabilityRegistry()
        reg.register("analyzer", "a", _handler)
        reg.register("notifier", "b", _handler)
        reg.clear()
        assert all(v == 0 for v in reg.summary().values())


class TestSummaryAndAllEntries:
    def test_summary_counts(self) -> None:
        reg = CapabilityRegistry()
        reg.register("analyzer", "a", _handler)
        reg.register("analyzer", "b", _handler)
        reg.register("notifier", "c", _handler)
        s = reg.summary()
        assert s["analyzer"] == 2
        assert s["notifier"] == 1
        assert s["exporter"] == 0

    def test_all_entries_flat(self) -> None:
        reg = CapabilityRegistry()
        reg.register("analyzer", "a", _handler)
        reg.register("exporter", "b", _handler)
        assert len(reg.all_entries()) == 2


class TestConvenienceHelpers:
    @pytest.mark.parametrize(
        "method,category",
        [
            ("register_analyzer", "analyzer"),
            ("register_notifier", "notifier"),
            ("register_report_section", "report_section"),
            ("register_exporter", "exporter"),
            ("register_tunnel_template", "tunnel_template"),
            ("register_recon_strategy", "recon_strategy"),
        ],
    )
    def test_register_convenience(self, method: str, category: str) -> None:
        reg = CapabilityRegistry()
        getattr(reg, method)("name", _handler, plugin_name="p")
        assert len(reg.get(category)) == 1

    @pytest.mark.parametrize(
        "method,category",
        [
            ("get_analyzers", "analyzer"),
            ("get_notifiers", "notifier"),
            ("get_report_sections", "report_section"),
            ("get_exporters", "exporter"),
            ("get_tunnel_templates", "tunnel_template"),
            ("get_recon_strategies", "recon_strategy"),
        ],
    )
    def test_get_convenience(self, method: str, category: str) -> None:
        reg = CapabilityRegistry()
        reg.register(category, "x", _handler)
        result = getattr(reg, method)()
        assert len(result) == 1


class TestUnknownCategory:
    def test_register_raises_value_error(self) -> None:
        reg = CapabilityRegistry()
        with pytest.raises(ValueError, match="Unknown capability category"):
            reg.register("bogus", "x", _handler)


class TestCategories:
    def test_six_categories(self) -> None:
        assert len(CapabilityRegistry.CATEGORIES) == 6
        for cat in CapabilityRegistry.CATEGORIES:
            assert isinstance(cat, str)
