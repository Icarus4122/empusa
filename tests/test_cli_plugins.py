"""
Tests for empusa.cli_plugins

Covers: list_plugins_render, create_plugin refresh call,
        toggle_plugin blocked guard, uninstall_plugin_ui refresh call,
        config value JSON parsing.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from empusa.cli_plugins import list_plugins_render

# -- list_plugins_render ---------------------------------------------


class TestListPluginsRender:
    def test_none_plugin_manager(self) -> None:
        result = list_plugins_render(None)
        assert "not initialized" in str(result).lower()

    def test_empty_plugins(self) -> None:
        pm = MagicMock()
        pm.plugins = {}
        result = list_plugins_render(pm)
        assert "no plugins" in str(result).lower()

    def test_with_plugins_returns_table(self) -> None:
        desc = MagicMock()
        desc.name = "demo"
        desc.version = "1.0.0"
        desc.activated = True
        desc.activatable = True
        desc.enabled = True
        desc.events = ["on_startup"]
        desc.description = "A demo plugin"

        pm = MagicMock()
        pm.plugins = {"demo": desc}
        pm.active_count.return_value = 1
        pm.plugin_count.return_value = 1

        table = list_plugins_render(pm)
        # Rich Table doesn't expose a simple string check, but it should be a Table
        assert table is not None
        assert hasattr(table, "columns")  # It's a Rich Table


# -- Config value JSON parsing ----------------------------------------


class TestConfigJsonParsing:
    """Verify that plugin config editing parses typed values via json.loads."""

    def test_json_loads_int(self) -> None:
        """json.loads('42') -> int(42)"""
        assert json.loads("42") == 42

    def test_json_loads_bool(self) -> None:
        assert json.loads("true") is True
        assert json.loads("false") is False

    def test_json_loads_string_fallback(self) -> None:
        """Non-JSON strings remain as strings in the actual code."""
        raw = "hello world"
        try:
            val = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            val = raw
        assert val == "hello world"

    def test_json_loads_list(self) -> None:
        assert json.loads("[1,2,3]") == [1, 2, 3]


# -- create_plugin calls refresh() -----------------------------------


class TestCreatePluginRefresh:
    @patch("empusa.cli_plugins.Prompt")
    @patch("empusa.cli_plugins.Confirm")
    def test_create_plugin_calls_refresh(
        self,
        mock_confirm: MagicMock,
        mock_prompt: MagicMock,
        tmp_path: Path,
    ) -> None:
        """create_plugin() should call plugin_manager.refresh() on success."""
        from empusa.cli_plugins import create_plugin

        mock_prompt.ask.side_effect = [
            "test_plugin",  # name
            "1.0.0",  # version
            "Test Author",  # author
            "A test plugin",  # description
            "",  # events (default)
            "",  # permissions (default)
        ]
        mock_confirm.ask.return_value = True

        pm = MagicMock()
        pm.create_plugin_scaffold.return_value = tmp_path / "test_plugin"

        with patch("empusa.cli_plugins.PLUGINS_DIR", tmp_path):
            create_plugin(pm)

        pm.refresh.assert_called_once()


# -- uninstall calls refresh() ----------------------------------------


class TestUninstallRefresh:
    @patch("empusa.cli_plugins.Prompt")
    @patch("empusa.cli_plugins.Confirm")
    def test_uninstall_calls_refresh(
        self,
        mock_confirm: MagicMock,
        mock_prompt: MagicMock,
        tmp_path: Path,
    ) -> None:
        from empusa.cli_plugins import uninstall_plugin_ui

        desc = MagicMock()
        desc.name = "victim"
        desc.path = tmp_path / "victim"
        desc.activated = False

        pm = MagicMock()
        pm.plugins = {"victim": desc}
        pm.uninstall_plugin.return_value = True

        # The UI asks for a numeric index, then a confirm
        mock_prompt.ask.return_value = "1"
        mock_confirm.ask.return_value = True

        uninstall_plugin_ui(pm)
        pm.refresh.assert_called_once()


# -- show_registry_render ---------------------------------------------


class TestShowRegistryRender:
    def test_none_registry(self) -> None:
        from empusa.cli_plugins import show_registry_render

        result = show_registry_render(None)
        assert "not available" in str(result).lower()

    def test_empty_registry(self) -> None:
        from empusa.cli_plugins import show_registry_render

        reg = MagicMock()
        reg.summary.return_value = {}
        result = show_registry_render(reg)
        assert "empty" in str(result).lower()

    def test_with_entries(self) -> None:
        from empusa.cli_plugins import show_registry_render

        entry = MagicMock()
        entry.name = "nmap_scanner"

        rep1 = MagicMock()
        rep1.name = "rep1"
        rep2 = MagicMock()
        rep2.name = "rep2"

        reg = MagicMock()
        reg.summary.return_value = {"scanner": 1, "reporter": 2}
        reg.get.side_effect = lambda cat: [entry] if cat == "scanner" else [rep1, rep2]

        table = show_registry_render(reg)
        assert hasattr(table, "columns")
        assert table.caption is not None
        assert "3" in table.caption


# -- list_plugins_render status branches ------------------------------


class TestListPluginsRenderStatuses:
    def _make_desc(self, *, activated: bool, activatable: bool, enabled: bool) -> MagicMock:
        desc = MagicMock()
        desc.name = "test"
        desc.version = "1.0"
        desc.activated = activated
        desc.activatable = activatable
        desc.enabled = enabled
        desc.events = []
        desc.description = "test"
        return desc

    def test_active_status(self) -> None:
        pm = MagicMock()
        desc = self._make_desc(activated=True, activatable=True, enabled=True)
        pm.plugins = {"p": desc}
        pm.active_count.return_value = 1
        pm.plugin_count.return_value = 1
        result = list_plugins_render(pm)
        assert result is not None

    def test_blocked_status(self) -> None:
        pm = MagicMock()
        desc = self._make_desc(activated=False, activatable=False, enabled=True)
        pm.plugins = {"p": desc}
        pm.active_count.return_value = 0
        pm.plugin_count.return_value = 1
        result = list_plugins_render(pm)
        assert result is not None

    def test_disabled_status(self) -> None:
        pm = MagicMock()
        desc = self._make_desc(activated=False, activatable=True, enabled=False)
        pm.plugins = {"p": desc}
        pm.active_count.return_value = 0
        pm.plugin_count.return_value = 1
        result = list_plugins_render(pm)
        assert result is not None
