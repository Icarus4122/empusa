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
            "Test Author",  # autho
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


# -- list_plugins (console-emitting variant) -------------------------


class TestListPlugins:
    def test_none_pm_logs_error(self) -> None:
        from empusa.cli_plugins import list_plugins

        list_plugins(None)  # should not raise

    def test_empty_plugins(self) -> None:
        from empusa.cli_plugins import list_plugins

        pm = MagicMock()
        pm.plugins = {}
        list_plugins(pm)

    def test_with_plugins_each_status(self) -> None:
        from empusa.cli_plugins import list_plugins

        def mk(activated, activatable, enabled, name):
            d = MagicMock()
            d.name = name
            d.version = "1.0"
            d.activated = activated
            d.activatable = activatable
            d.enabled = enabled
            d.events = []
            d.description = "x"
            return d

        pm = MagicMock()
        pm.plugins = {
            "a": mk(True, True, True, "a"),
            "b": mk(False, False, True, "b"),
            "c": mk(False, True, True, "c"),
            "d": mk(False, True, False, "d"),
        }
        pm.active_count.return_value = 1
        pm.plugin_count.return_value = 4
        list_plugins(pm)


# -- toggle_plugin ----------------------------------------------------


class TestTogglePlugin:
    def _pm(self, *, activated=False, activatable=True, enabled=False):
        d = MagicMock()
        d.name = "p"
        d.activated = activated
        d.activatable = activatable
        d.enabled = enabled
        pm = MagicMock()
        pm.plugins = {"p": d}
        return pm

    def test_none_pm(self) -> None:
        from empusa.cli_plugins import toggle_plugin

        toggle_plugin(None)

    def test_no_plugins(self) -> None:
        from empusa.cli_plugins import toggle_plugin

        pm = MagicMock()
        pm.plugins = {}
        toggle_plugin(pm)

    @patch("empusa.cli_plugins.Confirm")
    @patch("empusa.cli_plugins.Prompt")
    def test_blocked_plugin_rejected(self, mp: MagicMock, mc: MagicMock) -> None:
        from empusa.cli_plugins import toggle_plugin

        pm = self._pm(activatable=False)
        mp.ask.return_value = "1"
        toggle_plugin(pm)
        pm.disable_plugin.assert_not_called()
        pm.enable_plugin.assert_not_called()

    @patch("empusa.cli_plugins.Confirm")
    @patch("empusa.cli_plugins.Prompt")
    def test_enable_disabled_plugin(self, mp: MagicMock, mc: MagicMock) -> None:
        from empusa.cli_plugins import toggle_plugin

        pm = self._pm(enabled=False)
        mp.ask.return_value = "1"
        mc.ask.return_value = True
        toggle_plugin(pm)
        pm.enable_plugin.assert_called_once_with("p")

    @patch("empusa.cli_plugins.Confirm")
    @patch("empusa.cli_plugins.Prompt")
    def test_disable_enabled_plugin(self, mp: MagicMock, mc: MagicMock) -> None:
        from empusa.cli_plugins import toggle_plugin

        pm = self._pm(enabled=True)
        mp.ask.return_value = "1"
        mc.ask.return_value = True
        toggle_plugin(pm)
        pm.disable_plugin.assert_called_once_with("p")

    @patch("empusa.cli_plugins.Prompt")
    def test_invalid_index(self, mp: MagicMock) -> None:
        from empusa.cli_plugins import toggle_plugin

        pm = self._pm()
        mp.ask.return_value = "99"
        toggle_plugin(pm)

    @patch("empusa.cli_plugins.Prompt")
    def test_non_numeric(self, mp: MagicMock) -> None:
        from empusa.cli_plugins import toggle_plugin

        pm = self._pm()
        mp.ask.return_value = "abc"
        toggle_plugin(pm)


# -- plugin_info ------------------------------------------------------


class TestPluginInfo:
    def _desc(self, name="p", config=None):
        d = MagicMock()
        d.name = name
        d.version = "1.0"
        d.author = "auth"
        d.description = "desc"
        d.activated = True
        d.activatable = True
        d.enabled = True
        d.events = ["on_startup"]
        d.requires = []
        d.permissions = ["network"]
        d.path = Path("/tmp/p")
        d.config = config or {}
        return d

    def test_none_pm(self) -> None:
        from empusa.cli_plugins import plugin_info

        plugin_info(None)

    def test_no_plugins(self) -> None:
        from empusa.cli_plugins import plugin_info

        pm = MagicMock()
        pm.plugins = {}
        plugin_info(pm)

    @patch("empusa.cli_plugins.Confirm")
    @patch("empusa.cli_plugins.Prompt")
    def test_view_no_edit(self, mp: MagicMock, mc: MagicMock) -> None:
        from empusa.cli_plugins import plugin_info

        pm = MagicMock()
        pm.plugins = {"p": self._desc(config={"x": 1})}
        mp.ask.return_value = "1"
        mc.ask.return_value = False
        plugin_info(pm)
        pm.set_plugin_config.assert_not_called()

    @patch("empusa.cli_plugins.Confirm")
    @patch("empusa.cli_plugins.Prompt")
    def test_edit_int_config(self, mp: MagicMock, mc: MagicMock) -> None:
        from empusa.cli_plugins import plugin_info

        pm = MagicMock()
        pm.plugins = {"p": self._desc()}
        mp.ask.side_effect = ["1", "key", "42"]
        mc.ask.return_value = True
        plugin_info(pm)
        pm.set_plugin_config.assert_called_once_with("p", "key", 42)

    @patch("empusa.cli_plugins.Confirm")
    @patch("empusa.cli_plugins.Prompt")
    def test_edit_string_fallback(self, mp: MagicMock, mc: MagicMock) -> None:
        from empusa.cli_plugins import plugin_info

        pm = MagicMock()
        pm.plugins = {"p": self._desc()}
        mp.ask.side_effect = ["1", "k", "hello world"]
        mc.ask.return_value = True
        plugin_info(pm)
        pm.set_plugin_config.assert_called_once_with("p", "k", "hello world")

    @patch("empusa.cli_plugins.Prompt")
    def test_invalid_index(self, mp: MagicMock) -> None:
        from empusa.cli_plugins import plugin_info

        pm = MagicMock()
        pm.plugins = {"p": self._desc()}
        mp.ask.return_value = "99"
        plugin_info(pm)

    @patch("empusa.cli_plugins.Prompt")
    def test_non_numeric(self, mp: MagicMock) -> None:
        from empusa.cli_plugins import plugin_info

        pm = MagicMock()
        pm.plugins = {"p": self._desc()}
        mp.ask.return_value = "abc"
        plugin_info(pm)


# -- uninstall_plugin_ui extra branches ------------------------------


class TestUninstallPluginUiExtras:
    def test_none_pm(self) -> None:
        from empusa.cli_plugins import uninstall_plugin_ui

        uninstall_plugin_ui(None)

    def test_no_plugins(self) -> None:
        from empusa.cli_plugins import uninstall_plugin_ui

        pm = MagicMock()
        pm.plugins = {}
        uninstall_plugin_ui(pm)

    @patch("empusa.cli_plugins.Confirm")
    @patch("empusa.cli_plugins.Prompt")
    def test_cancel_confirm(self, mp: MagicMock, mc: MagicMock) -> None:
        from empusa.cli_plugins import uninstall_plugin_ui

        pm = MagicMock()
        d = MagicMock()
        d.name = "p"
        pm.plugins = {"p": d}
        mp.ask.return_value = "1"
        mc.ask.return_value = False
        uninstall_plugin_ui(pm)
        pm.uninstall_plugin.assert_not_called()

    @patch("empusa.cli_plugins.Confirm")
    @patch("empusa.cli_plugins.Prompt")
    def test_uninstall_failure(self, mp: MagicMock, mc: MagicMock) -> None:
        from empusa.cli_plugins import uninstall_plugin_ui

        pm = MagicMock()
        d = MagicMock()
        d.name = "p"
        pm.plugins = {"p": d}
        pm.uninstall_plugin.return_value = False
        mp.ask.return_value = "1"
        mc.ask.return_value = True
        uninstall_plugin_ui(pm)
        pm.refresh.assert_not_called()

    @patch("empusa.cli_plugins.Prompt")
    def test_invalid_index(self, mp: MagicMock) -> None:
        from empusa.cli_plugins import uninstall_plugin_ui

        pm = MagicMock()
        d = MagicMock()
        d.name = "p"
        pm.plugins = {"p": d}
        mp.ask.return_value = "5"
        uninstall_plugin_ui(pm)

    @patch("empusa.cli_plugins.Prompt")
    def test_non_numeric(self, mp: MagicMock) -> None:
        from empusa.cli_plugins import uninstall_plugin_ui

        pm = MagicMock()
        d = MagicMock()
        d.name = "p"
        pm.plugins = {"p": d}
        mp.ask.return_value = "x"
        uninstall_plugin_ui(pm)


# -- show_registry ----------------------------------------------------


class TestShowRegistry:
    def test_none(self) -> None:
        from empusa.cli_plugins import show_registry

        show_registry(None)

    def test_empty(self) -> None:
        from empusa.cli_plugins import show_registry

        reg = MagicMock()
        reg.summary.return_value = {}
        show_registry(reg)

    def test_with_entries(self) -> None:
        from empusa.cli_plugins import show_registry

        e = MagicMock()
        e.name = "alpha"
        reg = MagicMock()
        reg.summary.return_value = {"scanner": 1}
        reg.get.return_value = [e]
        show_registry(reg)


# -- open_plugins_dir -------------------------------------------------


class TestOpenPluginsDir:
    def test_linux(self, tmp_path: Path) -> None:
        from empusa.cli_plugins import open_plugins_dir

        with (
            patch("empusa.cli_plugins.PLUGINS_DIR", tmp_path),
            patch("empusa.cli_plugins.IS_WINDOWS", False),
            patch("empusa.cli_plugins.platform.system", return_value="Linux"),
            patch("empusa.cli_plugins.subprocess.run") as r,
        ):
            open_plugins_dir()
            r.assert_called_once()
            assert r.call_args[0][0][0] == "xdg-open"

    def test_darwin(self, tmp_path: Path) -> None:
        from empusa.cli_plugins import open_plugins_dir

        with (
            patch("empusa.cli_plugins.PLUGINS_DIR", tmp_path),
            patch("empusa.cli_plugins.IS_WINDOWS", False),
            patch("empusa.cli_plugins.platform.system", return_value="Darwin"),
            patch("empusa.cli_plugins.subprocess.run") as r,
        ):
            open_plugins_dir()
            r.assert_called_once()
            assert r.call_args[0][0][0] == "open"

    def test_exception_handled(self, tmp_path: Path) -> None:
        from empusa.cli_plugins import open_plugins_dir

        with (
            patch("empusa.cli_plugins.PLUGINS_DIR", tmp_path),
            patch("empusa.cli_plugins.IS_WINDOWS", False),
            patch("empusa.cli_plugins.platform.system", side_effect=RuntimeError("boom")),
        ):
            open_plugins_dir()  # must not raise


# -- create_plugin extra branches ------------------------------------


class TestCreatePluginExtras:
    def test_none_pm(self) -> None:
        from empusa.cli_plugins import create_plugin

        create_plugin(None)

    @patch("empusa.cli_plugins.Prompt")
    def test_blank_name_aborts(self, mp: MagicMock) -> None:
        from empusa.cli_plugins import create_plugin

        mp.ask.return_value = ""
        pm = MagicMock()
        create_plugin(pm)
        pm.create_plugin_scaffold.assert_not_called()

    @patch("empusa.cli_plugins.Prompt")
    def test_event_selection_and_perms(self, mp: MagicMock, tmp_path: Path) -> None:
        from empusa.cli_plugins import create_plugin

        pm = MagicMock()
        pm.create_plugin_scaffold.return_value = tmp_path / "x"
        pm.refresh.return_value = ["one warning"]

        mp.ask.side_effect = [
            "my plugin",
            "desc",
            "auth",
            "1, abc, 2",
            "network, filesystem",
        ]
        create_plugin(pm)
        kwargs = pm.create_plugin_scaffold.call_args.kwargs
        assert kwargs["name"] == "my_plugin"
        assert "network" in kwargs["permissions"]
        # Selected events should include indices 1 and 2 (valid), invalid "abc" skipped
        assert len(kwargs["events"]) == 2
