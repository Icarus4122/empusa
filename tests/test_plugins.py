"""
Tests for empusa.plugins (PluginManager graph logic)
and empusa.services (ScopedServices permission gating).

Run with:  python -m pytest tests/ -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from empusa.plugins import PluginManager
from empusa.services import (
    PermissionError,
    ScopedServices,
)
from tests.conftest import write_plugin

# -- Fixtures --------------------------------------------------------


@pytest.fixture()
def plugins_dir(tmp_path: Path) -> Path:
    d = tmp_path / "plugins"
    d.mkdir()
    return d


# -- Graph Logic Tests -----------------------------------------------


class TestMissingDependency:
    """A plugin whose dependency is not installed must be blocked."""

    def test_missing_dep_blocks_plugin(self, plugins_dir: Path) -> None:
        write_plugin(plugins_dir, "child", requires=["nonexistent"])
        pm = PluginManager(plugins_dir)
        pm.discover()
        warnings = pm.resolve_dependencies()

        desc = pm.plugins["child"]
        assert not desc.activatable, "plugin with missing dep should be non-activatable"
        assert any("nonexistent" in w for w in warnings)


class TestInvalidPermission:
    """A plugin with an unknown permission must be blocked at discovery."""

    def test_bad_perm_blocks_plugin(self, plugins_dir: Path) -> None:
        write_plugin(plugins_dir, "badperm", permissions=["teleport"])
        pm = PluginManager(plugins_dir)
        pm.discover()

        desc = pm.plugins["badperm"]
        assert not desc.activatable, "plugin with invalid permission should be non-activatable"


class TestChainPropagation:
    """If B is blocked, A (which depends on B) must also be blocked."""

    def test_simple_chain(self, plugins_dir: Path) -> None:
        write_plugin(plugins_dir, "base", permissions=["teleport"])  # bad perm -> blocked
        write_plugin(plugins_dir, "dependent", requires=["base"])

        pm = PluginManager(plugins_dir)
        pm.discover()
        pm.resolve_dependencies()

        assert not pm.plugins["base"].activatable
        assert not pm.plugins["dependent"].activatable, "dependent of blocked plugin should also be blocked"

    def test_longer_chain(self, plugins_dir: Path) -> None:
        """A -> B -> C; C blocked -> B blocked -> A blocked."""
        write_plugin(plugins_dir, "c_leaf", permissions=["teleport"])  # blocked
        write_plugin(plugins_dir, "b_mid", requires=["c_leaf"])
        write_plugin(plugins_dir, "a_top", requires=["b_mid"])

        pm = PluginManager(plugins_dir)
        pm.discover()
        pm.resolve_dependencies()

        for name in ("c_leaf", "b_mid", "a_top"):
            assert not pm.plugins[name].activatable, f"{name} should be blocked via transitive propagation"


class TestDirectCycle:
    """A <-> B mutual dependency must block both."""

    def test_direct_cycle(self, plugins_dir: Path) -> None:
        write_plugin(plugins_dir, "alpha", requires=["beta"])
        write_plugin(plugins_dir, "beta", requires=["alpha"])

        pm = PluginManager(plugins_dir)
        pm.discover()
        warnings = pm.resolve_dependencies()

        assert not pm.plugins["alpha"].activatable
        assert not pm.plugins["beta"].activatable
        assert any("cycle" in w for w in warnings)


class TestLongerCycle:
    """A -> B -> C -> A cycle must block all three."""

    def test_three_node_cycle(self, plugins_dir: Path) -> None:
        write_plugin(plugins_dir, "x", requires=["y"])
        write_plugin(plugins_dir, "y", requires=["z"])
        write_plugin(plugins_dir, "z", requires=["x"])

        pm = PluginManager(plugins_dir)
        pm.discover()
        pm.resolve_dependencies()

        for name in ("x", "y", "z"):
            assert not pm.plugins[name].activatable, f"{name} should be blocked as part of a cycle"


class TestDependentOfCycleInvalidation:
    """D depends on A which is in a cycle -> D must also be blocked."""

    def test_dependent_of_cycle(self, plugins_dir: Path) -> None:
        # A <-> B cycle
        write_plugin(plugins_dir, "a", requires=["b"])
        write_plugin(plugins_dir, "b", requires=["a"])
        # D depends on A
        write_plugin(plugins_dir, "d", requires=["a"])

        pm = PluginManager(plugins_dir)
        pm.discover()
        pm.resolve_dependencies()

        assert not pm.plugins["a"].activatable
        assert not pm.plugins["b"].activatable
        assert not pm.plugins["d"].activatable, "D depends on cycle member A -> should be blocked"


class TestHealthyGraph:
    """Plugins with satisfied deps and valid perms should remain activatable."""

    def test_all_good(self, plugins_dir: Path) -> None:
        write_plugin(plugins_dir, "core", permissions=["loot_read"])
        write_plugin(plugins_dir, "ext", requires=["core"], permissions=["filesystem"])

        pm = PluginManager(plugins_dir)
        pm.discover()
        pm.resolve_dependencies()

        assert pm.plugins["core"].activatable
        assert pm.plugins["ext"].activatable


class TestEnableBlockedPlugin:
    """enable_plugin() must refuse to enable a non-activatable plugin."""

    def test_enable_refused(self, plugins_dir: Path) -> None:
        write_plugin(plugins_dir, "bad", permissions=["teleport"])

        pm = PluginManager(plugins_dir)
        pm.discover()
        pm.resolve_dependencies()

        result = pm.enable_plugin("bad")
        assert not result, "enable_plugin should return False for blocked plugin"
        assert not pm.plugins["bad"].activated


class TestRefreshLifecycle:
    """refresh() must deactivate, re-discover, resolve, and re-activate."""

    def test_refresh_reactivates_healthy_plugins(self, plugins_dir: Path, make_services) -> None:
        svc = make_services(plugins_dir.parent)
        write_plugin(plugins_dir, "alpha", permissions=["loot_read"])
        pm = PluginManager(plugins_dir, services=svc)
        pm.discover()
        pm.resolve_dependencies()
        pm.activate_all()
        assert pm.plugins["alpha"].activated

        # Refresh should deactivate + re-activate cleanly
        warnings = pm.refresh()
        assert pm.plugins["alpha"].activated
        assert warnings == []

    def test_refresh_picks_up_new_plugin(self, plugins_dir: Path, make_services) -> None:
        svc = make_services(plugins_dir.parent)
        write_plugin(plugins_dir, "first", permissions=["loot_read"])
        pm = PluginManager(plugins_dir, services=svc)
        pm.discover()
        pm.resolve_dependencies()
        pm.activate_all()
        assert pm.plugin_count() == 1

        # Add a second plugin on disk, then refresh
        write_plugin(plugins_dir, "second", permissions=["filesystem"])
        pm.refresh()
        assert pm.plugin_count() == 2
        assert "second" in pm.plugins
        assert pm.plugins["second"].activated

    def test_refresh_blocks_newly_broken_plugin(self, plugins_dir: Path, make_services) -> None:
        svc = make_services(plugins_dir.parent)
        write_plugin(plugins_dir, "good")
        pm = PluginManager(plugins_dir, services=svc)
        pm.discover()
        pm.resolve_dependencies()
        pm.activate_all()
        assert pm.plugins["good"].activated

        # Corrupt the manifest to add a bad permission
        manifest = plugins_dir / "good" / "manifest.json"
        raw = json.loads(manifest.read_text(encoding="utf-8"))
        raw["permissions"] = ["teleport"]
        manifest.write_text(json.dumps(raw), encoding="utf-8")

        pm.refresh()
        assert not pm.plugins["good"].activatable
        assert not pm.plugins["good"].activated


# -- ScopedServices Tests --------------------------------------------


class TestScopedServicesLootRead:
    """loot_read permission gates read_all, count, search."""

    def test_allowed(self, make_services) -> None:
        svc = make_services()
        scoped = ScopedServices(svc, ["loot_read"], "reader")
        scoped.loot.read_all()
        scoped.loot.count()
        scoped.loot.search("host", "test")

    def test_denied(self, make_services) -> None:
        svc = make_services()
        scoped = ScopedServices(svc, [], "noperm")
        with pytest.raises(PermissionError):
            scoped.loot.read_all()
        with pytest.raises(PermissionError):
            scoped.loot.count()
        with pytest.raises(PermissionError):
            scoped.loot.search("host", "test")


class TestScopedServicesLootWrite:
    """loot_write permission gates append."""

    def test_allowed(self, make_services) -> None:
        svc = make_services()
        scoped = ScopedServices(svc, ["loot_write"], "writer")
        scoped.loot.append({"host": "10.10.10.1", "data": "cred"})

    def test_denied(self, make_services) -> None:
        svc = make_services()
        scoped = ScopedServices(svc, ["loot_read"], "reader_only")
        with pytest.raises(PermissionError):
            scoped.loot.append({"host": "10.10.10.1"})


class TestScopedServicesFilesystem:
    """filesystem permission gates artifact.write and artifact.write_bytes."""

    def test_write_allowed(self, make_services) -> None:
        svc = make_services()
        scoped = ScopedServices(svc, ["filesystem"], "fs_plugin")
        p = scoped.artifact.write("test_output.txt", "hello")
        assert p.exists()

    def test_write_denied(self, make_services) -> None:
        svc = make_services()
        scoped = ScopedServices(svc, [], "no_fs")
        with pytest.raises(PermissionError):
            scoped.artifact.write("test_output.txt", "hello")

    def test_write_bytes_denied(self, make_services) -> None:
        svc = make_services()
        scoped = ScopedServices(svc, [], "no_fs")
        with pytest.raises(PermissionError):
            scoped.artifact.write_bytes("binary.dat", b"\x00\x01")

    def test_exists_always_allowed(self, make_services) -> None:
        """exists() is read-only — no permission required."""
        svc = make_services()
        scoped = ScopedServices(svc, [], "no_fs")
        scoped.artifact.exists("anything.txt")


class TestScopedServicesSubprocess:
    """subprocess permission gates runner.run."""

    def test_allowed(self, make_services) -> None:
        svc = make_services()
        scoped = ScopedServices(svc, ["subprocess"], "exec_plugin")
        # dry_run=True so it won't actually execute
        result = scoped.runner.run(["echo", "hello"])
        assert result.returncode == 0

    def test_denied(self, make_services) -> None:
        svc = make_services()
        scoped = ScopedServices(svc, [], "no_exec")
        with pytest.raises(PermissionError):
            scoped.runner.run(["echo", "hello"])


class TestScopedServicesAlwaysAvailable:
    """logger and env are always accessible regardless of permissions."""

    def test_logger_always_available(self, make_services) -> None:
        svc = make_services()
        scoped = ScopedServices(svc, [], "empty_perms")
        scoped.logger.info("test message")
        scoped.logger.error("test error")
        scoped.logger.warn("test warning")
        scoped.logger.success("test success")

    def test_env_always_available(self, make_services) -> None:
        svc = make_services()
        scoped = ScopedServices(svc, [], "empty_perms")
        assert scoped.env.is_active()
        assert scoped.env.env_path() is not None


class TestScopedServicesMultiplePerms:
    """A plugin with multiple permissions can use all of them."""

    def test_all_perms(self, make_services) -> None:
        svc = make_services()
        scoped = ScopedServices(
            svc,
            ["loot_read", "loot_write", "filesystem", "subprocess"],
            "full_access",
        )
        scoped.loot.read_all()
        scoped.loot.append({"host": "10.10.10.1"})
        scoped.artifact.write("out.txt", "data")
        scoped.runner.run(["echo", "ok"])  # dry_run
