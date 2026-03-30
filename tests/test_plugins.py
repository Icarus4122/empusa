"""
Tests for empusa.plugins (PluginManager graph logic)
and empusa.services (ScopedServices permission gating).

Run with:  python -m pytest tests/ -v
       or: python -m unittest tests.test_plugins -v
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console

from empusa.plugins import PluginManager
from empusa.services import (
    ArtifactWriter,
    CommandRunner,
    EnvResolver,
    LoggerService,
    LootAccessor,
    PermissionError,
    ScopedServices,
    Services,
)


# -- Helpers ---------------------------------------------------------


def _write_plugin(
    plugins_dir: Path,
    name: str,
    *,
    events: Optional[List[str]] = None,
    requires: Optional[List[str]] = None,
    permissions: Optional[List[str]] = None,
    enabled: bool = True,
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
    (d / "plugin.py").write_text(
        "def activate(s, r, b): pass\n"
        "def deactivate(): pass\n",
        encoding="utf-8",
    )
    return d


def _make_services(tmp: Path) -> Services:
    """Build a real Services container rooted in *tmp*."""
    console = Console(quiet=True)
    logger = LoggerService(console, verbose=False, quiet=True)
    config: Dict[str, Any] = {"session_env": str(tmp)}
    env = EnvResolver(config)
    artifact = ArtifactWriter(env)
    loot = LootAccessor(env)
    runner = CommandRunner(logger, dry_run=True)
    return Services(
        logger=logger,
        artifact=artifact,
        loot=loot,
        env=env,
        runner=runner,
    )


# -- Graph Logic Tests ----------------------------------------------


class TestMissingDependency(unittest.TestCase):
    """A plugin whose dependency is not installed must be blocked."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.plugins_dir = self.tmp / "plugins"
        self.plugins_dir.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_missing_dep_blocks_plugin(self) -> None:
        _write_plugin(self.plugins_dir, "child", requires=["nonexistent"])
        pm = PluginManager(self.plugins_dir)
        pm.discover()
        warnings = pm.resolve_dependencies()

        desc = pm.plugins["child"]
        self.assertFalse(desc.activatable, "plugin with missing dep should be non-activatable")
        self.assertTrue(any("nonexistent" in w for w in warnings))


class TestInvalidPermission(unittest.TestCase):
    """A plugin with an unknown permission must be blocked at discovery."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.plugins_dir = self.tmp / "plugins"
        self.plugins_dir.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_bad_perm_blocks_plugin(self) -> None:
        _write_plugin(self.plugins_dir, "badperm", permissions=["teleport"])
        pm = PluginManager(self.plugins_dir)
        pm.discover()

        desc = pm.plugins["badperm"]
        self.assertFalse(desc.activatable, "plugin with invalid permission should be non-activatable")


class TestChainPropagation(unittest.TestCase):
    """If B is blocked, A (which depends on B) must also be blocked."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.plugins_dir = self.tmp / "plugins"
        self.plugins_dir.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_simple_chain(self) -> None:
        _write_plugin(self.plugins_dir, "base", permissions=["teleport"])  # bad perm -> blocked
        _write_plugin(self.plugins_dir, "dependent", requires=["base"])

        pm = PluginManager(self.plugins_dir)
        pm.discover()
        pm.resolve_dependencies()

        self.assertFalse(pm.plugins["base"].activatable)
        self.assertFalse(
            pm.plugins["dependent"].activatable,
            "dependent of blocked plugin should also be blocked",
        )

    def test_longer_chain(self) -> None:
        """A -> B -> C; C blocked -> B blocked -> A blocked."""
        _write_plugin(self.plugins_dir, "c_leaf", permissions=["teleport"])  # blocked
        _write_plugin(self.plugins_dir, "b_mid", requires=["c_leaf"])
        _write_plugin(self.plugins_dir, "a_top", requires=["b_mid"])

        pm = PluginManager(self.plugins_dir)
        pm.discover()
        pm.resolve_dependencies()

        for name in ("c_leaf", "b_mid", "a_top"):
            self.assertFalse(
                pm.plugins[name].activatable,
                f"{name} should be blocked via transitive propagation",
            )


class TestDirectCycle(unittest.TestCase):
    """A <-> B mutual dependency must block both."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.plugins_dir = self.tmp / "plugins"
        self.plugins_dir.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_direct_cycle(self) -> None:
        _write_plugin(self.plugins_dir, "alpha", requires=["beta"])
        _write_plugin(self.plugins_dir, "beta", requires=["alpha"])

        pm = PluginManager(self.plugins_dir)
        pm.discover()
        warnings = pm.resolve_dependencies()

        self.assertFalse(pm.plugins["alpha"].activatable)
        self.assertFalse(pm.plugins["beta"].activatable)
        self.assertTrue(any("cycle" in w for w in warnings))


class TestLongerCycle(unittest.TestCase):
    """A -> B -> C -> A cycle must block all three."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.plugins_dir = self.tmp / "plugins"
        self.plugins_dir.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_three_node_cycle(self) -> None:
        _write_plugin(self.plugins_dir, "x", requires=["y"])
        _write_plugin(self.plugins_dir, "y", requires=["z"])
        _write_plugin(self.plugins_dir, "z", requires=["x"])

        pm = PluginManager(self.plugins_dir)
        pm.discover()
        _warnings = pm.resolve_dependencies()

        for name in ("x", "y", "z"):
            self.assertFalse(
                pm.plugins[name].activatable,
                f"{name} should be blocked as part of a cycle",
            )


class TestDependentOfCycleInvalidation(unittest.TestCase):
    """D depends on A which is in a cycle -> D must also be blocked."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.plugins_dir = self.tmp / "plugins"
        self.plugins_dir.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dependent_of_cycle(self) -> None:
        # A <-> B cycle
        _write_plugin(self.plugins_dir, "a", requires=["b"])
        _write_plugin(self.plugins_dir, "b", requires=["a"])
        # D depends on A
        _write_plugin(self.plugins_dir, "d", requires=["a"])

        pm = PluginManager(self.plugins_dir)
        pm.discover()
        pm.resolve_dependencies()

        self.assertFalse(pm.plugins["a"].activatable)
        self.assertFalse(pm.plugins["b"].activatable)
        self.assertFalse(
            pm.plugins["d"].activatable,
            "D depends on cycle member A -> should be blocked",
        )


class TestHealthyGraph(unittest.TestCase):
    """Plugins with satisfied deps and valid perms should remain activatable."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.plugins_dir = self.tmp / "plugins"
        self.plugins_dir.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_all_good(self) -> None:
        _write_plugin(self.plugins_dir, "core", permissions=["loot_read"])
        _write_plugin(self.plugins_dir, "ext", requires=["core"], permissions=["filesystem"])

        pm = PluginManager(self.plugins_dir)
        pm.discover()
        pm.resolve_dependencies()

        self.assertTrue(pm.plugins["core"].activatable)
        self.assertTrue(pm.plugins["ext"].activatable)


class TestEnableBlockedPlugin(unittest.TestCase):
    """enable_plugin() must refuse to enable a non-activatable plugin."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.plugins_dir = self.tmp / "plugins"
        self.plugins_dir.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_enable_refused(self) -> None:
        _write_plugin(self.plugins_dir, "bad", permissions=["teleport"])

        pm = PluginManager(self.plugins_dir)
        pm.discover()
        pm.resolve_dependencies()

        result = pm.enable_plugin("bad")
        self.assertFalse(result, "enable_plugin should return False for blocked plugin")
        self.assertFalse(pm.plugins["bad"].activated)


# -- ScopedServices Tests -------------------------------------------


class TestScopedServicesLootRead(unittest.TestCase):
    """loot_read permission gates read_all, count, search."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.svc = _make_services(self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_allowed(self) -> None:
        scoped = ScopedServices(self.svc, ["loot_read"], "reader")
        # Should not raise
        scoped.loot.read_all()
        scoped.loot.count()
        scoped.loot.search("host", "test")

    def test_denied(self) -> None:
        scoped = ScopedServices(self.svc, [], "noperm")
        with self.assertRaises(PermissionError):
            scoped.loot.read_all()
        with self.assertRaises(PermissionError):
            scoped.loot.count()
        with self.assertRaises(PermissionError):
            scoped.loot.search("host", "test")


class TestScopedServicesLootWrite(unittest.TestCase):
    """loot_write permission gates append."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.svc = _make_services(self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_allowed(self) -> None:
        scoped = ScopedServices(self.svc, ["loot_write"], "writer")
        scoped.loot.append({"host": "10.10.10.1", "data": "cred"})

    def test_denied(self) -> None:
        scoped = ScopedServices(self.svc, ["loot_read"], "reader_only")
        with self.assertRaises(PermissionError):
            scoped.loot.append({"host": "10.10.10.1"})


class TestScopedServicesFilesystem(unittest.TestCase):
    """filesystem permission gates artifact.write and artifact.write_bytes."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.svc = _make_services(self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_write_allowed(self) -> None:
        scoped = ScopedServices(self.svc, ["filesystem"], "fs_plugin")
        p = scoped.artifact.write("test_output.txt", "hello")
        self.assertTrue(p.exists())

    def test_write_denied(self) -> None:
        scoped = ScopedServices(self.svc, [], "no_fs")
        with self.assertRaises(PermissionError):
            scoped.artifact.write("test_output.txt", "hello")

    def test_write_bytes_denied(self) -> None:
        scoped = ScopedServices(self.svc, [], "no_fs")
        with self.assertRaises(PermissionError):
            scoped.artifact.write_bytes("binary.dat", b"\x00\x01")

    def test_exists_always_allowed(self) -> None:
        """exists() is read-only — no permission required."""
        scoped = ScopedServices(self.svc, [], "no_fs")
        # Should not raise even without filesystem permission
        scoped.artifact.exists("anything.txt")


class TestScopedServicesSubprocess(unittest.TestCase):
    """subprocess permission gates runner.run."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.svc = _make_services(self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_allowed(self) -> None:
        scoped = ScopedServices(self.svc, ["subprocess"], "exec_plugin")
        # dry_run=True so it won't actually execute
        result = scoped.runner.run(["echo", "hello"])
        self.assertEqual(result.returncode, 0)

    def test_denied(self) -> None:
        scoped = ScopedServices(self.svc, [], "no_exec")
        with self.assertRaises(PermissionError):
            scoped.runner.run(["echo", "hello"])


class TestScopedServicesAlwaysAvailable(unittest.TestCase):
    """logger and env are always accessible regardless of permissions."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.svc = _make_services(self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_logger_always_available(self) -> None:
        scoped = ScopedServices(self.svc, [], "empty_perms")
        # Should not raise
        scoped.logger.info("test message")
        scoped.logger.error("test error")
        scoped.logger.warn("test warning")
        scoped.logger.success("test success")

    def test_env_always_available(self) -> None:
        scoped = ScopedServices(self.svc, [], "empty_perms")
        # Should not raise
        self.assertTrue(scoped.env.is_active())
        self.assertIsNotNone(scoped.env.env_path())


class TestScopedServicesMultiplePerms(unittest.TestCase):
    """A plugin with multiple permissions can use all of them."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.svc = _make_services(self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_all_perms(self) -> None:
        scoped = ScopedServices(
            self.svc,
            ["loot_read", "loot_write", "filesystem", "subprocess"],
            "full_access",
        )
        scoped.loot.read_all()
        scoped.loot.append({"host": "10.10.10.1"})
        scoped.artifact.write("out.txt", "data")
        scoped.runner.run(["echo", "ok"])  # dry_run


if __name__ == "__main__":
    unittest.main()
