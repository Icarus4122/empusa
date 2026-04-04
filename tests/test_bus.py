"""
Tests for empusa.bus

Covers: EventBus subscribe / unsubscribe / emit / emit_legacy,
        legacy hook adapter, attach_plugin_manager routing,
        context enrichment (timestamp, session_env), last_results.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from empusa.bus import EventBus
from empusa.events import (
    EmpusaEvent,
    PostScanEvent,
    StartupEvent,
)


@pytest.fixture()
def bus(tmp_path: Path) -> EventBus:
    """Minimal EventBus wired to a temp hooks dir."""
    return EventBus(
        hooks_dir=tmp_path / "hooks",
        verbose=False,
        quiet=True,
        session_env_fn=lambda: "test_env",
    )


# -- subscribe / unsubscribe ----------------------------------------


class TestSubscription:
    def test_subscribe_and_receive(self, bus: EventBus) -> None:
        received: list[EmpusaEvent] = []
        bus.subscribe("on_startup", received.append)
        bus.emit(StartupEvent())
        assert len(received) == 1
        assert received[0].event == "on_startup"

    def test_unsubscribe(self, bus: EventBus) -> None:
        received: list[EmpusaEvent] = []
        bus.subscribe("on_startup", received.append)
        assert bus.unsubscribe("on_startup", received.append) is True
        bus.emit(StartupEvent())
        assert received == []

    def test_unsubscribe_unknown_returns_false(self, bus: EventBus) -> None:
        assert bus.unsubscribe("on_startup", lambda e: None) is False

    def test_subscriber_count(self, bus: EventBus) -> None:
        assert bus.subscriber_count("post_scan") == 0
        bus.subscribe("post_scan", lambda e: None)
        assert bus.subscriber_count("post_scan") == 1


# -- emit ------------------------------------------------------------


class TestEmit:
    def test_timestamp_autofilled(self, bus: EventBus) -> None:
        evt = StartupEvent(timestamp="")
        bus.emit(evt)
        assert evt.timestamp != ""

    def test_session_env_autofilled(self, bus: EventBus) -> None:
        evt = StartupEvent(session_env="")
        bus.emit(evt)
        assert evt.session_env == "test_env"

    def test_returns_list(self, bus: EventBus) -> None:
        results = bus.emit(StartupEvent())
        assert isinstance(results, list)

    def test_last_results(self, bus: EventBus) -> None:
        bus.emit(StartupEvent())
        assert isinstance(bus.last_results, list)


# -- emit_legacy -----------------------------------------------------


class TestEmitLegacy:
    def test_constructs_typed_event(self, bus: EventBus) -> None:
        received: list[EmpusaEvent] = []
        bus.subscribe("post_scan", received.append)
        bus.emit_legacy("post_scan", {"ip": "10.10.10.5", "os_type": "Linux"})
        assert len(received) == 1
        assert isinstance(received[0], PostScanEvent)
        assert received[0].ip == "10.10.10.5"  # type: ignore[attr-defined]

    def test_unknown_event_uses_base(self, bus: EventBus) -> None:
        received: list[EmpusaEvent] = []
        bus.subscribe("custom_event", received.append)
        bus.emit_legacy("custom_event", {"key": "value"})
        assert len(received) == 1
        assert isinstance(received[0], EmpusaEvent)

    def test_context_enriched(self, bus: EventBus) -> None:
        received: list[EmpusaEvent] = []
        bus.subscribe("on_startup", received.append)
        bus.emit_legacy("on_startup")
        evt = received[0]
        assert evt.timestamp != ""
        assert evt.session_env == "test_env"


# -- legacy hook adapter ---------------------------------------------


class TestLegacyHooks:
    def test_hook_script_executed(self, tmp_path: Path) -> None:
        hooks_dir = tmp_path / "hooks"
        evt_dir = hooks_dir / "post_scan"
        evt_dir.mkdir(parents=True)
        marker = tmp_path / "marker.txt"
        script = evt_dir / "test_hook.py"
        script.write_text(f"import pathlib\ndef run(context):\n    pathlib.Path(r'{marker}').write_text('fired')\n")
        bus = EventBus(hooks_dir=hooks_dir, quiet=True)
        bus.emit(PostScanEvent(ip="1.2.3.4"))
        assert marker.read_text() == "fired"

    def test_hook_without_run_skipped(self, tmp_path: Path) -> None:
        hooks_dir = tmp_path / "hooks"
        evt_dir = hooks_dir / "on_startup"
        evt_dir.mkdir(parents=True)
        (evt_dir / "no_run.py").write_text("x = 1\n")
        bus = EventBus(hooks_dir=hooks_dir, quiet=True)
        bus.emit(StartupEvent())  # Should not raise

    def test_hook_error_does_not_propagate(self, tmp_path: Path) -> None:
        hooks_dir = tmp_path / "hooks"
        evt_dir = hooks_dir / "on_startup"
        evt_dir.mkdir(parents=True)
        (evt_dir / "bad.py").write_text("def run(ctx): raise RuntimeError('boom')\n")
        bus = EventBus(hooks_dir=hooks_dir, quiet=True)
        bus.emit(StartupEvent())  # Error caught internally

    def test_list_legacy_hooks(self, tmp_path: Path) -> None:
        hooks_dir = tmp_path / "hooks"
        (hooks_dir / "post_scan").mkdir(parents=True)
        (hooks_dir / "post_scan" / "a.py").touch()
        bus = EventBus(hooks_dir=hooks_dir, quiet=True)
        mapping = bus.list_legacy_hooks()
        assert "a.py" in mapping.get("post_scan", [])


# -- plugin manager routing ------------------------------------------


class TestPluginRouting:
    def test_no_pm_no_error(self, bus: EventBus) -> None:
        bus.emit(StartupEvent())  # No PM attached, should just work

    def test_attached_pm_receives_events(self, bus: EventBus) -> None:
        dispatched: list[str] = []

        class FakePM:
            def dispatch_event(self, name: str, event: EmpusaEvent) -> list[dict[str, Any]]:
                dispatched.append(name)
                return [{"plugin": "fake", "result": "ok"}]

        bus.attach_plugin_manager(FakePM())  # type: ignore[arg-type]
        results = bus.emit(StartupEvent())
        assert "on_startup" in dispatched
        assert any(r.get("plugin") == "fake" for r in results)
