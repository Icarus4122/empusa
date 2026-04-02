"""
Tests for empusa.events

Covers: dataclass construction, to_dict serialisation,
        EVENT_MAP completeness, ALL_EVENTS consistency,
        field defaults, TestFireEvent sentinel fields.
"""

from __future__ import annotations

from typing import List, Type

from empusa.events import (
    ALL_EVENTS,
    EVENT_MAP,
    EmpusaEvent,
    EnvSelectEvent,
    LootAddedEvent,
    PostBuildEvent,
    PostCommandEvent,
    PostCompileEvent,
    PostScanEvent,
    PreBuildEvent,
    PreCommandEvent,
    PreReportWriteEvent,
    PreScanHostEvent,
    ReportGeneratedEvent,
    ShutdownEvent,
    StartupEvent,
    TestFireEvent,
)


class TestBaseEvent:
    def test_defaults(self) -> None:
        evt = EmpusaEvent()
        assert evt.event == ""
        assert evt.timestamp != ""      # auto-filled by default_factory
        assert evt.session_env == ""

    def test_to_dict_is_plain_dict(self) -> None:
        evt = EmpusaEvent(event="test")
        d = evt.to_dict()
        assert isinstance(d, dict)
        assert d["event"] == "test"


class TestAllSubclasses:
    """Ensure every concrete event can be instantiated with only defaults."""

    SUBCLASSES: List[Type[EmpusaEvent]] = [
        StartupEvent,
        ShutdownEvent,
        EnvSelectEvent,
        PreBuildEvent,
        PostBuildEvent,
        PreScanHostEvent,
        PostScanEvent,
        LootAddedEvent,
        PreReportWriteEvent,
        ReportGeneratedEvent,
        PostCompileEvent,
        PreCommandEvent,
        PostCommandEvent,
        TestFireEvent,
    ]

    def test_instantiate_defaults(self) -> None:
        for cls in self.SUBCLASSES:
            obj = cls()
            assert obj.event != ""
            d = obj.to_dict()
            assert "event" in d
            assert "timestamp" in d

    def test_event_names_unique(self) -> None:
        names = [cls().event for cls in self.SUBCLASSES]
        assert len(names) == len(set(names))


class TestEventMap:
    def test_all_events_in_map(self) -> None:
        for name in ALL_EVENTS:
            assert name in EVENT_MAP

    def test_map_values_are_subclasses(self) -> None:
        for cls in EVENT_MAP.values():
            assert issubclass(cls, EmpusaEvent)

    def test_all_events_matches_keys(self) -> None:
        assert set(ALL_EVENTS) == set(EVENT_MAP.keys())


class TestSpecificFields:
    def test_post_scan_fields(self) -> None:
        evt = PostScanEvent(ip="10.0.0.1", os_type="Linux")
        assert evt.ip == "10.0.0.1"
        assert evt.os_type == "Linux"

    def test_loot_added_fields(self) -> None:
        evt = LootAddedEvent(host="10.0.0.2", cred_type="hash", username="root")
        d = evt.to_dict()
        assert d["host"] == "10.0.0.2"

    def test_test_fire_sentinel(self) -> None:
        evt = TestFireEvent()
        d = evt.to_dict()
        assert d["_test_fire"] is True
        assert evt.ip == "10.10.10.10"

    def test_shutdown_killed_pids_default_empty(self) -> None:
        evt = ShutdownEvent()
        assert evt.killed_pids == []

    def test_pre_build_ips_default_empty(self) -> None:
        evt = PreBuildEvent()
        assert evt.ips == []

    def test_pre_command_args_default_empty(self) -> None:
        evt = PreCommandEvent()
        assert evt.args == []

    def test_post_command_return_code_default(self) -> None:
        evt = PostCommandEvent()
        assert evt.return_code == 0


class TestToDict:
    def test_roundtrip_preserves_values(self) -> None:
        evt = PostScanEvent(ip="1.2.3.4", os_type="Windows", scan_output="data")
        d = evt.to_dict()
        assert d["ip"] == "1.2.3.4"
        assert d["os_type"] == "Windows"
        assert d["scan_output"] == "data"

    def test_list_field_survives_serialisation(self) -> None:
        evt = PreBuildEvent(ips=["10.0.0.1", "10.0.0.2"])
        d = evt.to_dict()
        assert d["ips"] == ["10.0.0.1", "10.0.0.2"]
