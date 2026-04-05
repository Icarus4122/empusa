"""
Tests for empusa.events

Covers: dataclass construction, to_dict serialisation,
        EVENT_MAP completeness, ALL_EVENTS consistency,
        field defaults, TestFireEvent sentinel fields,
        workspace contract constants, event payload schemas.
"""

from __future__ import annotations

from dataclasses import fields as dc_fields

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
    PostWorkspaceInitEvent,
    PreBuildEvent,
    PreCommandEvent,
    PreReportWriteEvent,
    PreScanHostEvent,
    PreWorkspaceInitEvent,
    ReportGeneratedEvent,
    ShutdownEvent,
    StartupEvent,
    TestFireEvent,
    WorkspaceSelectEvent,
    make_event,
)


class TestBaseEvent:
    def test_defaults(self) -> None:
        evt = EmpusaEvent()
        assert evt.event == ""
        assert evt.timestamp != ""  # auto-filled by default_factory
        assert evt.session_env == ""

    def test_to_dict_is_plain_dict(self) -> None:
        evt = EmpusaEvent(event="test")
        d = evt.to_dict()
        assert isinstance(d, dict)
        assert d["event"] == "test"


class TestAllSubclasses:
    """Ensure every concrete event can be instantiated with only defaults."""

    SUBCLASSES: list[type[EmpusaEvent]] = [
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


class TestMakeEvent:
    """Tests for the canonical make_event() factory."""

    def test_known_event_returns_typed(self) -> None:
        evt = make_event("pre_build", env_name="myenv", ips=["10.0.0.1"])
        assert isinstance(evt, PreBuildEvent)
        assert evt.env_name == "myenv"
        assert evt.ips == ["10.0.0.1"]

    def test_event_field_set(self) -> None:
        evt = make_event("on_startup")
        assert evt.event == "on_startup"
        assert isinstance(evt, StartupEvent)

    def test_unknown_event_returns_base(self) -> None:
        evt = make_event("custom_event")
        assert isinstance(evt, EmpusaEvent)
        assert evt.event == "custom_event"

    def test_drops_unknown_keys(self) -> None:
        evt = make_event("on_startup", bogus_key="ignored")
        assert isinstance(evt, StartupEvent)
        assert not hasattr(evt, "bogus_key")

    def test_empty_name_raises(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="must not be empty"):
            make_event("")

    def test_workspace_events(self) -> None:
        evt = make_event(
            "pre_workspace_init",
            workspace_name="box1",
            workspace_root="/opt/lab/workspaces",
            profile="htb",
            set_active=True,
        )
        assert isinstance(evt, PreWorkspaceInitEvent)
        assert evt.workspace_name == "box1"
        assert evt.profile == "htb"
        assert evt.set_active is True

    def test_workspace_select_event(self) -> None:
        evt = make_event(
            "on_workspace_select",
            workspace_name="box1",
            workspace_root="/opt/lab/workspaces",
            workspace_path="/opt/lab/workspaces/box1",
            profile="htb",
        )
        assert isinstance(evt, WorkspaceSelectEvent)
        assert evt.workspace_path == "/opt/lab/workspaces/box1"

    def test_to_dict_roundtrip(self) -> None:
        evt = make_event("post_scan", ip="1.2.3.4", os_type="Linux")
        d = evt.to_dict()
        assert d["ip"] == "1.2.3.4"
        assert d["os_type"] == "Linux"
        assert d["event"] == "post_scan"

    def test_all_registered_events_constructable(self) -> None:
        for name in ALL_EVENTS:
            evt = make_event(name)
            assert evt.event == name
            assert isinstance(evt, EVENT_MAP[name])


# ═══════════════════════════════════════════════════════════════════
#  Contract-pinning: workspace constants and event payload schemas
# ═══════════════════════════════════════════════════════════════════


class TestWorkspaceConstantsPinned:
    """Pin the workspace constants that Hecate and downstream tooling depend on."""

    def test_profile_list_pinned(self) -> None:
        from empusa.workspace import PROFILES

        assert set(PROFILES.keys()) == {"htb", "build", "research", "internal"}

    def test_default_workspace_root_pinned(self) -> None:
        from empusa.workspace import DEFAULT_WORKSPACE_ROOT

        assert DEFAULT_WORKSPACE_ROOT.as_posix() == "/opt/lab/workspaces"

    def test_metadata_filename_pinned(self) -> None:
        from empusa.workspace import METADATA_FILENAME

        assert METADATA_FILENAME == ".empusa-workspace.json"

    def test_htb_profile_dirs_pinned(self) -> None:
        from empusa.workspace import PROFILES

        assert PROFILES["htb"]["dirs"] == [
            "notes", "scans", "web", "creds", "loot",
            "exploits", "screenshots", "reports", "logs",
        ]

    def test_htb_profile_templates_pinned(self) -> None:
        from empusa.workspace import PROFILES

        assert PROFILES["htb"]["templates"] == [
            "engagement.md", "target.md", "recon.md", "services.md",
            "finding.md", "privesc.md", "web.md",
        ]


class TestEventPayloadSchemasPinned:
    """Pin the field set of every workspace/build/report event dataclass.

    If a field is added or removed the test fails, forcing an explicit
    decision about whether downstream consumers need updating.
    """

    @staticmethod
    def _field_names(cls: type) -> set[str]:
        return {f.name for f in dc_fields(cls)}

    def test_pre_workspace_init_fields(self) -> None:
        expected = {"event", "timestamp", "session_env",
                    "workspace_name", "workspace_root", "profile", "set_active"}
        assert self._field_names(PreWorkspaceInitEvent) == expected

    def test_post_workspace_init_fields(self) -> None:
        expected = {"event", "timestamp", "session_env",
                    "workspace_name", "workspace_root", "workspace_path",
                    "profile", "set_active", "created_paths"}
        assert self._field_names(PostWorkspaceInitEvent) == expected

    def test_workspace_select_fields(self) -> None:
        expected = {"event", "timestamp", "session_env",
                    "workspace_name", "workspace_root", "workspace_path", "profile"}
        assert self._field_names(WorkspaceSelectEvent) == expected

    def test_pre_build_fields(self) -> None:
        expected = {"event", "timestamp", "session_env",
                    "env_name", "ips"}
        assert self._field_names(PreBuildEvent) == expected

    def test_post_build_fields(self) -> None:
        expected = {"event", "timestamp", "session_env",
                    "env_name", "env_path", "ips"}
        assert self._field_names(PostBuildEvent) == expected

    def test_pre_report_write_fields(self) -> None:
        expected = {"event", "timestamp", "session_env",
                    "env_name", "env_path", "standalone_count", "ad_count"}
        assert self._field_names(PreReportWriteEvent) == expected

    def test_report_generated_fields(self) -> None:
        expected = {"event", "timestamp", "session_env",
                    "report_path", "env_name", "env_path",
                    "standalone_count", "ad_count"}
        assert self._field_names(ReportGeneratedEvent) == expected

    def test_post_scan_fields_pinned(self) -> None:
        expected = {"event", "timestamp", "session_env",
                    "ip", "scan_output", "os_type", "ports_dir"}
        assert self._field_names(PostScanEvent) == expected

    def test_loot_added_fields_pinned(self) -> None:
        expected = {"event", "timestamp", "session_env",
                    "host", "cred_type", "username", "secret",
                    "source", "env_name", "env_path"}
        assert self._field_names(LootAddedEvent) == expected
