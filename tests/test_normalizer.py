from analystbridge.core.event_schema import Actor, RawEvent, Target
from analystbridge.ingestion.normalizer import Normalizer


def _normalize(raw: RawEvent):
    return Normalizer().normalize(raw)


def test_process_event_uses_pid_for_node_ids():
    raw = RawEvent(
        timestamp=0.5,
        event_type="process",
        action="spawned_process",
        actor=Actor(pid="100", name="explorer.exe"),
        target=Target(pid="200", name="malware.exe"),
    )
    norm = _normalize(raw)
    assert norm.actor_id == "proc:100"
    assert norm.target_id == "proc:200"
    assert norm.target_type == "process"


def test_network_event_prefers_url_then_domain_then_ip():
    norm_url = _normalize(
        RawEvent(
            timestamp=1.0,
            event_type="network",
            action="http_request",
            actor=Actor(pid="200"),
            target=Target(url="https://x/y", domain="x", remote_ip="1.2.3.4", remote_port=443),
        )
    )
    assert norm_url.target_type == "url"

    norm_domain = _normalize(
        RawEvent(
            timestamp=1.0,
            event_type="network",
            action="connect",
            actor=Actor(pid="200"),
            target=Target(domain="x", remote_ip="1.2.3.4", remote_port=443),
        )
    )
    assert norm_domain.target_type == "domain"

    norm_ip = _normalize(
        RawEvent(
            timestamp=1.0,
            event_type="network",
            action="connect",
            actor=Actor(pid="200"),
            target=Target(remote_ip="1.2.3.4", remote_port=443),
        )
    )
    assert norm_ip.target_type == "ip"
    assert norm_ip.target_id == "ip:1.2.3.4:443"


def test_registry_event_includes_value_name():
    raw = RawEvent(
        timestamp=2.0,
        event_type="registry",
        action="set_value",
        actor=Actor(pid="300", name="reg.exe"),
        target=Target(key=r"HKCU\Software\X", value_name="Updater", value_data="payload.ps1"),
    )
    norm = _normalize(raw)
    assert norm.target_type == "registry"
    assert "Updater" in norm.target_id


def test_normalize_all_demo_events_runs_clean():
    """End-to-end: every demo event should normalize without raising."""
    from pathlib import Path

    from analystbridge.ingestion.json_parser import JsonSandboxParser

    parsed = JsonSandboxParser().parse_file(Path("sample_data/ransomware_demo.json"))
    norm = Normalizer().normalize_all(parsed.events)
    assert len(norm) == len(parsed.events)
    # Every event should have an actor_id (everything in the demo has an actor PID).
    assert all(e.actor_id is not None for e in norm)
