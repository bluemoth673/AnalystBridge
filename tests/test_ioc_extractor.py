from pathlib import Path

import pytest

from analystbridge.core.ioc_extractor import IocExtractor, defang_domain, defang_ip, defang_url
from analystbridge.ingestion.json_parser import JsonSandboxParser
from analystbridge.ingestion.normalizer import Normalizer
from analystbridge.storage import repositories as repo
from analystbridge.storage.database import Database


@pytest.fixture()
def demo_events(tmp_path):
    db = Database(tmp_path / "t.db")
    db.init_schema()
    parsed = JsonSandboxParser().parse_file(Path("sample_data/ransomware_demo.json"))
    norm = Normalizer().normalize_all(parsed.events)
    repo.upsert_sample(db, parsed.sample)
    repo.insert_events(db, parsed.sample.sample_id, norm)
    rows = repo.list_events_for_sample(db, parsed.sample.sample_id)
    db.close()
    return rows


def test_defang_helpers():
    assert defang_domain("cdn.badactor.com") == "cdn[.]badactor[.]com"
    assert defang_ip("193.233.7.23") == "193[.]233[.]7[.]23"
    assert defang_url("https://x.com/y") == "hxxps://x[.]com/y"


def test_demo_extracts_expected_ioc_types(demo_events):
    iocs = IocExtractor().extract(demo_events)
    types = {i.ioc_type for i in iocs}
    assert {"ipv4", "domain", "url", "sha256", "file_path", "registry_key"} <= types


def test_iocs_are_deduplicated(demo_events):
    iocs = IocExtractor().extract(demo_events)
    seen = set()
    for ioc in iocs:
        key = (ioc.ioc_type, ioc.value)
        assert key not in seen, f"duplicate IOC: {key}"
        seen.add(key)


def test_network_iocs_are_defanged_for_display(demo_events):
    iocs = IocExtractor().extract(demo_events)
    domain = next(i for i in iocs if i.ioc_type == "domain" and "badactor" in i.value)
    assert domain.display_value == "cdn[.]badactor[.]com"
    assert domain.value == "cdn.badactor.com"  # raw value preserved for hunting


def test_iocs_track_source_events(demo_events):
    iocs = IocExtractor().extract(demo_events)
    assert all(ioc.source_event_ids for ioc in iocs)
