"""Tests for the YARA generator + the YARA Rules page."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from analystbridge.core.yara_generator import (
    builtin_rules,
    generate_rules_for_bundle,
)
from analystbridge.ui.services import default_demo_path, load_bundle_from_json

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture(scope="module")
def bundle():
    return load_bundle_from_json(default_demo_path())


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


def test_builtin_rules_are_well_formed():
    rules = builtin_rules()
    assert len(rules) >= 5

    expected_names = {
        "AB_Suspicious_PowerShell_Downloader",
        "AB_Mshta_Proxy_Execution",
        "AB_Inhibit_System_Recovery",
        "AB_Run_Key_Persistence",
        "AB_Generic_Ransom_Note",
    }
    actual = {r.name for r in rules}
    assert expected_names <= actual

    for r in rules:
        assert r.body.startswith("rule "), f"{r.name} body missing 'rule' header"
        assert "condition:" in r.body
        assert "{" in r.body and "}" in r.body
        assert r.source == "builtin"


def test_generate_rules_for_bundle_emits_hash_rule(bundle):
    rules = generate_rules_for_bundle(bundle)
    sha_rules = [r for r in rules if "SHA256" in r.name]
    assert sha_rules, "expected at least one hash rule for the demo sample"
    body = sha_rules[0].body
    assert "hash.sha256" in body
    assert sha_rules[0].source == "generated"


def test_generate_rules_for_bundle_emits_network_rule(bundle):
    rules = generate_rules_for_bundle(bundle)
    net_rules = [r for r in rules if "Network_IOCs" in r.name]
    assert len(net_rules) == 1
    body = net_rules[0].body
    assert "cdn.badactor.com" in body
    assert "any of them" in body


def test_generate_rules_for_bundle_emits_ransomware_rule(bundle):
    """Demo drops .locked files → expect the encryption-pattern rule."""
    rules = generate_rules_for_bundle(bundle)
    enc_rules = [r for r in rules if "Encryption_Pattern" in r.name]
    assert enc_rules, "expected encryption-pattern rule for the ransomware demo"


def test_generate_rules_for_bundle_is_deterministic(bundle):
    a = generate_rules_for_bundle(bundle)
    b = generate_rules_for_bundle(bundle)
    assert [r.name for r in a] == [r.name for r in b]
    assert [r.body for r in a] == [r.body for r in b]


# ---------------------------------------------------------------------------
# YARA page
# ---------------------------------------------------------------------------


def test_yara_page_populates_both_tabs(qapp, bundle):
    from analystbridge.ui.yara_page import YaraPage

    page = YaraPage()
    page.set_bundle(bundle)
    assert "built-in" in page.builtin_counter.text().lower()
    assert "generated" in page.generated_counter.text().lower()
    assert page._builtin
    assert page._generated


def test_yara_page_main_window_routing(qapp):
    """Phase 11: clicking the YARA sidebar nav opens the full Rules page."""
    from analystbridge.main_window import MainWindow

    w = MainWindow()
    w.on_load_demo()
    w.on_nav("YARA")
    assert w.center_stack.currentWidget() is w.yara_page
    # Demo always produces at least the built-in rules.
    assert len(w.yara_page._builtin) >= 5
    # And the generated tab is populated for the demo.
    assert len(w.yara_page._generated) >= 1
