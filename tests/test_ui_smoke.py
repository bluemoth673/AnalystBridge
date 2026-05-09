"""UI smoke test — instantiates MainWindow under the offscreen Qt platform
and runs Load Demo. Catches import-time errors, signal mis-wiring, and
rendering exceptions without needing a display."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def test_main_window_loads_demo_bundle(qapp):
    from analystbridge.main_window import MainWindow

    w = MainWindow()
    w.on_load_demo()

    assert w._bundle is not None
    assert w._bundle.result.score.score >= 75
    assert "invoice_may_2026.exe" in w.sample_label.text()
    # Stat strip should reflect ingested counts
    assert int(w.dashboard_page.stat_events.value_label.text()) >= 20
    assert int(w.dashboard_page.stat_techniques.value_label.text()) >= 5


def test_node_click_updates_right_panel(qapp):
    from analystbridge.main_window import MainWindow

    w = MainWindow()
    w.on_load_demo()
    # Pick any node and simulate selection through the same path the graph uses
    any_node = next(iter(w._bundle.graph.nodes))
    w.on_node_clicked(any_node)
    # Node title gets updated to the node label (or id)
    assert w.right_panel.node_title.text()


def test_nav_switches_central_view(qapp):
    from analystbridge.main_window import MainWindow

    w = MainWindow()
    w.on_load_demo()
    w.on_nav("Graph")
    assert w.center_stack.currentIndex() == 1
    w.on_nav("Dashboard")
    assert w.center_stack.currentIndex() == 0
    w.on_nav("About")
    # About is now index 4 (Dashboard, Graph, Reports, Settings, About)
    assert w.center_stack.currentWidget() is w.about_page
    w.on_nav("Reports")
    assert w.center_stack.currentWidget() is w.reports_page
    w.on_nav("Settings")
    assert w.center_stack.currentWidget() is w.settings_page


def test_sidebar_type_filters_narrow_dashboard(qapp):
    from analystbridge.main_window import MainWindow

    w = MainWindow()
    w.on_load_demo()
    total = len(w.dashboard_page.events_table._all_events)
    w.on_nav("Network")
    assert w.center_stack.currentWidget() is w.dashboard_page
    assert w.dashboard_page.type_combo.currentText() == "network"
    assert 0 < w.dashboard_page.events_table.rowCount() < total

    w.on_nav("Processes")
    assert w.dashboard_page.type_combo.currentText() == "process"


def test_sidebar_mitre_indicators_open_full_pages(qapp):
    from analystbridge.main_window import MainWindow

    w = MainWindow()
    w.on_load_demo()

    # MITRE ATT&CK → full table view with rows for every mapping
    w.on_nav("MITRE ATT&CK")
    assert w.center_stack.currentWidget() is w.mitre_page
    assert w.mitre_page.table.rowCount() == len(w._bundle.result.mappings) >= 5

    # Indicators → full table view with rows for every IOC
    w.on_nav("Indicators")
    assert w.center_stack.currentWidget() is w.indicators_page
    assert w.indicators_page.table.rowCount() == len(w._bundle.result.iocs) > 0


def test_sidebar_compare_page(qapp):
    from analystbridge.main_window import MainWindow

    w = MainWindow()
    w.on_load_demo()
    w.on_nav("Compare")
    assert w.center_stack.currentWidget() is w.compare_page
    # With only one sample loaded, history is empty.
    assert "0 prior samples" in w.compare_page.history_label.text()
    assert w.compare_page.table.rowCount() == 0
    # The table is explicitly hidden when there's nothing to compare against.
    assert w.compare_page.table.isHidden()


def test_load_sample_dialog_function_paths(qapp):
    """Bypass the QFileDialog and exercise the path-loading code path directly."""
    from analystbridge.main_window import MainWindow
    from analystbridge.ui.services import default_demo_path

    w = MainWindow()
    w._load_path(default_demo_path(), source_label="test")
    assert w._bundle is not None
    # Loading the same demo again replaces the fingerprint, doesn't duplicate.
    w._load_path(default_demo_path(), source_label="test-2")
    assert len(w._sample_memory) == 1


def test_about_page_lists_team_members(qapp):
    from analystbridge.ui.about_page import AboutPage, SUPERVISOR, TEAM_MEMBERS

    page = AboutPage()
    text = _collect_visible_text(page)
    for name in TEAM_MEMBERS:
        assert name in text, f"missing team member {name!r}"
    assert SUPERVISOR in text


def test_timeline_cutoff_hides_future_edges(qapp):
    from analystbridge.main_window import MainWindow

    w = MainWindow()
    w.on_load_demo()
    # Pick a cutoff just above the earliest event
    sorted_ts = sorted(e.ts for e in w._bundle.events)
    early = sorted_ts[0] + 0.1
    max_ts = sorted_ts[-1]

    w.on_time_changed(early)
    visible_edges = sum(1 for e in w.graph_view._edges if e.isVisible())
    assert visible_edges < len(w.graph_view._edges), (
        "cutoff did not hide any edges"
    )

    # Restoring to max_ts (treated as full reveal) shows everything again
    w.on_time_changed(max_ts)
    assert all(e.isVisible() for e in w.graph_view._edges)


def test_storyline_click_highlights_graph(qapp):
    from analystbridge.main_window import MainWindow

    w = MainWindow()
    w.on_load_demo()
    stages = w._bundle.result.storyline
    target = next((s for s in stages if s.supporting_event_ids), None)
    assert target is not None, "demo bundle should have at least one storyline stage"
    w.on_stage_selected(list(target.supporting_event_ids))

    highlighted = [e for e in w.graph_view._edges if e._highlighted]
    assert highlighted, "expected at least one edge highlighted after stage click"

    # Clearing restores everything
    w.on_stage_selected([])
    assert not any(e._highlighted for e in w.graph_view._edges)


def test_swimlane_layout_assigns_nodes_to_lanes(qapp):
    """Phase 10: every node lands in the lane its kind belongs to.

    Lane is decided by Y-bucket — Y is divided into 4 horizontal bands of
    LANE_H pixels each starting after the time-ruler header. A correctly-laid
    node falls in the band matching ``ZONE_BY_KIND``.
    """
    from analystbridge.main_window import MainWindow
    from analystbridge.ui.swimlane_view import HEADER_H, LANE_H, ZONE_BY_KIND

    w = MainWindow()
    w.on_load_demo()

    canvas = w.graph_view.canvas
    assert canvas._current_layout is not None
    layout = canvas._current_layout

    def lane_from_y(y: float) -> int:
        """Convert a node's Y to its 1-based lane index."""
        return int((y - HEADER_H) // LANE_H) + 1

    detections_in_lane_4 = 0
    misplaced: list[tuple[str, str, int, int]] = []
    for nid, (x, y) in layout.positions.items():
        kind = w._bundle.graph.nodes[nid].get("kind", "")
        expected = ZONE_BY_KIND.get(kind, 3)
        actual = lane_from_y(y)
        if abs(actual - expected) > 0:
            misplaced.append((nid, kind, expected, actual))
        if expected == 4:
            detections_in_lane_4 += 1

    assert not misplaced, f"nodes outside their lane: {misplaced[:5]}"
    # Demo includes YARA hits → at least one detection in the bottom lane.
    assert detections_in_lane_4 >= 1


def test_swimlane_renders_evidence_lines_for_yara(qapp):
    """Each YARA detection should drop a dashed line up to the file/process it fired on."""
    from analystbridge.main_window import MainWindow

    w = MainWindow()
    w.on_load_demo()
    canvas = w.graph_view.canvas
    assert len(canvas._evidence) >= 1, (
        "expected at least one detection-to-target evidence line on the demo"
    )


def test_right_panel_has_phase7_tabs(qapp):
    from analystbridge.main_window import MainWindow

    w = MainWindow()
    w.on_load_demo()
    tab_titles = [w.right_panel.tabs.tabText(i) for i in range(w.right_panel.tabs.count())]
    assert "AI Insights" in tab_titles
    assert "Notes" in tab_titles


def test_ai_insights_renders_preview_content(qapp):
    from analystbridge.main_window import MainWindow

    w = MainWindow()
    w.on_load_demo()
    # The preview banner should mention "AI Preview" since no model is connected
    assert "Preview" in w.right_panel._ai_banner.text()
    # And the content layout should have several cards (executive, containment, ...)
    assert w.right_panel._ai_content_layout.count() >= 3


def test_notes_save_and_reload(qapp, tmp_path):
    from analystbridge.notes import NotesStore
    from analystbridge.ai import LLMAssistEngine
    from analystbridge.ui.right_panel import RightPanel
    from analystbridge.ui.services import default_demo_path, load_bundle_from_json

    bundle = load_bundle_from_json(default_demo_path())
    panel = RightPanel(llm_engine=LLMAssistEngine(), notes_store=NotesStore(root=tmp_path))
    panel.set_bundle(bundle)

    panel.notes_edit.setPlainText("triage in progress")
    panel._save_notes()

    # Re-open with a fresh panel; notes must persist via sidecar file
    panel2 = RightPanel(llm_engine=LLMAssistEngine(), notes_store=NotesStore(root=tmp_path))
    panel2.set_bundle(bundle)
    assert "triage in progress" in panel2.notes_edit.toPlainText()


def test_dashboard_filter_narrows_results(qapp):
    from analystbridge.main_window import MainWindow

    w = MainWindow()
    w.on_load_demo()
    table = w.dashboard_page.events_table
    total = len(table._all_events)
    assert total >= 20

    w.dashboard_page.type_combo.setCurrentText("network")
    visible_after_type = table.rowCount()
    assert 0 < visible_after_type < total

    w.dashboard_page.type_combo.setCurrentText("All")
    w.dashboard_page.search_edit.setText("powershell")
    visible_after_search = table.rowCount()
    assert 0 < visible_after_search < total

    w.dashboard_page._on_clear_filter()
    assert table.rowCount() == total


def test_export_dialog_default_selection(qapp):
    from analystbridge.exports.action_pack import ARTIFACTS
    from analystbridge.ui.export_dialog import ExportDialog

    dlg = ExportDialog(default_out_dir="exports")
    sel = dlg.selection()
    assert set(sel.selected) == set(ARTIFACTS)
    # AI checkbox is disabled by default (no local model)
    assert dlg.ai_checkbox.isEnabled() is False
    assert sel.use_ai is False


def test_about_page_roadmap_mentions_gemma(qapp):
    from analystbridge.ui.about_page import AboutPage
    from PySide6.QtWidgets import QLabel

    page = AboutPage()
    text = "\n".join(child.text() for child in page.findChildren(QLabel))
    assert "Gemma" in text
    assert "ROADMAP" in text or "Roadmap" in text


def _collect_visible_text(widget) -> str:
    """Recursively gather text from QLabel children for assertion convenience."""
    from PySide6.QtWidgets import QLabel

    parts: list[str] = []
    for child in widget.findChildren(QLabel):
        parts.append(child.text())
    return "\n".join(parts)
