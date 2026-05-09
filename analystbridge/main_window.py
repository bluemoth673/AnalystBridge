"""Main AnalystBridge window — orchestrates all UI panels and engine wiring."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from analystbridge import __version__
from analystbridge.ai import LLMAssistEngine
from analystbridge.core.similarity import SampleFingerprint
from analystbridge.exports.action_pack import export_action_pack
from analystbridge.notes import NotesStore
from analystbridge.ui.about_page import AboutPage
from analystbridge.ui.compare_page import ComparePage
from analystbridge.ui.dashboard_page import DashboardPage
from analystbridge.ui.export_dialog import ExportDialog
from analystbridge.ui.graph_view import GraphView
from analystbridge.ui.icons import get_nav_pixmap
from analystbridge.ui.indicators_page import IndicatorsPage
from analystbridge.ui.mitre_page import MitrePage
from analystbridge.ui.reports_page import ReportsPage
from analystbridge.ui.right_panel import RightPanel
from analystbridge.ui.services import AnalysisBundle, default_demo_path, load_bundle_from_json
from analystbridge.ui.settings_page import SettingsPage
from analystbridge.ui.storyline_panel import StorylinePanel
from analystbridge.ui.theme import C, QSS
from analystbridge.ui.timeline_panel import TimelinePanel
from analystbridge.ui.yara_page import YaraPage

NAV_ITEMS = (
    "Dashboard",
    "Graph",
    "Processes",
    "Network",
    "Files",
    "Registry",
    "YARA",
    "MITRE ATT&CK",
    "Indicators",
    "Compare",
    "Reports",
    "Settings",
    "About",
)


def _slugify(name: str) -> str:
    return name.lower().replace(" ", "_").replace("&", "")


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("AnalystBridge — Malware Visual Intelligence Engine")

        # Auto-size the window relative to the user's primary screen, so the
        # demo lays out sensibly on both a 1366×768 laptop and a 4K external
        # monitor. We aim at ~92 % of the available area, clamped to a
        # comfortable range, and floor to a minimum that still shows the four
        # main columns.
        self._auto_size_to_screen()
        self.setStyleSheet(QSS)
        self._bundle: Optional[AnalysisBundle] = None
        self._nav_buttons: dict[str, QPushButton] = {}

        # Phase 7+: shared services across the panels.
        self._llm = LLMAssistEngine()
        self._notes = NotesStore()

        # Phase 8+: session memory of every fingerprint loaded this session.
        self._sample_memory: list[SampleFingerprint] = []

        self._build_ui()
        self.statusBar().showMessage(
            f"Ready — v{__version__} · click Load Demo or Load Sample… to ingest a report"
        )

    # --- Window-sizing helper --------------------------------------------
    def _auto_size_to_screen(self) -> None:
        """Resize and centre the window based on the primary screen geometry.

        The point: a 13" laptop gets a window that fits, a 27" monitor gets
        a comfortably-large one — neither cramped nor dwarfed. Clamps to a
        sensible range so the layout never breaks.
        """
        screen = QGuiApplication.primaryScreen()
        if screen is None:
            self.resize(1400, 880)
            self.setMinimumSize(1100, 680)
            return

        avail = screen.availableGeometry()
        target_w = max(1100, min(int(avail.width() * 0.92), 1880))
        target_h = max(680,  min(int(avail.height() * 0.92), 1180))

        # Floor: never demand more space than the screen can give.
        target_w = min(target_w, avail.width())
        target_h = min(target_h, avail.height())

        # Minimum size scales down with the screen so a 1280×720 laptop isn't
        # locked out of a working layout.
        min_w = min(1100, max(960, int(avail.width() * 0.78)))
        min_h = min(680,  max(620, int(avail.height() * 0.78)))
        self.setMinimumSize(min_w, min_h)
        self.resize(target_w, target_h)

        # Centre on the screen.
        frame = self.frameGeometry()
        frame.moveCenter(avail.center())
        self.move(frame.topLeft())

    # --- UI construction --------------------------------------------------
    def _build_ui(self) -> None:
        central = QWidget(self)
        # Surface = elevated panel tint so the gaps between cards read navy
        # instead of pure-black. Cards still pop because BG_CARD is brighter.
        central.setObjectName("Surface")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 8)
        root.setSpacing(10)

        root.addWidget(self._build_topbar())

        # Main split: sidebar | center | right (right panel resizable).
        self._splitter = QSplitter(Qt.Orientation.Horizontal)
        self._splitter.setHandleWidth(6)
        self._splitter.setChildrenCollapsible(False)
        self._splitter.addWidget(self._build_sidebar())
        self._splitter.addWidget(self._build_center())
        self._splitter.addWidget(self._build_right())
        self._splitter.setStretchFactor(0, 0)   # sidebar: fixed-ish
        self._splitter.setStretchFactor(1, 1)   # center: grows
        self._splitter.setStretchFactor(2, 0)   # right: only if space
        self._splitter.setSizes([220, 1000, 400])
        root.addWidget(self._splitter, 1)

        # Bottom-row Attack Storyline strip.
        self.storyline_panel = StorylinePanel()
        self.storyline_panel.setMinimumHeight(160)
        self.storyline_panel.setMaximumHeight(220)
        self.storyline_panel.stage_selected.connect(self.on_stage_selected)
        root.addWidget(self.storyline_panel)

    def _build_topbar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("TopBar")
        bar.setMinimumHeight(64)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 8, 16, 8)
        layout.setSpacing(14)

        title_box = QWidget()
        tl = QVBoxLayout(title_box)
        tl.setContentsMargins(0, 0, 0, 0)
        tl.setSpacing(0)
        title = QLabel("AnalystBridge")
        title.setObjectName("Title")
        sub = QLabel("Visualize. Investigate. Respond.")
        sub.setObjectName("Subtitle")
        tl.addWidget(title)
        tl.addWidget(sub)
        layout.addWidget(title_box)

        # Status pill — "Live" / "Replaying"
        self.status_pill = QLabel("●  Idle")
        self.status_pill.setStyleSheet(
            f"background:{C.BG_PANEL_2}; color:{C.TEXT_DIM};"
            f"border:1px solid {C.BORDER}; border-radius:11px; padding:4px 10px;"
        )
        layout.addWidget(self.status_pill)

        layout.addStretch()

        self.sample_label = QLabel("No sample loaded")
        self.sample_label.setObjectName("Dim")
        layout.addWidget(self.sample_label)

        # Refresh / Fit View
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setToolTip("Re-run analysis on the loaded sample")
        self.refresh_btn.clicked.connect(self.on_refresh)
        layout.addWidget(self.refresh_btn)

        self.fit_btn = QPushButton("Fit View")
        self.fit_btn.setToolTip("Fit the behaviour graph to the viewport")
        self.fit_btn.clicked.connect(self.on_fit_view)
        layout.addWidget(self.fit_btn)

        # Load buttons
        self.load_demo_btn = QPushButton("Load Demo")
        self.load_demo_btn.setToolTip("Load the bundled ransomware demo sample")
        self.load_demo_btn.clicked.connect(self.on_load_demo)
        layout.addWidget(self.load_demo_btn)

        self.load_sample_btn = QPushButton("Load Sample…")
        self.load_sample_btn.setObjectName("Primary")
        self.load_sample_btn.setToolTip(
            "Open a CAPE / Cuckoo / Sysmon / AnalystBridge JSON report"
        )
        self.load_sample_btn.clicked.connect(self.on_load_sample)
        layout.addWidget(self.load_sample_btn)

        self.export_btn = QPushButton("Generate SOC Action Pack")
        self.export_btn.clicked.connect(self.on_export)
        layout.addWidget(self.export_btn)

        return bar

    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setMinimumWidth(210)
        sidebar.setMaximumWidth(260)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(8, 12, 8, 12)
        layout.setSpacing(2)

        for item in NAV_ITEMS:
            btn = QPushButton(f"  {item}")
            btn.setObjectName("NavItem")
            btn.setCheckable(True)
            btn.setIconSize(QSize(18, 18))
            pix = get_nav_pixmap(item, size=18)
            if pix is not None and not pix.isNull():
                btn.setIcon(QIcon(pix))
            btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            if item == "Dashboard":
                btn.setChecked(True)
            btn.clicked.connect(lambda _checked, name=item: self.on_nav(name))
            self._nav_buttons[item] = btn
            layout.addWidget(btn)

        layout.addStretch()

        version = QLabel(f"v{__version__}")
        version.setObjectName("Muted")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(version)

        return sidebar

    def _build_center(self) -> QWidget:
        center = QWidget()
        layout = QVBoxLayout(center)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        self.center_stack = QStackedWidget()
        self.dashboard_page = DashboardPage()
        self.graph_view = GraphView()
        self.mitre_page = MitrePage()
        self.indicators_page = IndicatorsPage()
        self.yara_page = YaraPage()
        self.compare_page = ComparePage()
        self.reports_page = ReportsPage(exports_root="exports")
        self.settings_page = SettingsPage(llm_engine=self._llm)
        self.about_page = AboutPage()

        self.graph_view.node_clicked.connect(self.on_node_clicked)
        self.mitre_page.mapping_selected.connect(self.on_evidence_selected)
        self.indicators_page.ioc_selected.connect(self.on_evidence_selected)

        # Keep the order in self._page_index in sync with _add order.
        self._page_widgets = {
            "Dashboard": self.dashboard_page,
            "Graph": self.graph_view,
            "MITRE ATT&CK": self.mitre_page,
            "Indicators": self.indicators_page,
            "YARA": self.yara_page,
            "Compare": self.compare_page,
            "Reports": self.reports_page,
            "Settings": self.settings_page,
            "About": self.about_page,
        }
        for w in self._page_widgets.values():
            self.center_stack.addWidget(w)
        layout.addWidget(self.center_stack, 1)

        self.timeline = TimelinePanel()
        self.timeline.time_changed.connect(self.on_time_changed)
        layout.addWidget(self.timeline)

        return center

    def _build_right(self) -> QWidget:
        # Outer wrapper sits in the splitter and has the Surface tint so the
        # gaps between Node Details / Malice Score / Score Breakdown cards
        # read as navy instead of black voids.
        wrapper = QWidget()
        wrapper.setObjectName("Surface")
        wrapper.setMinimumWidth(360)
        wrapper.setMaximumWidth(620)
        outer_layout = QVBoxLayout(wrapper)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # The right panel itself can be tall; wrap it in a scroll area so
        # Node Details / Malice / Breakdown / Tabs are *always* reachable
        # even on smaller laptop screens.
        from PySide6.QtWidgets import QScrollArea
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setStyleSheet("background: transparent;")
        outer_layout.addWidget(scroll)

        self.right_panel = RightPanel(llm_engine=self._llm, notes_store=self._notes)
        self.right_panel.event_ids_selected.connect(self.on_evidence_selected)
        scroll.setWidget(self.right_panel)
        return wrapper

    # --- Slots ------------------------------------------------------------
    def on_nav(self, name: str) -> None:
        for item, btn in self._nav_buttons.items():
            btn.setChecked(item == name)

        # Direct page-stack targets
        if name in self._page_widgets:
            self.center_stack.setCurrentWidget(self._page_widgets[name])
            if name == "Dashboard":
                # Always reset the events search/type filter on a Dashboard
                # nav click — the user expects "all events" by default, not
                # whatever filter was left from the Processes/Network/Files
                # type-filter shortcuts.
                self.dashboard_page.reset_filter()
            elif name == "Reports":
                self.reports_page.refresh()
            elif name == "Compare":
                self._refresh_compare_page()
            self.statusBar().showMessage(f"View: {name}")
            return

        # Type-filter shortcuts that just narrow the dashboard event table.
        # ("YARA" is no longer a filter — it has its own full Rules page.)
        type_filters = {
            "Processes": "process",
            "Network": "network",
            "Files": "file",
            "Registry": "registry",
        }
        if name in type_filters:
            kind = type_filters[name]
            self.center_stack.setCurrentWidget(self.dashboard_page)
            self.dashboard_page.search_edit.clear()
            self.dashboard_page.type_combo.setCurrentText(kind)
            self.statusBar().showMessage(f"Filtered events to type = {kind}")
            return

        self.center_stack.setCurrentWidget(self.dashboard_page)

    def on_load_demo(self) -> None:
        self._load_path(default_demo_path(), source_label="bundled demo")

    def on_load_sample(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Open sandbox report",
            "",
            "Sandbox reports (*.json);;All files (*)",
        )
        if not path_str:
            return
        self._load_path(Path(path_str), source_label=Path(path_str).name)

    def _load_path(self, path: Path, source_label: str) -> None:
        try:
            bundle = load_bundle_from_json(path)
        except Exception as exc:  # noqa: BLE001
            self.statusBar().showMessage(f"Load failed: {exc}")
            QMessageBox.critical(
                self,
                "Load failed",
                f"Could not parse {path.name}:\n{exc}",
            )
            return
        self._apply_bundle(bundle, source_label=source_label)

    def on_refresh(self) -> None:
        if self._bundle is None:
            self.on_load_demo()
            return
        self.on_load_demo()
        self.statusBar().showMessage("Re-ran analysis on the current sample.")

    def on_fit_view(self) -> None:
        self.graph_view.fit_view()
        self.on_nav("Graph")

    def on_export(self) -> None:
        if self._bundle is None:
            self.statusBar().showMessage("Load a sample first.")
            QMessageBox.warning(
                self, "Generate SOC Action Pack",
                "Click Load Demo or Load Sample… first to ingest a sample.",
            )
            return

        dialog = ExportDialog(default_out_dir="exports", llm_engine=self._llm, parent=self)
        if dialog.exec() != ExportDialog.DialogCode.Accepted:
            self.statusBar().showMessage("Export cancelled.")
            return

        sel = dialog.selection()
        if not sel.selected:
            QMessageBox.warning(
                self, "Generate SOC Action Pack",
                "No artifacts selected — pick at least one file to write.",
            )
            return

        try:
            manifest = export_action_pack(
                self._bundle,
                exports_root=sel.out_dir,
                selected=sel.selected,
            )
        except Exception as exc:  # noqa: BLE001
            self.statusBar().showMessage(f"Export failed: {exc}")
            QMessageBox.critical(self, "Export failed", str(exc))
            return

        files = "\n".join(f"  - {p.name}" for p in manifest.files)
        ai_note = (
            "\n\nAI-enhanced summary requested — falling back to deterministic "
            "preview (local model not yet connected)."
            if sel.use_ai else ""
        )
        QMessageBox.information(
            self,
            "SOC Action Pack",
            f"Wrote {len(manifest.files)} files to:\n{manifest.out_dir}\n\n{files}{ai_note}",
        )
        self.statusBar().showMessage(
            f"Exported {len(manifest.files)} files to {manifest.out_dir}"
        )

    def on_node_clicked(self, node_id: str) -> None:
        if self._bundle is None:
            return
        self.right_panel.show_node(node_id, self._bundle.graph)
        self.statusBar().showMessage(f"Selected: {node_id}")

    def on_time_changed(self, ts: float) -> None:
        if self._bundle is None:
            return
        max_ts = max((e.ts for e in self._bundle.events), default=0.0)
        cutoff = None if ts >= max_ts - 1e-6 else ts
        self.graph_view.set_cutoff(cutoff)
        if cutoff is None:
            self._set_status_pill("●  Live", C.SUCCESS)
        else:
            self._set_status_pill(f"●  Replay  {ts:.2f}s", C.WARNING)

    def on_stage_selected(self, event_ids: list[int]) -> None:
        self.graph_view.highlight_event_ids(event_ids)
        if event_ids:
            self.on_nav("Graph")
            self.statusBar().showMessage(
                f"Highlighting storyline stage — {len(event_ids)} supporting events"
            )
        else:
            self.statusBar().showMessage("Cleared storyline highlight.")

    def on_evidence_selected(self, event_ids: list[int]) -> None:
        self.graph_view.highlight_event_ids(event_ids)
        if event_ids:
            self.on_nav("Graph")
            self.statusBar().showMessage(
                f"Highlighting {len(event_ids)} related events on graph"
            )

    # --- Internal helpers -------------------------------------------------
    def _apply_bundle(self, bundle: AnalysisBundle, source_label: str = "") -> None:
        self._bundle = bundle
        sample = bundle.sample
        self.sample_label.setText(
            f"Sample: {sample.get('filename', '--')}   ·   "
            f"Platform: {sample.get('platform', '--')}"
            + (f"   ·   Source: {sample.get('sandbox_source', '?')}" if sample.get('sandbox_source') else "")
        )
        self.dashboard_page.set_bundle(bundle)
        self.graph_view.set_graph(bundle.graph, mappings=bundle.result.mappings)
        self.right_panel.set_bundle(bundle)
        self.mitre_page.set_bundle(bundle)
        self.indicators_page.set_bundle(bundle)
        self.yara_page.set_bundle(bundle)
        self.storyline_panel.set_storyline(bundle.result.storyline)
        self.timeline.set_events(bundle.events)

        # Update session memory for the Compare page
        fp = SampleFingerprint.from_result(
            sample.get("sample_id") or "unknown",
            sample.get("filename") or "sample",
            bundle.result,
        )
        # Replace any prior fingerprint with the same sample_id, otherwise append.
        self._sample_memory = [m for m in self._sample_memory if m.sample_id != fp.sample_id]
        self._sample_memory.append(fp)
        self._refresh_compare_page()

        self._set_status_pill("●  Live", C.SUCCESS)
        self.statusBar().showMessage(
            f"Loaded {sample.get('filename')} ({source_label}) - Malice "
            f"{bundle.result.score.score}/{bundle.result.score.risk_level}, "
            f"{len(bundle.result.mappings)} techniques, "
            f"{len(bundle.result.iocs)} IOCs"
        )

    def _refresh_compare_page(self) -> None:
        if self._bundle is None:
            self.compare_page.update(None, [])
            return
        sid = self._bundle.sample.get("sample_id") or "unknown"
        current = next((m for m in self._sample_memory if m.sample_id == sid), None)
        history = [m for m in self._sample_memory if m.sample_id != sid]
        self.compare_page.update(current, history)

    def _set_status_pill(self, text: str, color: str) -> None:
        self.status_pill.setText(text)
        self.status_pill.setStyleSheet(
            f"background:{C.BG_PANEL_2}; color:{color};"
            f"border:1px solid {color}; border-radius:11px; padding:4px 10px;"
        )
