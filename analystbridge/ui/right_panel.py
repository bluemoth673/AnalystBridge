"""Right-hand panel: Node Details + Malice Score gauge + Score Breakdown +
tabbed evidence (MITRE ATT&CK / Indicators / API Calls / YARA Hits / Raw
Events / AI Insights / Notes).

Each clickable list emits `event_ids_selected(list[int])` so the graph can
highlight the matching nodes/edges. The Notes tab persists per-sample to a
sidecar Markdown file via `NotesStore`.
"""
from __future__ import annotations

import networkx as nx
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QClipboard, QGuiApplication, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from analystbridge.ai import AISummary, LLMAssistEngine
from analystbridge.core.event_row import EventRow
from analystbridge.core.mitre_mapper import MitreMapping
from analystbridge.notes import NotesStore
from analystbridge.ui.icons import get_kind_pixmap
from analystbridge.ui.services import AnalysisBundle
from analystbridge.ui.theme import C, kind_color
from analystbridge.ui.widgets import MaliceScoreGauge


class _Section(QFrame):
    def __init__(self, title: str, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(14, 12, 14, 12)
        self._layout.setSpacing(6)
        self._title = QLabel(title.upper())
        self._title.setObjectName("H3")
        self._layout.addWidget(self._title)

    def add(self, widget: QWidget) -> None:
        self._layout.addWidget(widget)


class RightPanel(QWidget):
    event_ids_selected = Signal(list)

    def __init__(
        self,
        llm_engine: LLMAssistEngine | None = None,
        notes_store: NotesStore | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._llm = llm_engine or LLMAssistEngine()
        self._notes = notes_store or NotesStore()
        self._current_sample_id: str | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        # Node Details — redesigned card with icon header + key-value grid.
        self.node_section = self._build_node_details_section()
        layout.addWidget(self.node_section)

        # Malice Score
        score_section = _Section("Malice Score")
        self.gauge = MaliceScoreGauge()
        score_section.add(self.gauge)
        layout.addWidget(score_section)

        # Score Breakdown — custom widget with red contribution numbers.
        breakdown_section = _Section("Score Breakdown")
        breakdown_scroll = QScrollArea()
        breakdown_scroll.setWidgetResizable(True)
        breakdown_scroll.setFrameShape(QFrame.Shape.NoFrame)
        breakdown_scroll.setStyleSheet("background: transparent;")
        self._breakdown_body = QWidget()
        self._breakdown_layout = QVBoxLayout(self._breakdown_body)
        self._breakdown_layout.setContentsMargins(0, 0, 0, 0)
        self._breakdown_layout.setSpacing(4)
        self._breakdown_layout.addStretch()
        breakdown_scroll.setWidget(self._breakdown_body)
        breakdown_section.add(breakdown_scroll)
        layout.addWidget(breakdown_section, 1)

        # Tabs: MITRE ATT&CK / Indicators / API / YARA / Raw / AI / Notes
        self.tabs = QTabWidget()
        self.mitre_list = QListWidget()
        self.iocs_list = QListWidget()
        self.api_list = QListWidget()
        self.yara_list = QListWidget()
        self.raw_list = QListWidget()
        for w in (self.mitre_list, self.iocs_list, self.api_list, self.yara_list, self.raw_list):
            w.setStyleSheet(
                f"QListWidget{{ background: {C.BG_PANEL}; border: 1px solid {C.BORDER};"
                "border-radius: 6px; }"
            )
        self.ai_tab = self._build_ai_tab()
        self.notes_tab = self._build_notes_tab()
        self.tabs.addTab(self.mitre_list, "MITRE ATT&CK")
        self.tabs.addTab(self.iocs_list, "Indicators")
        self.tabs.addTab(self.api_list, "API Calls")
        self.tabs.addTab(self.yara_list, "YARA Hits")
        self.tabs.addTab(self.raw_list, "Raw Events")
        self.tabs.addTab(self.ai_tab, "AI Insights")
        self.tabs.addTab(self.notes_tab, "Notes")
        layout.addWidget(self.tabs, 2)

        # Click → event highlight
        self.mitre_list.itemClicked.connect(self._emit_mitre)
        self.iocs_list.itemClicked.connect(self._emit_ioc)
        self.api_list.itemClicked.connect(self._emit_event)
        self.yara_list.itemClicked.connect(self._emit_event)
        self.raw_list.itemClicked.connect(self._emit_event)

    # ------------------------------------------------------------------
    # Node Details card — icon header + selectable key-value grid
    # ------------------------------------------------------------------

    def _build_node_details_section(self) -> QFrame:
        section = QFrame()
        section.setObjectName("Card")
        v = QVBoxLayout(section)
        v.setContentsMargins(14, 12, 14, 12)
        v.setSpacing(10)

        # Section title strip
        head_row = QHBoxLayout()
        title = QLabel("NODE DETAILS")
        title.setObjectName("H3")
        head_row.addWidget(title)
        head_row.addStretch()

        self.node_badge = QLabel("")
        self.node_badge.setVisible(False)
        head_row.addWidget(self.node_badge)
        v.addLayout(head_row)

        # Icon + filename row
        icon_row = QHBoxLayout()
        icon_row.setSpacing(10)

        self._node_icon = QLabel()
        self._node_icon.setFixedSize(40, 40)
        self._node_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_row.addWidget(self._node_icon, 0, Qt.AlignmentFlag.AlignTop)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        self.node_title = QLabel("—")
        self.node_title.setStyleSheet(
            f"color:{C.TEXT}; font-size:14px; font-weight:700;"
        )
        self.node_title.setWordWrap(True)
        self.node_title.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.node_subtitle = QLabel("Click a node on the graph to see its details.")
        self.node_subtitle.setStyleSheet(f"color:{C.TEXT_DIM}; font-size:11px;")
        self.node_subtitle.setWordWrap(True)
        self.node_subtitle.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        title_box.addWidget(self.node_title)
        title_box.addWidget(self.node_subtitle)
        icon_row.addLayout(title_box, 1)
        v.addLayout(icon_row)

        # Property grid (host) — populated by show_node
        self._props_host = QWidget()
        self._props_grid = QGridLayout(self._props_host)
        self._props_grid.setContentsMargins(0, 4, 0, 0)
        self._props_grid.setHorizontalSpacing(10)
        self._props_grid.setVerticalSpacing(4)
        self._props_grid.setColumnStretch(0, 0)
        self._props_grid.setColumnStretch(1, 1)
        v.addWidget(self._props_host)

        # Copy-all button (hidden until a node is selected)
        self.copy_node_btn = QPushButton("Copy details")
        self.copy_node_btn.setVisible(False)
        self.copy_node_btn.clicked.connect(self._copy_node_details)
        copy_row = QHBoxLayout()
        copy_row.addStretch()
        copy_row.addWidget(self.copy_node_btn)
        v.addLayout(copy_row)

        return section

    # ------------------------------------------------------------------
    # Tab builders
    # ------------------------------------------------------------------

    def _build_ai_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        body = QWidget()
        self._ai_body_layout = QVBoxLayout(body)
        self._ai_body_layout.setContentsMargins(8, 8, 8, 8)
        self._ai_body_layout.setSpacing(10)

        # Status banner
        self._ai_banner = QLabel("AI engine not connected — showing preview content.")
        self._ai_banner.setWordWrap(True)
        self._ai_banner.setStyleSheet(
            f"background:{C.BG_PANEL_2}; color:{C.WARNING};"
            f"border:1px solid {C.WARNING}; border-radius:6px; padding:6px 10px;"
        )
        self._ai_body_layout.addWidget(self._ai_banner)

        # Body container that gets cleared on each render
        self._ai_content = QWidget()
        self._ai_content_layout = QVBoxLayout(self._ai_content)
        self._ai_content_layout.setContentsMargins(0, 0, 0, 0)
        self._ai_content_layout.setSpacing(10)
        self._ai_body_layout.addWidget(self._ai_content)
        self._ai_body_layout.addStretch()

        scroll.setWidget(body)
        return scroll

    def _build_notes_tab(self) -> QWidget:
        wrap = QWidget()
        v = QVBoxLayout(wrap)
        v.setContentsMargins(8, 8, 8, 8)
        v.setSpacing(8)

        hint = QLabel(
            "Case notes are saved automatically to "
            "<code>notes/&lt;sample_id&gt;.md</code> and persist across sessions."
        )
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {C.TEXT_DIM};")
        v.addWidget(hint)

        self.notes_edit = QTextEdit()
        self.notes_edit.setPlaceholderText(
            "Triage notes, IR decisions, follow-up tasks, hypotheses…"
        )
        self.notes_edit.setStyleSheet(
            f"QTextEdit{{ background: {C.BG_PANEL}; color: {C.TEXT};"
            f"border: 1px solid {C.BORDER}; border-radius: 6px; padding: 8px; }}"
        )
        self.notes_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        v.addWidget(self.notes_edit, 1)

        actions = QHBoxLayout()
        self.notes_status = QLabel("")
        self.notes_status.setObjectName("Muted")
        actions.addWidget(self.notes_status)
        actions.addStretch()

        self.notes_save_btn = QPushButton("Save")
        self.notes_save_btn.setObjectName("Primary")
        self.notes_save_btn.clicked.connect(self._save_notes)
        actions.addWidget(self.notes_save_btn)
        v.addLayout(actions)

        return wrap

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_bundle(self, bundle: AnalysisBundle) -> None:
        sample = bundle.sample
        self._current_sample_id = sample.get("sample_id")
        self.node_title.setText(sample.get("filename") or "--")
        sha = sample.get("sha256") or "?"
        self.node_subtitle.setText(
            f"sha256: {sha}\nplatform: {sample.get('platform') or '?'}\n"
            f"sandbox: {sample.get('sandbox_source') or '?'}"
        )

        # Malice
        self.gauge.set_score(bundle.result.score.score, bundle.result.score.risk_level)

        # Breakdown — render as red-numbered rows
        self._populate_breakdown(bundle.result.score.contributions)

        # MITRE
        self.mitre_list.clear()
        for m in bundle.result.mappings:
            text = (
                f"{m.technique_id}   {m.technique_name}\n"
                f"   tactic: {m.tactic}, confidence: {m.confidence:.0%}"
            )
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, list(m.evidence_event_ids))
            self.mitre_list.addItem(item)

        # IOCs
        self.iocs_list.clear()
        for i in bundle.result.iocs:
            item = QListWidgetItem(f"[{i.ioc_type}]   {i.display_value}")
            item.setData(Qt.ItemDataRole.UserRole, list(i.source_event_ids))
            self.iocs_list.addItem(item)

        # API Calls
        self.api_list.clear()
        api_events = [e for e in bundle.events if e.event_type == "api"]
        for e in api_events:
            api_name = e.target.get("api") or e.action or "?"
            module = e.target.get("module") or ""
            text = f"{e.ts:>6.2f}s   {api_name}"
            if module:
                text += f"   ({module})"
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, [e.event_id])
            self.api_list.addItem(item)
        if not api_events:
            self.api_list.addItem(QListWidgetItem("(no API events captured)"))

        # YARA Hits
        self.yara_list.clear()
        yara_events = [e for e in bundle.events if e.event_type == "yara"]
        for e in yara_events:
            rule = e.target.get("rule") or "?"
            tags = e.target.get("tags") or ""
            text = f"{rule}\n   tags: {tags}" if tags else rule
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, [e.event_id])
            self.yara_list.addItem(item)
        if not yara_events:
            self.yara_list.addItem(QListWidgetItem("(no YARA hits)"))

        # Raw Events
        self.raw_list.clear()
        for e in bundle.events:
            text = f"{e.ts:>6.2f}s  [{e.event_type}]  {e.action or ''}"
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, [e.event_id])
            self.raw_list.addItem(item)

        # AI Insights
        self._render_ai_summary(bundle)

        # Notes — load whatever was saved earlier for this sample
        self._load_notes()

    def show_node(self, node_id: str, graph: nx.MultiDiGraph) -> None:
        if node_id not in graph:
            return
        data = dict(graph.nodes[node_id])
        kind = data.get("kind", "unknown")
        label = (data.get("label") or node_id).strip()

        # Augment the node data with the earliest timestamp from any edge that
        # touches it — that's the analyst's "first-seen" / event timestamp.
        first_seen = self._earliest_ts_for(graph, node_id)
        if first_seen is not None and "first_seen_ts" not in data:
            data["first_seen_ts"] = f"{first_seen:.3f}s"

        # Title / subtitle
        title, sub = _split_node_label(label, kind, data)
        self.node_title.setText(title or node_id)
        self.node_subtitle.setText(sub or kind.upper())

        # Icon
        self._render_node_icon(kind)

        # Severity badge — heuristic: if the kind has high-risk markers, show one.
        self._render_node_badge(kind, data)

        # Property grid
        self._populate_property_grid(node_id, kind, data)

        self.copy_node_btn.setVisible(True)

    @staticmethod
    def _earliest_ts_for(graph: nx.MultiDiGraph, node_id: str) -> float | None:
        ts: list[float] = []
        for _u, _v, edata in graph.in_edges(node_id, data=True):
            if "ts" in edata:
                ts.append(float(edata["ts"]))
        for _u, _v, edata in graph.out_edges(node_id, data=True):
            if "ts" in edata:
                ts.append(float(edata["ts"]))
        return min(ts) if ts else None

    def _render_node_icon(self, kind: str) -> None:
        # Use the same kind icon as the graph; tinted to the kind colour for variety.
        pix = get_kind_pixmap(kind, size=28, tint=kind_color(kind))
        if pix is None or pix.isNull():
            self._node_icon.setText(kind[:2].upper())
            self._node_icon.setStyleSheet(
                f"background:{C.BG_PANEL_2}; color:{kind_color(kind)};"
                f"border:1px solid {kind_color(kind)}; border-radius:8px;"
                f"font-weight:700; font-size:11px;"
            )
            self._node_icon.setPixmap(QPixmap())
        else:
            self._node_icon.setStyleSheet(
                f"background:{C.BG_PANEL_2}; border:1px solid {kind_color(kind)};"
                f"border-radius:8px;"
            )
            self._node_icon.setPixmap(pix)

    def _render_node_badge(self, kind: str, data: dict) -> None:
        text = ""
        color = ""
        if kind == "process":
            cmd = (data.get("command_line") or "").lower()
            if "-enc" in cmd or "downloadstring" in cmd or "-w hidden" in cmd:
                text, color = "SUSPICIOUS", C.SUSPICIOUS
        elif kind in ("ip", "domain", "url"):
            text, color = "EXTERNAL", C.WARNING
        elif kind == "yara":
            text, color = "YARA HIT", C.WARNING
        elif kind == "registry":
            key = (data.get("key") or "").lower()
            if "currentversion\\run" in key:
                text, color = "PERSISTENCE", C.REGISTRY
        elif kind == "file":
            fp = (data.get("file_path") or data.get("path") or "").lower()
            if fp.endswith((".locked", ".encrypted", ".crypt")):
                text, color = "ENCRYPTED", C.SUSPICIOUS

        if text:
            self.node_badge.setText(f"●  {text}")
            self.node_badge.setStyleSheet(
                f"background:{C.BG_PANEL_2}; color:{color};"
                f"border:1px solid {color}; border-radius:8px;"
                f"padding:2px 8px; font-size:10px; font-weight:700;"
            )
            self.node_badge.setVisible(True)
        else:
            self.node_badge.setVisible(False)

    def _populate_property_grid(self, node_id: str, kind: str, data: dict) -> None:
        # Clear all rows
        while self._props_grid.count():
            item = self._props_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Per-kind ordered field list, matching the reference screenshot.
        ordered = _ordered_fields_for_kind(kind, data)

        row = 0
        for label, value in ordered:
            self._props_grid.addWidget(self._prop_label(label), row, 0)
            self._props_grid.addWidget(self._prop_value(value), row, 1)
            row += 1

    def _prop_label(self, text: str) -> QLabel:
        lbl = QLabel(text + ":")
        lbl.setStyleSheet(
            f"color:{C.TEXT_DIM}; font-size:11px; padding:3px 0;"
        )
        lbl.setMinimumWidth(105)
        return lbl

    def _prop_value(self, text: str) -> QLabel:
        val = QLabel(text)
        val.setStyleSheet(
            f"color:{C.TEXT}; font-size:11px; padding:3px 0;"
            f"font-family:'Consolas','Cascadia Mono',monospace;"
        )
        val.setWordWrap(True)
        val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        return val

    def _copy_node_details(self) -> None:
        # Walk the grid pairs and write a tab-separated key/value bundle.
        lines = [self.node_title.text()]
        for row in range(self._props_grid.rowCount()):
            lab_item = self._props_grid.itemAtPosition(row, 0)
            val_item = self._props_grid.itemAtPosition(row, 1)
            if not lab_item or not val_item:
                continue
            lab = lab_item.widget().text() if lab_item.widget() else ""
            val = val_item.widget().text() if val_item.widget() else ""
            if val:
                lines.append(f"{lab} {val}")
        QGuiApplication.clipboard().setText("\n".join(lines), QClipboard.Mode.Clipboard)
        self.copy_node_btn.setText("Copied!")
        from PySide6.QtCore import QTimer
        QTimer.singleShot(1200, lambda: self.copy_node_btn.setText("Copy details"))

    # ------------------------------------------------------------------
    # Click handlers — pull event_ids stored in UserRole
    # ------------------------------------------------------------------

    def _emit_mitre(self, item: QListWidgetItem) -> None:
        evidence = item.data(Qt.ItemDataRole.UserRole) or []
        self.event_ids_selected.emit(list(evidence))

    def _emit_ioc(self, item: QListWidgetItem) -> None:
        evidence = item.data(Qt.ItemDataRole.UserRole) or []
        self.event_ids_selected.emit(list(evidence))

    def _emit_event(self, item: QListWidgetItem) -> None:
        evidence = item.data(Qt.ItemDataRole.UserRole) or []
        self.event_ids_selected.emit(list(evidence))

    # ------------------------------------------------------------------
    # Score breakdown — red contribution numbers
    # ------------------------------------------------------------------

    def _populate_breakdown(self, contributions) -> None:
        # Clear all existing rows except the trailing stretch.
        while self._breakdown_layout.count() > 1:
            item = self._breakdown_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for c in contributions:
            row = QFrame()
            row.setStyleSheet(
                f"background:{C.BG_PANEL_2}; border:1px solid {C.BORDER};"
                f"border-radius:6px; padding:0;"
            )
            rl = QHBoxLayout(row)
            rl.setContentsMargins(10, 6, 10, 6)
            rl.setSpacing(10)

            sign = "+" if c.points >= 0 else ""
            num = QLabel(f"{sign}{c.points}")
            num.setStyleSheet(
                f"color: {C.SUSPICIOUS}; font-weight: 700; font-size: 13px;"
            )
            num.setMinimumWidth(34)
            num.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            rl.addWidget(num)

            reason = QLabel(c.reason)
            reason.setStyleSheet(f"color: {C.TEXT}; font-size: 11px;")
            reason.setWordWrap(True)
            rl.addWidget(reason, 1)

            # Insert above the trailing stretch
            self._breakdown_layout.insertWidget(self._breakdown_layout.count() - 1, row)

    # ------------------------------------------------------------------
    # AI Insights rendering
    # ------------------------------------------------------------------

    def _render_ai_summary(self, bundle: AnalysisBundle) -> None:
        # Clear previous content
        while self._ai_content_layout.count():
            item = self._ai_content_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        summary: AISummary = self._llm.generate_summary(bundle)
        status = self._llm.status()

        # Banner reflects connected state
        if status.available and summary.generated_by_llm:
            self._ai_banner.setText(
                f"● Generated by {summary.model} (offline) — "
                f"confidence {summary.confidence:.0%}"
            )
            self._ai_banner.setStyleSheet(
                f"background:{C.BG_PANEL_2}; color:{C.SUCCESS};"
                f"border:1px solid {C.SUCCESS}; border-radius:6px; padding:6px 10px;"
            )
        else:
            self._ai_banner.setText(
                f"● AI Preview — local model not connected. "
                f"This narrative will be generated by {status.model} (offline) "
                f"once the model adapter ships."
            )
            self._ai_banner.setStyleSheet(
                f"background:{C.BG_PANEL_2}; color:{C.WARNING};"
                f"border:1px solid {C.WARNING}; border-radius:6px; padding:6px 10px;"
            )

        # Executive summary card
        self._ai_content_layout.addWidget(
            self._ai_card("Executive Summary", summary.executive_summary)
        )
        # Containment plan
        self._ai_content_layout.addWidget(
            self._ai_card("Recommended Containment Plan",
                          self._format_bullets(summary.containment_plan))
        )
        # Suggested hunts
        self._ai_content_layout.addWidget(
            self._ai_card("Suggested SIEM Hunts",
                          self._format_bullets(summary.suggested_hunts))
        )
        # Open questions
        self._ai_content_layout.addWidget(
            self._ai_card("Open Questions for the Analyst",
                          self._format_bullets(summary.open_questions))
        )

    @staticmethod
    def _format_bullets(items: list[str]) -> str:
        if not items:
            return "(none)"
        return "\n".join(f"•  {it}" for it in items)

    def _ai_card(self, title: str, body: str) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        card.setStyleSheet(
            f"QFrame#Card {{ background:{C.BG_CARD}; border:1px solid {C.BORDER};"
            f"border-radius:8px; }}"
        )
        v = QVBoxLayout(card)
        v.setContentsMargins(14, 12, 14, 12)
        v.setSpacing(6)

        head = QLabel(title.upper())
        head.setObjectName("H3")
        head.setStyleSheet(f"color: {C.ACCENT_2}; letter-spacing: 0.5px;")
        v.addWidget(head)

        text = QLabel(body)
        text.setWordWrap(True)
        text.setStyleSheet(f"color: {C.TEXT}; line-height: 1.55;")
        text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        v.addWidget(text)
        return card

    # ------------------------------------------------------------------
    # Notes IO
    # ------------------------------------------------------------------

    def _load_notes(self) -> None:
        if not self._current_sample_id:
            self.notes_edit.clear()
            self.notes_status.setText("")
            return
        text = self._notes.load(self._current_sample_id)
        self.notes_edit.blockSignals(True)
        self.notes_edit.setPlainText(text)
        self.notes_edit.blockSignals(False)
        if text.strip():
            self.notes_status.setText(f"Loaded notes for {self._current_sample_id}")
        else:
            self.notes_status.setText("(no notes saved yet)")

    def _save_notes(self) -> None:
        if not self._current_sample_id:
            self.notes_status.setText("Load a sample first.")
            return
        path = self._notes.save(self._current_sample_id, self.notes_edit.toPlainText())
        self.notes_status.setText(f"Saved → {path}")


# ---------------------------------------------------------------------------
# Module helpers — node label parsing + per-kind property ordering
# ---------------------------------------------------------------------------


def _split_node_label(label: str, kind: str, data: dict) -> tuple[str, str]:
    """Pick (title, subtitle) for the Node Details header from a graph node."""
    label = (label or "").strip()
    if kind == "process":
        if "\n" in label:
            top, _, bottom = label.partition("\n")
            return top, bottom
        pid = data.get("pid")
        return label, f"PID: {pid}" if pid else "PROCESS"
    if kind == "file":
        if "\\" in label or "/" in label:
            sep = "\\" if "\\" in label else "/"
            base = label.rsplit(sep, 1)[-1]
            return base, "FILE"
        return label or "(unnamed file)", "FILE"
    if kind == "registry":
        return (label.split("\\")[0] if label else "REGISTRY"), "REGISTRY"
    if kind in ("domain", "url", "ip"):
        return label or kind.upper(), f"{kind.upper()}  ·  443 / HTTPS"
    return label or kind.upper(), kind.upper()


def _ordered_fields_for_kind(kind: str, data: dict) -> list[tuple[str, str]]:
    """Return key-value pairs in the order matching the reference mockup."""
    rows: list[tuple[str, str]] = []

    def take(label: str, *keys: str) -> None:
        for k in keys:
            v = data.get(k)
            if v not in (None, ""):
                rows.append((label, str(v)))
                return

    # Always-first: when the node has an event timestamp, surface it at the
    # top of the grid so the analyst sees *exactly* when this entity entered
    # the timeline.
    take("Event Timestamp", "first_seen_ts", "ts", "first_seen", "start_time")

    if kind == "process":
        take("Path", "path")
        take("Command Line", "command_line", "cmdline")
        take("PID", "pid")
        take("Parent PID", "parent_pid", "ppid")
        take("Parent Process", "parent_name", "parent")
        take("User", "user", "username")
        take("Integrity Level", "integrity_level", "integrity")
        # Note: the Event Timestamp row at the top already covers start time.
    elif kind == "file":
        take("Full Path", "file_path", "path")
        take("SHA256", "sha256")
        take("MD5", "md5")
        take("Size", "size")
        take("Created By", "created_by", "actor")
    elif kind == "registry":
        take("Key", "key")
        take("Value Name", "value_name")
        take("Value Data", "value_data")
        take("Hive", "hive")
    elif kind in ("domain", "url", "ip"):
        take("Host", "domain", "remote_ip", "url")
        take("URL", "url")
        take("IP", "remote_ip")
        take("Port", "remote_port")
        take("Protocol", "protocol")
        take("Method", "method")
    elif kind == "yara":
        take("Rule", "rule")
        take("Tags", "tags")
        take("Severity", "severity")
    elif kind == "api":
        take("API", "api")
        take("Module", "module")
        take("Result", "result")
    elif kind == "module":
        take("Module Name", "name")
        take("Path", "path")
    elif kind == "memory":
        take("Region", "name")
        take("Address", "address")
        take("Size", "size")
        take("Protection", "protection")
    else:
        # Generic fallback — show whatever's there.
        for k, v in data.items():
            if k in ("label", "kind", "name"):
                continue
            if v in (None, ""):
                continue
            rows.append((k.replace("_", " ").title(), str(v)))
    return rows
