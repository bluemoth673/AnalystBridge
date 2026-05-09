"""Full-page MITRE ATT&CK mapping view.

Replaces the cramped right-panel list with a proper table:
  Technique | Tactic | Confidence | Reason

Every text cell is selectable (copy with Ctrl+C). Clicking a row emits
``mapping_selected(event_ids)`` so the graph can highlight the evidence.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from analystbridge.core.mitre_mapper import MitreMapping
from analystbridge.ui.services import AnalysisBundle
from analystbridge.ui.theme import C
from analystbridge.ui.widgets import make_card


_TACTIC_COLOR = {
    "Execution": C.SUSPICIOUS,
    "Persistence": C.REGISTRY,
    "Defense Evasion": C.WARNING,
    "Command and Control": C.NETWORK,
    "Impact": C.SUSPICIOUS,
    "Credential Access": C.WARNING,
    "Discovery": C.ACCENT,
}


class MitrePage(QWidget):
    mapping_selected = Signal(list)  # list[int] of supporting event ids

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(10)

        # ---- Header card ------------------------------------------------
        head = make_card()
        hl = QVBoxLayout(head)
        hl.setContentsMargins(20, 14, 20, 14)
        hl.setSpacing(2)

        title = QLabel("MITRE ATT&CK Mapping")
        title.setStyleSheet(f"color:{C.TEXT}; font-size:18px; font-weight:700;")
        hl.addWidget(title)

        sub = QLabel(
            "Every technique that fired against the loaded sample, with its "
            "tactic, confidence and the reason the rule produced a match. "
            "Click any row to highlight the supporting events on the graph."
        )
        sub.setObjectName("Muted")
        sub.setStyleSheet(f"color:{C.TEXT_DIM};")
        sub.setWordWrap(True)
        hl.addWidget(sub)

        # Counters row
        meta_row = QHBoxLayout()
        meta_row.setSpacing(20)
        self.tech_counter = QLabel("0 techniques")
        self.tactic_counter = QLabel("0 tactics")
        self.attack_version = QLabel("ATT&CK v15")
        for w in (self.tech_counter, self.tactic_counter, self.attack_version):
            w.setStyleSheet(f"color:{C.ACCENT_2}; font-size:11px; font-weight:600;")
            meta_row.addWidget(w)
        meta_row.addStretch()
        hl.addLayout(meta_row)
        outer.addWidget(head)

        # ---- Table ------------------------------------------------------
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Technique", "Tactic", "Confidence", "Reason"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(True)
        self.table.setStyleSheet(
            f"QTableWidget {{ background:{C.BG_PANEL}; alternate-background-color:{C.BG_PANEL_2};"
            f"border:1px solid {C.BORDER}; border-radius:8px; gridline-color:{C.BORDER}; }}"
            f"QTableWidget::item {{ padding: 10px 8px; }}"
            f"QHeaderView::section {{ background:{C.BG_CARD}; color:{C.TEXT_DIM};"
            f"padding:8px 10px; border:none; border-right:1px solid {C.BORDER};"
            f"font-weight:700; font-size:11px; letter-spacing:0.5px; }}"
        )
        self.table.itemSelectionChanged.connect(self._on_row_selected)
        outer.addWidget(self.table, 1)

        self._mappings: list[MitreMapping] = []

    def set_bundle(self, bundle: AnalysisBundle) -> None:
        self._mappings = list(bundle.result.mappings)
        self.table.setRowCount(len(self._mappings))

        tactics: set[str] = set()
        for r, m in enumerate(self._mappings):
            tactics.add(m.tactic)

            # Technique cell — bold ID + light name underneath via rich text.
            tech = QTableWidgetItem(f"{m.technique_id}\n{m.technique_name}")
            tech.setForeground(QColor(C.TEXT))
            tech.setFlags(tech.flags() & ~Qt.ItemFlag.ItemIsEditable)
            tech.setData(Qt.ItemDataRole.UserRole, list(m.evidence_event_ids))
            tech.setToolTip("Click row to highlight supporting events on the graph")
            self.table.setItem(r, 0, tech)

            # Tactic — coloured badge style
            tactic_color = _TACTIC_COLOR.get(m.tactic, C.ACCENT)
            tactic_item = QTableWidgetItem(m.tactic)
            tactic_item.setForeground(QColor(tactic_color))
            tactic_item.setFlags(tactic_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, 1, tactic_item)

            # Confidence
            conf = QTableWidgetItem(f"{m.confidence:.0%}")
            conf.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            conf.setForeground(QColor(self._confidence_color(m.confidence)))
            conf.setFlags(conf.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, 2, conf)

            # Reason
            reason = QTableWidgetItem(m.reason)
            reason.setForeground(QColor(C.TEXT_DIM))
            reason.setFlags(reason.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, 3, reason)

            self.table.setRowHeight(r, 56)

        self.tech_counter.setText(f"{len(self._mappings)} techniques")
        self.tactic_counter.setText(f"{len(tactics)} tactics")

    def _on_row_selected(self) -> None:
        items = self.table.selectedItems()
        if not items:
            return
        row = items[0].row()
        if row >= len(self._mappings):
            return
        evidence = self._mappings[row].evidence_event_ids
        self.mapping_selected.emit(list(evidence))

    @staticmethod
    def _confidence_color(c: float) -> str:
        if c >= 0.85:
            return C.SUSPICIOUS
        if c >= 0.65:
            return C.WARNING
        return C.ACCENT_2
