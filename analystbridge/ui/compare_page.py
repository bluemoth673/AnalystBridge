"""Compare-with-previous-samples panel.

The MainWindow keeps a session memory of every sample it has loaded —
``MainWindow._sample_memory`` — and feeds it here. The panel computes Jaccard
similarity (techniques + IOCs + storyline) between the *currently loaded*
sample and every other sample seen this session, and presents the result as
a sortable table with a percentage bar per row.
"""
from __future__ import annotations

from typing import Iterable

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from analystbridge.core.similarity import SampleFingerprint, compare, rank_against
from analystbridge.ui.theme import C
from analystbridge.ui.widgets import make_card


def _verdict_color(verdict: str) -> str:
    return {
        "near-identical": C.SUSPICIOUS,
        "strong": C.WARNING,
        "moderate": C.ACCENT_2,
        "weak": C.TEXT_DIM,
        "unrelated": C.TEXT_MUTED,
    }.get(verdict, C.TEXT_DIM)


class ComparePage(QWidget):
    sample_double_clicked = Signal(str)  # emits sample_id when user double-clicks a row

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(10)

        # ---- Header -----------------------------------------------------
        head = make_card()
        hl = QVBoxLayout(head)
        hl.setContentsMargins(20, 14, 20, 14)
        hl.setSpacing(4)

        title = QLabel("Compare with Previous Samples")
        title.setStyleSheet(f"color:{C.TEXT}; font-size:18px; font-weight:700;")
        hl.addWidget(title)

        sub = QLabel(
            "Behavioural similarity between the currently loaded sample and "
            "every sample loaded so far in this session — scored on Jaccard "
            "overlap of MITRE techniques (×0.55), IOC values (×0.20) and "
            "kill-chain stages (×0.25)."
        )
        sub.setObjectName("Muted")
        sub.setStyleSheet(f"color:{C.TEXT_DIM};")
        sub.setWordWrap(True)
        hl.addWidget(sub)

        meta_row = QHBoxLayout()
        meta_row.setSpacing(20)
        self.current_label = QLabel("Current sample: —")
        self.history_label = QLabel("0 prior samples")
        for w in (self.current_label, self.history_label):
            w.setStyleSheet(f"color:{C.ACCENT_2}; font-size:11px; font-weight:600;")
            meta_row.addWidget(w)
        meta_row.addStretch()
        hl.addLayout(meta_row)
        outer.addWidget(head)

        # ---- Empty state vs table --------------------------------------
        self._empty = self._make_empty_card()
        outer.addWidget(self._empty)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels([
            "Sample", "Composite", "Verdict", "Shared techniques", "Shared IOCs",
        ])
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(1, 180)
        h.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setStyleSheet(
            f"QTableWidget {{ background:{C.BG_PANEL}; alternate-background-color:{C.BG_PANEL_2};"
            f"border:1px solid {C.BORDER}; border-radius:8px; gridline-color:{C.BORDER}; }}"
            f"QTableWidget::item {{ padding: 10px 8px; }}"
            f"QHeaderView::section {{ background:{C.BG_CARD}; color:{C.TEXT_DIM};"
            f"padding:8px 10px; border:none; border-right:1px solid {C.BORDER};"
            f"font-weight:700; font-size:11px; letter-spacing:0.5px; }}"
        )
        self.table.cellDoubleClicked.connect(self._on_double_clicked)
        outer.addWidget(self.table, 1)
        self.table.setVisible(False)

        self._candidate_sample_ids: list[str] = []

    # ------------------------------------------------------------------
    def update(
        self,
        current: SampleFingerprint | None,
        history: Iterable[SampleFingerprint],
    ) -> None:
        history = [h for h in history if current is None or h.sample_id != current.sample_id]
        if current is None:
            self.current_label.setText("Current sample: —")
        else:
            self.current_label.setText(
                f"Current sample: {current.filename}  ({current.sample_id})"
            )
        self.history_label.setText(f"{len(history)} prior samples")

        if current is None or not history:
            self.table.setVisible(False)
            self._empty.setVisible(True)
            return

        self.table.setVisible(True)
        self._empty.setVisible(False)

        ranked = rank_against(current, history, top_k=50)
        self.table.setRowCount(len(ranked))
        self._candidate_sample_ids = [r.b for r in ranked]
        for r, report in enumerate(ranked):
            # Sample column — find the matching fingerprint to display its filename
            display = report.b
            for h in history:
                if h.sample_id == report.b:
                    display = f"{h.filename}\n{h.sample_id}"
                    break
            sample_item = QTableWidgetItem(display)
            sample_item.setFlags(sample_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, 0, sample_item)

            # Composite — text + progress bar widget
            self.table.setCellWidget(r, 1, self._composite_bar(report.composite))

            # Verdict
            verdict = QTableWidgetItem(report.verdict)
            verdict.setForeground(QColor(_verdict_color(report.verdict)))
            verdict.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            verdict.setFlags(verdict.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, 2, verdict)

            shared_t = QTableWidgetItem(", ".join(report.shared_techniques) or "—")
            shared_t.setForeground(QColor(C.TEXT_DIM))
            shared_t.setFlags(shared_t.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, 3, shared_t)

            shared_i = QTableWidgetItem(str(len(report.shared_iocs)))
            shared_i.setForeground(QColor(C.TEXT_DIM))
            shared_i.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            shared_i.setFlags(shared_i.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, 4, shared_i)

            self.table.setRowHeight(r, 56)

    # ------------------------------------------------------------------
    def _composite_bar(self, score: float) -> QWidget:
        wrap = QWidget()
        h = QHBoxLayout(wrap)
        h.setContentsMargins(8, 4, 8, 4)
        h.setSpacing(8)

        bar = QProgressBar()
        bar.setMinimum(0)
        bar.setMaximum(100)
        bar.setValue(int(round(score * 100)))
        bar.setTextVisible(False)
        bar.setFixedHeight(10)
        chunk_color = (
            C.SUSPICIOUS if score >= 0.85
            else C.WARNING if score >= 0.5
            else C.SUCCESS
        )
        bar.setStyleSheet(
            f"QProgressBar {{ background:{C.BG_PANEL_2}; border:1px solid {C.BORDER};"
            f"border-radius:5px; }}"
            f"QProgressBar::chunk {{ background:{chunk_color}; border-radius:4px; }}"
        )
        h.addWidget(bar, 1)

        pct = QLabel(f"{score:.0%}")
        pct.setStyleSheet(f"color:{C.TEXT}; font-weight:700; min-width: 36px;")
        pct.setMinimumWidth(40)
        pct.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight)
        h.addWidget(pct)
        return wrap

    def _make_empty_card(self) -> QFrame:
        card = make_card()
        v = QVBoxLayout(card)
        v.setContentsMargins(36, 36, 36, 36)
        msg = QLabel(
            "<b>No prior samples to compare against yet.</b><br>"
            f"<span style='color:{C.TEXT_DIM};'>"
            "Use <b>Load Sample…</b> to ingest a CAPE / Cuckoo / Sysmon / native "
            "JSON report. Each new sample is added to this session's memory and "
            "shows up here for comparison.</span>"
        )
        msg.setTextFormat(Qt.TextFormat.RichText)
        msg.setWordWrap(True)
        msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        msg.setStyleSheet(f"color:{C.TEXT}; font-size:13px; line-height:1.6;")
        v.addWidget(msg)
        return card

    def _on_double_clicked(self, row: int, _col: int) -> None:
        if 0 <= row < len(self._candidate_sample_ids):
            self.sample_double_clicked.emit(self._candidate_sample_ids[row])
