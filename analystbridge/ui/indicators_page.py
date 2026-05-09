"""Full-page Indicators (IOCs) view.

Searchable / type-filterable table with selectable cells (ctrl-C copies). The
defanged display value sits next to the raw value so analysts can paste either
form into reports / SIEMs.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QClipboard, QColor, QGuiApplication
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from analystbridge.core.ioc_extractor import Ioc
from analystbridge.ui.services import AnalysisBundle
from analystbridge.ui.theme import C
from analystbridge.ui.widgets import make_card


_IOC_TYPE_FILTERS = ("All", "domain", "ipv4", "url", "sha256", "file_path", "registry_key")


def _severity_color(sev: int) -> str:
    if sev >= 70:
        return C.SUSPICIOUS
    if sev >= 50:
        return C.WARNING
    return C.SUCCESS


class IndicatorsPage(QWidget):
    ioc_selected = Signal(list)  # supporting event ids

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(10)

        # ---- Header card ------------------------------------------------
        head = make_card()
        hl = QVBoxLayout(head)
        hl.setContentsMargins(20, 14, 20, 14)
        hl.setSpacing(6)

        h_top = QHBoxLayout()
        title = QLabel("Indicators of Compromise")
        title.setStyleSheet(f"color:{C.TEXT}; font-size:18px; font-weight:700;")
        h_top.addWidget(title)
        h_top.addStretch()

        self.copy_all_btn = QPushButton("Copy all (defanged)")
        self.copy_all_btn.clicked.connect(self._copy_all_defanged)
        h_top.addWidget(self.copy_all_btn)
        hl.addLayout(h_top)

        sub = QLabel(
            "Network indicators are defanged for safe sharing. The raw value "
            "is one column over — pick the form you want, click any cell to "
            "select, Ctrl+C to copy."
        )
        sub.setObjectName("Muted")
        sub.setStyleSheet(f"color:{C.TEXT_DIM};")
        sub.setWordWrap(True)
        hl.addWidget(sub)

        # ---- Filters row ------------------------------------------------
        filters = QHBoxLayout()
        filters.setSpacing(8)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search value, tag, or display form…")
        self.search_edit.setFixedWidth(320)
        self.search_edit.textChanged.connect(self._refilter)
        filters.addWidget(self.search_edit)

        self.type_combo = QComboBox()
        self.type_combo.addItems(_IOC_TYPE_FILTERS)
        self.type_combo.setFixedWidth(140)
        self.type_combo.currentTextChanged.connect(self._refilter)
        filters.addWidget(self.type_combo)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setFixedWidth(70)
        self.clear_btn.clicked.connect(self._clear_filter)
        filters.addWidget(self.clear_btn)

        filters.addStretch()
        self.counter = QLabel("0 indicators")
        self.counter.setStyleSheet(f"color:{C.ACCENT_2}; font-size:11px; font-weight:600;")
        filters.addWidget(self.counter)
        hl.addLayout(filters)
        outer.addWidget(head)

        # ---- Table ------------------------------------------------------
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "Type", "Defanged value", "Raw value", "Severity", "Confidence", "Tags",
        ])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setColumnWidth(1, 320)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setStyleSheet(
            f"QTableWidget {{ background:{C.BG_PANEL}; alternate-background-color:{C.BG_PANEL_2};"
            f"border:1px solid {C.BORDER}; border-radius:8px; gridline-color:{C.BORDER};"
            f"font-family:'Consolas','Cascadia Mono',monospace; font-size:11px; }}"
            f"QTableWidget::item {{ padding: 8px; }}"
            f"QTableWidget::item:selected {{ background:{C.BG_CARD}; color:{C.ACCENT_2}; }}"
            f"QHeaderView::section {{ background:{C.BG_CARD}; color:{C.TEXT_DIM};"
            f"padding:8px 10px; border:none; border-right:1px solid {C.BORDER};"
            f"font-weight:700; font-size:11px; letter-spacing:0.5px;"
            f"font-family:'Segoe UI',sans-serif; }}"
        )
        self.table.itemSelectionChanged.connect(self._on_row_selected)
        outer.addWidget(self.table, 1)

        self._iocs: list[Ioc] = []
        self._visible_indices: list[int] = []

    # ------------------------------------------------------------------
    def set_bundle(self, bundle: AnalysisBundle) -> None:
        self._iocs = list(bundle.result.iocs)
        self._refilter()

    # ------------------------------------------------------------------
    def _refilter(self) -> None:
        query = (self.search_edit.text() or "").strip().lower()
        type_filter = self.type_combo.currentText()
        self._visible_indices = []

        for idx, ioc in enumerate(self._iocs):
            if type_filter != "All" and ioc.ioc_type != type_filter:
                continue
            if query:
                hay = " ".join(
                    str(x or "").lower()
                    for x in (
                        ioc.ioc_type,
                        ioc.value,
                        ioc.display_value,
                        " ".join(ioc.tags or []),
                    )
                )
                if query not in hay:
                    continue
            self._visible_indices.append(idx)

        self.table.setRowCount(len(self._visible_indices))
        for r, idx in enumerate(self._visible_indices):
            ioc = self._iocs[idx]

            type_item = QTableWidgetItem(ioc.ioc_type)
            type_item.setForeground(QColor(C.ACCENT_2))
            type_item.setFlags(type_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, 0, type_item)

            defanged = QTableWidgetItem(ioc.display_value or ioc.value)
            defanged.setForeground(QColor(C.TEXT))
            defanged.setData(Qt.ItemDataRole.UserRole, list(ioc.source_event_ids))
            defanged.setFlags(defanged.flags() & ~Qt.ItemFlag.ItemIsEditable)
            defanged.setToolTip("Click row to highlight matching events on the graph")
            self.table.setItem(r, 1, defanged)

            raw = QTableWidgetItem(ioc.value)
            raw.setForeground(QColor(C.TEXT_DIM))
            raw.setFlags(raw.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, 2, raw)

            sev = QTableWidgetItem(str(ioc.severity))
            sev.setForeground(QColor(_severity_color(ioc.severity)))
            sev.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            sev.setFlags(sev.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, 3, sev)

            conf = QTableWidgetItem(f"{getattr(ioc, 'confidence', 0.0):.0%}")
            conf.setForeground(QColor(C.TEXT_DIM))
            conf.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            conf.setFlags(conf.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, 4, conf)

            tags = QTableWidgetItem(", ".join(ioc.tags or []))
            tags.setForeground(QColor(C.TEXT_DIM))
            tags.setFlags(tags.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, 5, tags)

            self.table.setRowHeight(r, 36)

        if len(self._visible_indices) == len(self._iocs):
            self.counter.setText(f"{len(self._iocs)} indicators")
        else:
            self.counter.setText(
                f"{len(self._visible_indices)} of {len(self._iocs)} indicators"
            )

    def _clear_filter(self) -> None:
        self.search_edit.clear()
        self.type_combo.setCurrentText("All")
        self._refilter()

    def _on_row_selected(self) -> None:
        items = self.table.selectedItems()
        if not items:
            return
        row = items[0].row()
        if row >= len(self._visible_indices):
            return
        ioc = self._iocs[self._visible_indices[row]]
        self.ioc_selected.emit(list(ioc.source_event_ids))

    def _copy_all_defanged(self) -> None:
        text = "\n".join(
            f"{i.ioc_type}\t{i.display_value or i.value}"
            for i in self._iocs
        )
        QGuiApplication.clipboard().setText(text, QClipboard.Mode.Clipboard)
