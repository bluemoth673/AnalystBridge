"""Dashboard page: stats strip + filterable events table."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
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

from analystbridge.core.event_row import EventRow
from analystbridge.ui.services import AnalysisBundle
from analystbridge.ui.theme import C
from analystbridge.ui.widgets import Stat, make_card

EVENT_TYPE_FILTERS = (
    "All",
    "process",
    "file",
    "network",
    "registry",
    "yara",
    "api",
    "module",
    "memory",
)


class EventsTable(QTableWidget):
    HEADERS = ("Time", "Type", "Actor", "Action", "Target")

    def __init__(self, parent=None) -> None:
        super().__init__(0, len(self.HEADERS), parent)
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.verticalHeader().setVisible(False)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.setAlternatingRowColors(True)
        self.setShowGrid(False)
        self._all_events: list[EventRow] = []

    def set_events(self, events: list[EventRow]) -> None:
        self._all_events = list(events)
        self.apply_filter("", "All")

    def apply_filter(self, query: str, type_filter: str) -> int:
        """Filter the table in-place. Returns the visible row count."""
        query = (query or "").strip().lower()
        type_filter = (type_filter or "All")

        rows: list[EventRow] = []
        for e in self._all_events:
            if type_filter != "All" and e.event_type != type_filter:
                continue
            if query:
                hay = " ".join(
                    str(x or "").lower()
                    for x in (
                        e.event_type,
                        e.actor_name or e.actor_id or "",
                        e.action or "",
                        self._target_label(e),
                    )
                )
                if query not in hay:
                    continue
            rows.append(e)

        self.setRowCount(len(rows))
        for r, e in enumerate(rows):
            self.setItem(r, 0, QTableWidgetItem(f"{e.ts:.2f}s"))
            self.setItem(r, 1, QTableWidgetItem(e.event_type))
            self.setItem(r, 2, QTableWidgetItem(e.actor_name or e.actor_id or ""))
            self.setItem(r, 3, QTableWidgetItem(e.action or ""))
            self.setItem(r, 4, QTableWidgetItem(self._target_label(e)))
        self.resizeColumnsToContents()
        self.horizontalHeader().setStretchLastSection(True)
        return len(rows)

    @staticmethod
    def _target_label(e: EventRow) -> str:
        t = e.target
        if e.target_type == "process":
            return f"{t.get('name', '')} (pid {t.get('pid', '')})"
        if e.target_type == "file":
            return t.get("file_path") or t.get("path") or ""
        if e.target_type in ("ip", "domain", "url"):
            return t.get("url") or t.get("domain") or t.get("remote_ip") or ""
        if e.target_type == "registry":
            key = t.get("key") or ""
            value = t.get("value_name")
            return f"{key}\\{value}" if value else key
        if e.target_type == "yara":
            return t.get("rule") or ""
        if e.target_type == "api":
            return t.get("api") or ""
        if e.target_type == "module":
            return t.get("name") or t.get("path") or ""
        if e.target_type == "memory":
            return t.get("name") or t.get("path") or ""
        return ""


class DashboardPage(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(10)

        # Stats strip
        stats_card = make_card()
        sl = QHBoxLayout(stats_card)
        sl.setContentsMargins(18, 14, 18, 14)
        sl.setSpacing(28)
        self.stat_events = Stat("EVENTS")
        self.stat_processes = Stat("PROCESSES")
        self.stat_network = Stat("NETWORK")
        self.stat_files = Stat("FILES")
        self.stat_registry = Stat("REGISTRY")
        self.stat_techniques = Stat("MITRE TECHNIQUES")
        self.stat_iocs = Stat("IOCS")
        for w in (
            self.stat_events,
            self.stat_processes,
            self.stat_network,
            self.stat_files,
            self.stat_registry,
            self.stat_techniques,
            self.stat_iocs,
        ):
            sl.addWidget(w)
        sl.addStretch()
        layout.addWidget(stats_card)

        # Events title + filter row
        title_row = QHBoxLayout()
        title_row.setSpacing(10)

        title = QLabel("Recent Events")
        title.setObjectName("H2")
        title_row.addWidget(title)
        title_row.addStretch()

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search actor / action / target …")
        self.search_edit.setFixedWidth(280)
        self.search_edit.textChanged.connect(self._on_filter_changed)
        title_row.addWidget(self.search_edit)

        self.type_combo = QComboBox()
        self.type_combo.addItems(EVENT_TYPE_FILTERS)
        self.type_combo.setFixedWidth(120)
        self.type_combo.currentTextChanged.connect(self._on_filter_changed)
        title_row.addWidget(self.type_combo)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setFixedWidth(70)
        self.clear_btn.clicked.connect(self._on_clear_filter)
        title_row.addWidget(self.clear_btn)

        layout.addLayout(title_row)

        self.filter_status = QLabel("")
        self.filter_status.setObjectName("Muted")
        self.filter_status.setStyleSheet(f"color: {C.TEXT_DIM};")
        layout.addWidget(self.filter_status)

        self.events_table = EventsTable()
        layout.addWidget(self.events_table, 1)

    def set_bundle(self, bundle: AnalysisBundle) -> None:
        events = bundle.events
        type_counts: dict[str, int] = {}
        for e in events:
            type_counts[e.event_type] = type_counts.get(e.event_type, 0) + 1

        self.stat_events.set_value(len(events))
        self.stat_processes.set_value(type_counts.get("process", 0))
        self.stat_network.set_value(type_counts.get("network", 0))
        self.stat_files.set_value(type_counts.get("file", 0))
        self.stat_registry.set_value(type_counts.get("registry", 0))
        self.stat_techniques.set_value(len(bundle.result.mappings))
        self.stat_iocs.set_value(len(bundle.result.iocs))

        self.events_table.set_events(events)
        self._on_filter_changed()

    # ------------------------------------------------------------------
    def _on_filter_changed(self, *_args) -> None:
        visible = self.events_table.apply_filter(
            self.search_edit.text(), self.type_combo.currentText()
        )
        total = len(self.events_table._all_events)
        if visible == total:
            self.filter_status.setText(f"Showing all {total} events")
        else:
            self.filter_status.setText(f"Showing {visible} of {total} events")

    def _on_clear_filter(self) -> None:
        self.search_edit.clear()
        self.type_combo.setCurrentText("All")
        self._on_filter_changed()

    def reset_filter(self) -> None:
        """Public alias for ``_on_clear_filter`` — the MainWindow calls this
        whenever the Dashboard nav button is clicked so users always land on
        an unfiltered events table."""
        self._on_clear_filter()
