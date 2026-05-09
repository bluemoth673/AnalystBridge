"""Settings page — paths, AI engine status, theme, keyboard shortcuts.

All paths are rendered through ``display_path`` so they appear as
``./exports``, ``./notes``, etc. — never as ``C:\\Users\\Omar\\…`` — which
keeps screenshots and the GitHub repo portable across machines.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from analystbridge import __version__
from analystbridge.ai import LLMAssistEngine
from analystbridge.paths import (
    EXPORTS_ROOT,
    ICONS_ROOT,
    NAV_ICONS_ROOT,
    NOTES_ROOT,
    PROJECT_ROOT,
    display_path,
)
from analystbridge.ui.icons import has_any_icons
from analystbridge.ui.theme import C
from analystbridge.ui.widgets import make_card


class SettingsPage(QWidget):
    def __init__(self, llm_engine: LLMAssistEngine | None = None, parent=None) -> None:
        super().__init__(parent)
        self._llm = llm_engine or LLMAssistEngine()

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer.addWidget(scroll)

        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(8, 8, 8, 8)
        body_layout.setSpacing(12)
        scroll.setWidget(body)

        body_layout.addWidget(self._build_app_card())
        body_layout.addWidget(self._build_paths_card())
        body_layout.addWidget(self._build_ai_card())
        body_layout.addWidget(self._build_icons_card())
        body_layout.addWidget(self._build_shortcuts_card())
        body_layout.addStretch()

    # ------------------------------------------------------------------
    @staticmethod
    def _section_title(text: str) -> QLabel:
        title = QLabel(text)
        title.setStyleSheet(
            f"color:{C.ACCENT_2}; font-weight:700; font-size:11px; letter-spacing:1px;"
        )
        return title

    @staticmethod
    def _kv_grid(rows: list[tuple[str, str, str]]) -> QGridLayout:
        """Build a 3-column grid: key (160px) | value (stretches) | optional accent.

        ``rows`` is a list of ``(key, value, value_color)``; pass ``""`` for the
        third element if you don't need a colour override.
        """
        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(8)
        grid.setColumnMinimumWidth(0, 160)
        grid.setColumnStretch(0, 0)
        grid.setColumnStretch(1, 1)

        for r, (k, v, color) in enumerate(rows):
            key_label = QLabel(k)
            key_label.setStyleSheet(
                f"color:{C.TEXT_DIM}; font-size:11px;"
            )
            key_label.setMinimumWidth(160)
            grid.addWidget(key_label, r, 0, Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)

            value_label = QLabel(v)
            value_label.setWordWrap(True)
            value_label.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            value_label.setStyleSheet(
                f"color:{color or C.TEXT}; font-size:11px;"
                f"font-family:'Consolas','Cascadia Mono',monospace;"
            )
            grid.addWidget(value_label, r, 1)

        return grid

    # ------------------------------------------------------------------
    def _build_app_card(self) -> QFrame:
        card = make_card()
        v = QVBoxLayout(card)
        v.setContentsMargins(20, 16, 20, 16)
        v.setSpacing(10)

        v.addWidget(self._section_title("APPLICATION"))
        v.addLayout(self._kv_grid([
            ("Version", __version__, ""),
            ("Theme", "Dark (built-in)", ""),
            ("UI Toolkit", "PySide6 / Qt 6", ""),
            ("Database", "SQLite (WAL mode, foreign keys ON)", ""),
        ]))
        return card

    def _build_paths_card(self) -> QFrame:
        card = make_card()
        v = QVBoxLayout(card)
        v.setContentsMargins(20, 16, 20, 16)
        v.setSpacing(10)

        v.addWidget(self._section_title("PATHS"))

        # Project-relative paths — same on every machine, so screenshots and
        # GitHub uploads never expose someone's home directory. The absolute
        # path is shown faded underneath as a tooltip-style hint.
        v.addLayout(self._kv_grid([
            ("Project root",      display_path(PROJECT_ROOT),     ""),
            ("Exports root",      display_path(EXPORTS_ROOT),     ""),
            ("Notes sidecar",     display_path(NOTES_ROOT),       ""),
            ("Node icons",        display_path(ICONS_ROOT),       ""),
            ("Sidebar icons",     display_path(NAV_ICONS_ROOT),   ""),
        ]))

        hint = QLabel(
            "Paths above are shown <i>relative to the project root</i> so they "
            "stay portable across machines and GitHub clones. Click any value "
            "and Ctrl+C to copy."
        )
        hint.setTextFormat(Qt.TextFormat.RichText)
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color:{C.TEXT_MUTED}; font-size:10px; padding-top:4px;")
        v.addWidget(hint)
        return card

    def _build_ai_card(self) -> QFrame:
        card = make_card()
        v = QVBoxLayout(card)
        v.setContentsMargins(20, 16, 20, 16)
        v.setSpacing(10)

        v.addWidget(self._section_title("AI ASSIST  (OFFLINE LLM)"))

        status = self._llm.status()
        status_color = C.SUCCESS if status.available else C.WARNING
        state_text = "Connected" if status.available else "Not connected (preview mode)"

        v.addLayout(self._kv_grid([
            ("Status", state_text, status_color),
            ("Model", status.model, ""),
            ("Backend", status.backend, ""),
        ]))

        detail = QLabel(status.detail)
        detail.setWordWrap(True)
        detail.setStyleSheet(
            f"color:{C.TEXT_DIM}; line-height:1.55; padding-top:4px;"
        )
        v.addWidget(detail)

        setup = QLabel(
            f"<b>To enable AI Assist:</b><br>"
            f"<span style='color:{C.ACCENT_2}; font-family:Consolas,monospace;'>"
            "1. Install Ollama  →  https://ollama.com<br>"
            "2. Pull the model  →  <b>ollama pull gemma2:9b</b><br>"
            "3. Restart AnalystBridge — the toggle in the Export dialog and "
            "AI Insights tab will activate automatically."
            "</span>"
        )
        setup.setTextFormat(Qt.TextFormat.RichText)
        setup.setWordWrap(True)
        setup.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        setup.setStyleSheet(
            f"background:{C.BG_PANEL_2}; border:1px solid {C.BORDER};"
            f"border-radius:6px; padding:12px; color:{C.TEXT}; line-height:1.55;"
        )
        v.addWidget(setup)
        return card

    def _build_icons_card(self) -> QFrame:
        card = make_card()
        v = QVBoxLayout(card)
        v.setContentsMargins(20, 16, 20, 16)
        v.setSpacing(10)

        v.addWidget(self._section_title("NODE & SIDEBAR ICONS"))

        icons_color = C.SUCCESS if has_any_icons() else C.WARNING
        icons_status = (
            "Loaded — graph nodes and sidebar render with PNG icons."
            if has_any_icons()
            else "No icons loaded — graph and sidebar use geometric fallbacks."
        )
        v.addLayout(self._kv_grid([
            ("Status", icons_status, icons_color),
            ("Drop node PNGs into", display_path(ICONS_ROOT), ""),
            ("Drop nav PNGs into", display_path(NAV_ICONS_ROOT), ""),
        ]))

        hint = QLabel(
            "Black-on-transparent icons (Heroicons / Tabler / Lucide) are "
            "auto-tinted to white so they read on the dark theme. Required "
            "filenames are listed in <code>assets/icons/README.md</code>."
        )
        hint.setTextFormat(Qt.TextFormat.RichText)
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color:{C.TEXT_DIM}; padding-top:4px; line-height:1.55;")
        v.addWidget(hint)
        return card

    def _build_shortcuts_card(self) -> QFrame:
        card = make_card()
        v = QVBoxLayout(card)
        v.setContentsMargins(20, 16, 20, 16)
        v.setSpacing(10)

        v.addWidget(self._section_title("KEYBOARD & MOUSE"))
        v.addLayout(self._kv_grid([
            ("Pan graph", "Use the white scrollbars on the right / bottom", ""),
            ("Zoom graph", "Mouse wheel", ""),
            ("Move a node", "Click + drag — connected edges follow", ""),
            ("Inspect node", "Click — Node Details on the right populates", ""),
            ("Highlight stage", "Click any card in the Attack Storyline strip", ""),
            ("Copy details", "Click 'Copy details' under Node Details, "
                             "or select text and Ctrl+C", ""),
        ]))
        return card
