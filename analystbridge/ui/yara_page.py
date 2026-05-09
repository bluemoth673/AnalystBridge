"""YARA Rules — full-page view of every rule AnalystBridge knows about.

Two tabs:

* **Built-in** — the static behavioural rules shipped with the engine
  (PowerShell downloader, mshta proxy, vssadmin, ransom-note pattern, etc.).
  These mirror the ATT&CK detection rules so analysts can drop them into a
  YARA scanner directly.

* **Generated for this sample** — IOC-derived rules built on the fly from the
  loaded bundle (one rule per file hash, one combined network-IOC rule,
  ransomware-extension pattern when applicable). Rebuilt every time
  ``set_bundle`` is called.

Each rule is displayed in a card with a syntax-highlighted body, a tags row,
and a "Copy" button so analysts can paste straight into their tooling.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QClipboard, QGuiApplication
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from analystbridge.core.yara_generator import (
    YaraRule,
    builtin_rules,
    generate_rules_for_bundle,
)
from analystbridge.ui.services import AnalysisBundle
from analystbridge.ui.theme import C
from analystbridge.ui.widgets import make_card


def _accent_for_source(source: str) -> str:
    return C.ACCENT_2 if source == "builtin" else C.WARNING


class _RuleCard(QFrame):
    """One YARA rule rendered as a card with tags + copyable body."""

    def __init__(self, rule: YaraRule, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.setStyleSheet(
            f"QFrame#Card {{ background:{C.BG_CARD}; border:1px solid {C.BORDER};"
            f"border-radius:10px; }}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(8)

        accent = _accent_for_source(rule.source)

        # ---- Header row -------------------------------------------------
        header = QHBoxLayout()
        header.setSpacing(8)

        name = QLabel(rule.name)
        name.setStyleSheet(
            f"color:{C.TEXT}; font-size:14px; font-weight:700;"
            f"font-family:'Consolas','Cascadia Mono',monospace;"
        )
        name.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        header.addWidget(name)

        source_chip = QLabel(rule.source.upper())
        source_chip.setStyleSheet(
            f"background:{C.BG_PANEL_2}; color:{accent};"
            f"border:1px solid {accent}; border-radius:8px;"
            f"padding:1px 8px; font-size:10px; font-weight:700;"
        )
        header.addWidget(source_chip)

        header.addStretch()

        line_chip = QLabel(f"{rule.line_count} lines")
        line_chip.setStyleSheet(f"color:{C.TEXT_DIM}; font-size:10px;")
        header.addWidget(line_chip)

        copy_btn = QPushButton("Copy")
        copy_btn.setFixedWidth(70)
        copy_btn.clicked.connect(lambda: self._copy_to_clipboard(rule.body))
        self._copy_btn = copy_btn
        header.addWidget(copy_btn)
        layout.addLayout(header)

        # ---- Summary ----------------------------------------------------
        if rule.summary:
            summary = QLabel(rule.summary)
            summary.setStyleSheet(f"color:{C.TEXT_DIM}; font-size:11px;")
            summary.setWordWrap(True)
            layout.addWidget(summary)

        # ---- Tag chips --------------------------------------------------
        if rule.tags:
            tags_row = QHBoxLayout()
            tags_row.setSpacing(6)
            for tag in rule.tags:
                chip = QLabel(tag)
                chip.setStyleSheet(
                    f"background:{C.BG_PANEL_2}; color:{accent};"
                    f"border:1px solid {accent}; border-radius:9px;"
                    f"padding:1px 8px; font-size:10px; font-weight:600;"
                )
                tags_row.addWidget(chip, 0, Qt.AlignmentFlag.AlignLeft)
            tags_row.addStretch()
            layout.addLayout(tags_row)

        # ---- Body (read-only QTextEdit so it scrolls + selects) --------
        body = QTextEdit()
        body.setReadOnly(True)
        body.setPlainText(rule.body)
        body.setStyleSheet(
            f"QTextEdit {{ background:{C.BG_PANEL}; color:{C.TEXT};"
            f"border:1px solid {C.BORDER}; border-radius:6px;"
            f"font-family:'Consolas','Cascadia Mono',monospace;"
            f"font-size:11px; padding:10px; }}"
        )
        body.setMinimumHeight(min(220, 22 + rule.line_count * 16))
        body.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        layout.addWidget(body)

    def _copy_to_clipboard(self, text: str) -> None:
        QGuiApplication.clipboard().setText(text, QClipboard.Mode.Clipboard)
        self._copy_btn.setText("Copied!")
        from PySide6.QtCore import QTimer
        QTimer.singleShot(1200, lambda: self._copy_btn.setText("Copy"))


class _RulesScroll(QScrollArea):
    """Scrollable column of _RuleCard instances; ``set_rules`` rebuilds the list."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self._body = QWidget()
        self._body_layout = QVBoxLayout(self._body)
        self._body_layout.setContentsMargins(2, 2, 2, 2)
        self._body_layout.setSpacing(10)
        self._body_layout.addStretch()
        self.setWidget(self._body)

    def set_rules(self, rules: list[YaraRule], empty_text: str = "") -> None:
        # Clear existing cards (everything except the trailing stretch).
        while self._body_layout.count() > 1:
            item = self._body_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not rules:
            empty = QLabel(empty_text or "No rules to display.")
            empty.setStyleSheet(
                f"color:{C.TEXT_DIM}; padding:36px; font-size:12px;"
            )
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty.setWordWrap(True)
            self._body_layout.insertWidget(self._body_layout.count() - 1, empty)
            return

        for rule in rules:
            card = _RuleCard(rule)
            self._body_layout.insertWidget(self._body_layout.count() - 1, card)


class YaraPage(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(10)

        # ---- Header card ------------------------------------------------
        head = make_card()
        hl = QVBoxLayout(head)
        hl.setContentsMargins(20, 14, 20, 14)
        hl.setSpacing(4)

        title = QLabel("YARA Rules")
        title.setStyleSheet(f"color:{C.TEXT}; font-size:18px; font-weight:700;")
        hl.addWidget(title)

        sub = QLabel(
            "Behavioural rules AnalystBridge ships with, plus IOC-derived "
            "rules generated on the fly for the currently loaded sample. "
            "Click <b>Copy</b> on any card to paste the rule into your YARA "
            "scanner — both sets are valid <code>yara-python</code> input."
        )
        sub.setTextFormat(Qt.TextFormat.RichText)
        sub.setStyleSheet(f"color:{C.TEXT_DIM};")
        sub.setWordWrap(True)
        hl.addWidget(sub)

        meta_row = QHBoxLayout()
        meta_row.setSpacing(20)
        self.builtin_counter = QLabel("0 built-in")
        self.generated_counter = QLabel("0 generated")
        for w in (self.builtin_counter, self.generated_counter):
            w.setStyleSheet(f"color:{C.ACCENT_2}; font-size:11px; font-weight:600;")
            meta_row.addWidget(w)
        meta_row.addStretch()

        self.copy_all_btn = QPushButton("Copy all rules")
        self.copy_all_btn.clicked.connect(self._copy_all)
        meta_row.addWidget(self.copy_all_btn)
        hl.addLayout(meta_row)

        outer.addWidget(head)

        # ---- Tabs: Built-in / Generated --------------------------------
        self.tabs = QTabWidget()
        self.builtin_scroll = _RulesScroll()
        self.generated_scroll = _RulesScroll()
        self.tabs.addTab(self.builtin_scroll, "Built-in")
        self.tabs.addTab(self.generated_scroll, "Generated for this sample")
        outer.addWidget(self.tabs, 1)

        # Built-in rules never change; populate immediately.
        self._builtin = builtin_rules()
        self.builtin_scroll.set_rules(self._builtin)
        self.builtin_counter.setText(f"{len(self._builtin)} built-in")
        self._generated: list[YaraRule] = []

    def set_bundle(self, bundle: AnalysisBundle) -> None:
        """Refresh the Generated tab from the loaded bundle."""
        self._generated = generate_rules_for_bundle(bundle)
        self.generated_scroll.set_rules(
            self._generated,
            empty_text=(
                "No IOC-derived rules for this sample yet — generated rules "
                "appear when the analyser extracts hashes, network indicators "
                "or ransomware-rename patterns from the loaded report."
            ),
        )
        self.generated_counter.setText(f"{len(self._generated)} generated")

    # ------------------------------------------------------------------
    def _copy_all(self) -> None:
        """Copy every rule (built-in + generated) joined into a single .yar."""
        rules = self._builtin + self._generated
        text = "\n\n".join(r.body for r in rules)
        QGuiApplication.clipboard().setText(text, QClipboard.Mode.Clipboard)
        self.copy_all_btn.setText("Copied!")
        from PySide6.QtCore import QTimer
        QTimer.singleShot(1200, lambda: self.copy_all_btn.setText("Copy all rules"))
