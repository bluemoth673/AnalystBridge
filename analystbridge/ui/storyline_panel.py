"""Bottom-row Attack Storyline card — horizontal strip of stage cards.

Each card has a numbered circle, the stage title, MITRE chips, the description
and the recommended action. Clicking a card emits ``stage_selected(event_ids)``
so the graph view can highlight the matching nodes/edges.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QCursor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from analystbridge.core.storyline_builder import StorylineStage
from analystbridge.ui.theme import C


# Map stage title → accent colour (lines up with kill-chain phases).
def _stage_accent(title: str) -> str:
    t = title.lower()
    if "execution" in t and "script" not in t:
        return C.ACCENT
    if "script" in t:
        return C.SUSPICIOUS
    if "delivery" in t:
        return C.NETWORK
    if "persistence" in t:
        return C.REGISTRY
    if "evasion" in t or "recovery" in t:
        return C.WARNING
    if "c2" in t or "command" in t:
        return C.NETWORK
    if "impact" in t:
        return C.SUSPICIOUS
    return C.ACCENT


class _StageCard(QFrame):
    clicked = Signal(int)  # emits the index in the storyline

    def __init__(self, index: int, stage: StorylineStage, parent=None) -> None:
        super().__init__(parent)
        self._index = index
        accent = _stage_accent(stage.title)
        self.setObjectName("StageCard")
        self.setStyleSheet(
            f"QFrame#StageCard {{ background:{C.BG_PANEL_2};"
            f"border:1px solid {C.BORDER}; border-radius:10px; }}"
            f"QFrame#StageCard:hover {{ border:1px solid {accent}; }}"
        )
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setFixedWidth(360)
        self.setMinimumHeight(135)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 12, 14, 12)
        outer.setSpacing(6)

        # ---- Header row: numbered circle + title -------------------------
        header = QHBoxLayout()
        header.setSpacing(10)

        bubble = QLabel(str(index + 1))
        bubble.setFixedSize(28, 28)
        bubble.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bubble.setStyleSheet(
            f"background:{accent}; color:{C.BG_DEEP};"
            f"border-radius:14px; font-weight:700; font-size:12px;"
        )
        header.addWidget(bubble, 0, Qt.AlignmentFlag.AlignTop)

        title = QLabel(stage.title)
        title.setStyleSheet(
            f"color:{C.TEXT}; font-weight:700; font-size:13px;"
        )
        title.setWordWrap(True)
        header.addWidget(title, 1)
        outer.addLayout(header)

        # ---- MITRE chips row --------------------------------------------
        if stage.mitre_ids:
            chips = QHBoxLayout()
            chips.setSpacing(6)
            for tid in stage.mitre_ids:
                chip = QLabel(tid)
                chip.setStyleSheet(
                    f"background:{C.BG_CARD}; color:{accent};"
                    f"border:1px solid {accent}; border-radius:9px;"
                    f"padding:1px 8px; font-size:10px; font-weight:600;"
                )
                chip.setMaximumHeight(20)
                chips.addWidget(chip, 0, Qt.AlignmentFlag.AlignLeft)
            chips.addStretch()
            outer.addLayout(chips)

        # ---- Description ------------------------------------------------
        desc = QLabel(stage.description)
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color:{C.TEXT_DIM}; font-size:11px; line-height:1.4;")
        outer.addWidget(desc)

        # ---- Recommended action -----------------------------------------
        if stage.recommended_action:
            action = QLabel(f"→ {stage.recommended_action}")
            action.setWordWrap(True)
            action.setStyleSheet(
                f"color:{C.ACCENT_2}; font-size:10px; font-style:italic;"
                f"padding-top:4px;"
            )
            outer.addWidget(action)

        outer.addStretch()

    def mousePressEvent(self, event) -> None:
        self.clicked.emit(self._index)
        super().mousePressEvent(event)


class StorylinePanel(QFrame):
    stage_selected = Signal(list)  # list[int] of event ids

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(6)

        # ---- Header row -------------------------------------------------
        header = QHBoxLayout()
        title = QLabel("Attack Storyline")
        title.setObjectName("H2")
        header.addWidget(title)

        hint = QLabel("Click any stage to highlight its evidence on the graph")
        hint.setObjectName("Muted")
        hint.setStyleSheet(f"color:{C.TEXT_MUTED}; font-size:10px;")
        header.addWidget(hint)
        header.addStretch()

        self.clear_btn = QPushButton("Clear highlight")
        self.clear_btn.setFixedHeight(26)
        self.clear_btn.clicked.connect(self._on_clear)
        header.addWidget(self.clear_btn)
        layout.addLayout(header)

        # ---- Horizontal scroll area with the stage cards ----------------
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self._cards_host = QWidget()
        self._cards_layout = QHBoxLayout(self._cards_host)
        self._cards_layout.setContentsMargins(2, 2, 2, 2)
        self._cards_layout.setSpacing(10)
        self._cards_layout.addStretch()

        self._scroll.setWidget(self._cards_host)
        layout.addWidget(self._scroll, 1)

        self._stages: list[StorylineStage] = []

    def set_storyline(self, stages: list[StorylineStage]) -> None:
        self._stages = list(stages)
        # Clear cards (everything except the trailing stretch)
        while self._cards_layout.count() > 1:
            item = self._cards_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for idx, stage in enumerate(stages):
            card = _StageCard(idx, stage)
            card.clicked.connect(self._on_card_clicked)
            self._cards_layout.insertWidget(self._cards_layout.count() - 1, card)

    def _on_card_clicked(self, idx: int) -> None:
        if idx < 0 or idx >= len(self._stages):
            return
        self.stage_selected.emit(list(self._stages[idx].supporting_event_ids))

    def _on_clear(self) -> None:
        self.stage_selected.emit([])
