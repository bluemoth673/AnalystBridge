"""Bottom timeline + replay engine.

Phase 6: connects the slider to a `time_changed(ts)` signal, drives auto-replay
via QTimer, renders coloured event ticks over the slider, and shows per-type
counts. The slider value 0 = start of capture, max = end. Hand the panel a
list of EventRow + the cutoff is the timestamp the rest of the UI should
filter to.
"""
from __future__ import annotations

from collections import Counter
from typing import Optional

from PySide6.QtCore import QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QBrush, QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from analystbridge.core.event_row import EventRow
from analystbridge.ui.theme import C, kind_color


class _EventTickStrip(QWidget):
    """Thin paint widget showing one tick per event, coloured by type."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._events: list[EventRow] = []
        self._max = 1.0
        self._cursor_ratio = 1.0
        self.setMinimumHeight(36)
        self.setMaximumHeight(48)

    def set_events(self, events: list[EventRow], max_ts: float) -> None:
        self._events = events
        self._max = max(max_ts, 1e-6)
        self.update()

    def set_cursor_ratio(self, ratio: float) -> None:
        self._cursor_ratio = max(0.0, min(1.0, ratio))
        self.update()

    def paintEvent(self, event) -> None:  # noqa: ARG002
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect()
        # Baseline
        p.setPen(QPen(QColor(C.BORDER), 1))
        baseline_y = rect.height() - 6
        p.drawLine(0, baseline_y, rect.width(), baseline_y)

        if not self._events or self._max <= 0:
            return

        cursor_x = rect.width() * self._cursor_ratio

        for e in self._events:
            x = (e.ts / self._max) * rect.width()
            color = QColor(kind_color(e.event_type))
            # Past events are bright, future events dim
            if x > cursor_x:
                color.setAlphaF(0.30)
            else:
                color.setAlphaF(0.85)
            p.setPen(QPen(color, 2))
            tick_h = 18
            p.drawLine(int(x), baseline_y - tick_h, int(x), baseline_y)

        # Cursor line
        p.setPen(QPen(QColor(C.ACCENT_2), 2))
        p.drawLine(int(cursor_x), 0, int(cursor_x), baseline_y)
        # Cursor knob
        p.setBrush(QBrush(QColor(C.ACCENT_2)))
        p.drawEllipse(QRectF(cursor_x - 4, 0, 8, 8))


class TimelinePanel(QFrame):
    time_changed = Signal(float)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 8, 14, 8)
        outer.setSpacing(6)

        # ----- Top row: title + transport controls + slider + time --------
        top = QHBoxLayout()
        top.setSpacing(8)

        title = QLabel("Timeline / Replay")
        title.setObjectName("H3")
        title.setMinimumWidth(120)

        self.skip_back_btn = QPushButton("|<")
        self.skip_back_btn.setFixedWidth(34)
        self.skip_back_btn.setToolTip("Jump to start")
        self.skip_back_btn.clicked.connect(self._on_skip_back)

        self.play_btn = QPushButton("▶")
        self.play_btn.setFixedWidth(38)
        self.play_btn.setObjectName("Primary")
        self.play_btn.setToolTip("Play / Pause replay")
        self.play_btn.clicked.connect(self._on_play_pause)

        self.skip_fwd_btn = QPushButton(">|")
        self.skip_fwd_btn.setFixedWidth(34)
        self.skip_fwd_btn.setToolTip("Jump to end")
        self.skip_fwd_btn.clicked.connect(self._on_skip_fwd)

        self.speed_combo = QComboBox()
        self.speed_combo.addItems(["0.5x", "1x", "2x", "4x"])
        self.speed_combo.setCurrentText("1x")
        self.speed_combo.setFixedWidth(64)
        self.speed_combo.currentTextChanged.connect(self._on_speed_changed)

        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.setMinimum(0)
        self.slider.setMaximum(1000)
        self.slider.setValue(1000)
        self.slider.valueChanged.connect(self._on_slider_changed)

        self.time_label = QLabel("0.00s / 0.00s")
        self.time_label.setObjectName("Dim")
        self.time_label.setMinimumWidth(120)
        self.time_label.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )

        top.addWidget(title)
        top.addWidget(self.skip_back_btn)
        top.addWidget(self.play_btn)
        top.addWidget(self.skip_fwd_btn)
        top.addWidget(self.speed_combo)
        top.addWidget(self.slider, 1)
        top.addWidget(self.time_label)
        outer.addLayout(top)

        # ----- Tick strip -----
        self.tick_strip = _EventTickStrip()
        outer.addWidget(self.tick_strip)

        # ----- Bottom row: per-type counts ------------------------------
        self.counts_row = QHBoxLayout()
        self.counts_row.setSpacing(14)
        self.counts_row.addStretch()
        outer.addLayout(self.counts_row)
        self._count_widgets: list[QWidget] = []

        # ----- State ----------------------------------------------------
        self._max = 1.0
        self._events: list[EventRow] = []
        self._timer = QTimer(self)
        self._timer.setInterval(80)  # ~12fps; adjusted by speed
        self._timer.timeout.connect(self._on_tick)
        self._speed = 1.0
        self._playing = False

    # -- Public API ----------------------------------------------------------

    def set_events(self, events: list[EventRow]) -> None:
        self._events = list(events) if events else []
        self._max = max((e.ts for e in self._events), default=1.0) or 1.0
        self.tick_strip.set_events(self._events, self._max)

        # Set slider to end of capture (full reveal). Disconnect to avoid emit storm.
        self.slider.blockSignals(True)
        self.slider.setValue(1000)
        self.slider.blockSignals(False)
        self.tick_strip.set_cursor_ratio(1.0)
        self.time_label.setText(f"{self._max:.2f}s / {self._max:.2f}s")
        self._stop()
        self._rebuild_counts()
        # Tell listeners we're at full reveal
        self.time_changed.emit(self._max)

    # -- Slot handlers -------------------------------------------------------

    def _on_slider_changed(self, value: int) -> None:
        ratio = value / 1000.0
        ts = ratio * self._max
        self.tick_strip.set_cursor_ratio(ratio)
        self.time_label.setText(f"{ts:.2f}s / {self._max:.2f}s")
        self.time_changed.emit(ts)

    def _on_play_pause(self) -> None:
        if self._playing:
            self._stop()
        else:
            # If at end, restart from beginning
            if self.slider.value() >= 1000:
                self.slider.setValue(0)
            self._start()

    def _start(self) -> None:
        self._playing = True
        self.play_btn.setText("❚❚")
        self._timer.start()

    def _stop(self) -> None:
        self._playing = False
        self.play_btn.setText("▶")
        self._timer.stop()

    def _on_tick(self) -> None:
        # Advance slider; covers _max seconds in (~ _max / speed) wall seconds.
        # Move ratio = (interval_ms / 1000) * speed / max_ts
        if self._max <= 0:
            self._stop()
            return
        delta_ratio = (self._timer.interval() / 1000.0) * self._speed / self._max
        new_value = self.slider.value() + int(delta_ratio * 1000)
        if new_value >= 1000:
            self.slider.setValue(1000)
            self._stop()
            return
        self.slider.setValue(new_value)

    def _on_speed_changed(self, text: str) -> None:
        self._speed = float(text.rstrip("x"))

    def _on_skip_back(self) -> None:
        self.slider.setValue(0)
        self._stop()

    def _on_skip_fwd(self) -> None:
        self.slider.setValue(1000)
        self._stop()

    # -- Counts row ----------------------------------------------------------

    def _rebuild_counts(self) -> None:
        # Clear existing
        while self.counts_row.count() > 0:
            item = self.counts_row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        counts = Counter(e.event_type for e in self._events)
        order = ("process", "file", "registry", "network", "module", "yara", "api", "memory")
        ordered = [(k, counts[k]) for k in order if counts.get(k)]
        # Append any stragglers
        for k, v in counts.items():
            if k not in order:
                ordered.append((k, v))

        for k, v in ordered:
            chip = self._make_count_chip(k, v)
            self.counts_row.addWidget(chip)
        self.counts_row.addStretch()

    @staticmethod
    def _make_count_chip(kind: str, count: int) -> QWidget:
        chip = QFrame()
        chip.setStyleSheet(
            f"background:{C.BG_PANEL_2}; border:1px solid {C.BORDER}; border-radius:10px;"
        )
        layout = QHBoxLayout(chip)
        layout.setContentsMargins(8, 2, 10, 2)
        layout.setSpacing(6)

        dot = QLabel("●")
        dot.setStyleSheet(f"color: {kind_color(kind)};")

        text = QLabel(f"{kind.title()}  {count}")
        text.setStyleSheet(f"color: {C.TEXT_DIM}; font-size: 11px;")

        layout.addWidget(dot)
        layout.addWidget(text)
        return chip
