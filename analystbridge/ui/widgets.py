"""Reusable AnalystBridge widgets — Card frames, Stat blocks, Malice Score gauge."""
from __future__ import annotations

import math

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QPointF,
    QPropertyAnimation,
    QRectF,
    Qt,
)
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget

from analystbridge.ui.theme import C


def make_card(parent: QWidget | None = None) -> QFrame:
    f = QFrame(parent)
    f.setObjectName("Card")
    return f


def make_panel(parent: QWidget | None = None) -> QFrame:
    f = QFrame(parent)
    f.setObjectName("Panel")
    return f


class Stat(QWidget):
    """Big number with a small uppercase label underneath."""

    def __init__(self, label: str, value: str = "--", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        self.value_label = QLabel(value)
        self.value_label.setObjectName("Stat")
        self.label_label = QLabel(label.upper())
        self.label_label.setObjectName("H3")
        layout.addWidget(self.value_label)
        layout.addWidget(self.label_label)

    def set_value(self, value: str | int) -> None:
        self.value_label.setText(str(value))


class MaliceScoreGauge(QWidget):
    """Half-circle gauge for the 0-100 Malice Score with a colour-banded arc."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score = 0          # the live (animated) value paintEvent reads
        self._target_score = 0   # what set_score was last called with
        self._risk = "Low"
        self.setMinimumSize(240, 190)

        # Spring-style needle / counter animation. The animation drives
        # ``self.animatedScore``, which is the property paintEvent reads —
        # so the arc, needle and the big number all sweep together.
        self._anim = QPropertyAnimation(self, b"animatedScore", self)
        self._anim.setDuration(900)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    # ----- Property exposed to QPropertyAnimation -------------------------

    def _get_animated_score(self) -> float:
        return float(self._score)

    def _set_animated_score(self, value: float) -> None:
        self._score = max(0.0, min(100.0, float(value)))
        self.update()

    animatedScore = Property(float, _get_animated_score, _set_animated_score)

    # ---------------------------------------------------------------------

    def set_score(self, score: int, risk: str) -> None:
        target = max(0, min(100, int(score)))
        self._target_score = target
        self._risk = risk
        self._anim.stop()
        self._anim.setStartValue(float(self._score))
        self._anim.setEndValue(float(target))
        self._anim.start()

    def paintEvent(self, event) -> None:  # noqa: ARG002
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect()

        # Reserve ~62 px under the visible top semicircle for score + risk text.
        bottom_reserve = 64
        # Arc square: width-bound, but constrained so the top-semicircle (size/2 tall)
        # plus bottom_reserve fits within the widget height.
        size = min(rect.width() - 16, (rect.height() - bottom_reserve) * 2)
        size = max(size, 110)
        cx = rect.center().x()
        arc_top = rect.top() + 8
        arc_rect = QRectF(cx - size / 2, arc_top, size, size)
        visible_bottom = arc_top + size / 2  # bottom of the visible top semicircle

        # Background arc (the unlit portion)
        bg_pen = QPen(QColor(C.BG_PANEL_2))
        bg_pen.setWidth(14)
        bg_pen.setCapStyle(Qt.PenCapStyle.FlatCap)
        p.setPen(bg_pen)
        # Top half: Qt arc angles in 1/16 degree, 0 = right, +ccw.
        # We want the top semicircle: start 180, span 180 (going counter-clockwise).
        p.drawArc(arc_rect, 180 * 16, 180 * 16)

        # Coloured score arc — drawn in 4 bands so the colour hints at risk
        bands = (
            (0, 25, QColor(C.SUCCESS)),
            (25, 50, QColor(C.WARNING)),
            (50, 75, QColor("#ff8a3d")),
            (75, 100, QColor(C.SUSPICIOUS)),
        )
        for lo, hi, color in bands:
            if self._score <= lo:
                break
            actual_hi = min(self._score, hi)
            # Map score 0..100 to angle 180..0 (top semicircle, sweeping clockwise)
            start_deg = 180 - (lo / 100.0) * 180
            span_deg = -((actual_hi - lo) / 100.0) * 180
            score_pen = QPen(color)
            score_pen.setWidth(14)
            score_pen.setCapStyle(Qt.PenCapStyle.FlatCap)
            p.setPen(score_pen)
            p.drawArc(arc_rect, int(start_deg * 16), int(span_deg * 16))

        # ---- Needle pointing at the current score -----------------------
        # Map score 0..100 to angle 180°..0° (left → right across the top).
        needle_deg = 180 - (self._score / 100.0) * 180
        needle_rad = math.radians(needle_deg)
        cx_pt = QPointF(arc_rect.center().x(), arc_rect.center().y())
        radius = arc_rect.width() / 2 - 2
        tip = QPointF(
            cx_pt.x() + math.cos(needle_rad) * (radius - 6),
            cx_pt.y() - math.sin(needle_rad) * (radius - 6),
        )
        # Build a slim triangular needle around the centre line
        perp = needle_rad + math.pi / 2
        base_w = 6
        b1 = QPointF(
            cx_pt.x() + math.cos(perp) * base_w,
            cx_pt.y() - math.sin(perp) * base_w,
        )
        b2 = QPointF(
            cx_pt.x() - math.cos(perp) * base_w,
            cx_pt.y() + math.sin(perp) * base_w,
        )
        needle_color = QColor(self._risk_color())
        p.setBrush(QBrush(needle_color))
        p.setPen(QPen(needle_color.darker(140), 1))
        p.drawPolygon(QPolygonF([tip, b1, b2]))
        # Hub (small filled circle at the centre)
        p.setBrush(QBrush(QColor(C.TEXT)))
        p.setPen(QPen(QColor(C.BORDER), 1))
        p.drawEllipse(cx_pt, 5, 5)

        # Score number sits just under the visible semicircle.
        p.setPen(QPen(QColor(C.TEXT)))
        p.setFont(QFont("Segoe UI", 30, QFont.Weight.Bold))
        score_text_rect = QRectF(rect.left(), visible_bottom + 4, rect.width(), 36)
        p.drawText(
            score_text_rect,
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter,
            str(int(round(self._score))),
        )

        # Risk label below the score
        p.setPen(QPen(QColor(self._risk_color())))
        p.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        risk_rect = QRectF(rect.left(), visible_bottom + 40, rect.width(), 20)
        p.drawText(
            risk_rect,
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter,
            self._risk,
        )
        p.end()

    def _risk_color(self) -> str:
        if self._risk == "High Risk":
            return C.SUSPICIOUS
        if self._risk in ("Suspicious", "Medium"):
            return C.WARNING
        return C.SUCCESS
