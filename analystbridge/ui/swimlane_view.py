"""Temporal Swimlane visualisation for the behaviour graph.

This is a strict, schematic alternative to the spring-force / layered graph
views: every node is positioned on a 2-D grid where

  * **X = timestamp**   (mapped through ``_x_for_ts`` — uniform pixels-per-second)
  * **Y = swimlane**    (one of four horizontal bands, picked by node kind)

so the analyst reads the attack as a left-to-right narrative.

Layout pipeline
---------------

::

    nx.MultiDiGraph
            │
            ▼
    1. compute_layout(g)  — for each node:
           t = earliest event timestamp touching it
           lane = ZONE_BY_KIND[kind]   (1..4)
           (x, y) = (x_for(t), lane_centre_y) + collision-stack offset
            │
            ▼
    2. _route_manhattan(p1, p2)  — orthogonal three-segment elbow,
       chosen so the vertical leg sits in the gap between lanes.
            │
            ▼
    3. _evidence_lines(g, mappings) — for every YARA / detection event,
       drop a dashed vertical line from the detection up to the actor /
       target it fired on (snapped to the same X so the line is straight).

The implementation is intentionally split into small testable functions.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, Optional

import networkx as nx
from PySide6.QtCore import QPointF, QRectF, Qt, Signal, QObject
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetrics,
    QPainter,
    QPainterPath,
    QPen,
    QPolygonF,
)
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsDropShadowEffect,
    QGraphicsItem,
    QGraphicsPathItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from analystbridge.core.mitre_mapper import MitreMapping
from analystbridge.ui.icons import get_kind_pixmap
from analystbridge.ui.theme import C, kind_color


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Each lane covers events of a particular semantic class. The ordering is
# top-to-bottom in the canvas (Network at the top, Detections at the bottom).
LANES = (
    ("Network",     1, "Domains, IPs, URLs and outbound connections."),
    ("Execution",   2, "Process lifecycle, modules, API calls and memory."),
    ("Artifacts",   3, "File-system writes and registry modifications."),
    ("Detections",  4, "YARA hits and behavioural alerts."),
)

ZONE_BY_KIND: dict[str, int] = {
    # Lane 1 — Network
    "domain": 1, "ip": 1, "ipv4": 1, "ipv6": 1, "url": 1, "network": 1,
    # Lane 2 — Execution & runtime
    "process": 2, "memory": 2, "api": 2, "module": 2,
    # Lane 3 — Artifacts
    "file": 3, "registry": 3,
    # Lane 4 — Detections
    "yara": 4,
}

# Layout dimensions — Phase 12 tuned for breathing room. Wider nodes, taller
# lanes, more horizontal density: every adjustment biases toward less
# spaghetti, more schematic.
NODE_W = 260
NODE_H = 62
NODE_VSPACE = 80        # vertical step when stacking colliding nodes
NODE_X_BUDGET = 360     # if two nodes are closer than this in X, stack vertically
LANE_H = 280            # vertical height of a lane (was 220 — bigger zones)
HEADER_H = 4            # vestigial — the in-canvas time ruler is gone, the bottom
                        # Timeline / Replay panel now anchors time
PAD_LEFT = 290          # X coordinate of the *centre* of the leftmost node.
                        # Must be ≥ PAD_LEFT_GUTTER + NODE_W/2 + breathing room
                        # so the leftmost node never overlays the lane label
                        # chip on the gutter (290 − 130 = 160 ≥ 138 + 12 px).
PAD_LEFT_GUTTER = 150   # the chip itself only paints up to 138 px (PAD_LEFT_GUTTER - 12)
PAD_RIGHT = 100
PAD_TOP = 6
PAD_BOTTOM = 30
# Stacking pattern — capped at ±1 so nodes never bleed into adjacent lanes.
# With the larger LANE_H=280 and NODE_VSPACE=78, slot ±1 sits well within the
# ±140 px lane half-height. Anything that doesn't fit in 3 slots gets its X
# bumped by half a budget so bursts of activity spread across the time axis
# rather than stacking outside the lane.
SLOT_PATTERN = (0, +1, -1)

# Pixels per second — the analyst can scale this by zooming the view
# horizontally. Default is calibrated so a typical 5–10 s sandbox capture
# renders well over 1800 px wide, giving each timestamp ~360 px of room
# (>= NODE_W) so adjacent events at the same timestamp never crowd.
DEFAULT_PX_PER_SEC = 380.0


# ---------------------------------------------------------------------------
# Signals delegate (QGraphicsItem can't emit signals directly)
# ---------------------------------------------------------------------------


class _SignalHub(QObject):
    node_clicked = Signal(str)
    node_moved = Signal(str)


# ---------------------------------------------------------------------------
# Coordinate calculation
# ---------------------------------------------------------------------------


@dataclass
class LayoutResult:
    positions: dict[str, tuple[float, float]]  # node_id → (x, y)
    t_min: float
    t_max: float
    px_per_sec: float
    plot_w: float
    plot_h: float

    def x_for(self, ts: float) -> float:
        return PAD_LEFT + max(0.0, ts - self.t_min) * self.px_per_sec

    def lane_centre_y(self, lane: int) -> float:
        return HEADER_H + (lane - 1) * LANE_H + LANE_H / 2

    def total_width(self) -> float:
        return PAD_LEFT + self.plot_w + PAD_RIGHT

    def total_height(self) -> float:
        return HEADER_H + 4 * LANE_H + PAD_BOTTOM


def compute_layout(
    g: nx.MultiDiGraph,
    px_per_sec: float = DEFAULT_PX_PER_SEC,
) -> LayoutResult:
    """Compute (x, y) for every node under the swimlane rules.

    ``px_per_sec`` controls how stretched the X axis is — the only knob the
    analyst-facing zoom controls touch.
    """
    # ----- Collect every (node, timestamp) the graph mentions ----------------
    earliest: dict[str, float] = {}
    timestamps: list[float] = []
    for u, v, _k, data in g.edges(keys=True, data=True):
        ts = float(data.get("ts", 0.0) or 0.0)
        timestamps.append(ts)
        for end in (u, v):
            if end not in earliest or ts < earliest[end]:
                earliest[end] = ts
    for n in g.nodes:
        earliest.setdefault(n, 0.0)

    if not timestamps:
        t_min = t_max = 0.0
    else:
        t_min, t_max = min(timestamps), max(timestamps)
    if t_max - t_min < 0.01:
        t_max = t_min + 1.0  # avoid div-by-zero / over-stretched single point

    plot_w = max(600.0, (t_max - t_min) * px_per_sec)

    def x_for(ts: float) -> float:
        return PAD_LEFT + max(0.0, ts - t_min) * px_per_sec

    # ----- Bucket nodes by lane ----------------------------------------------
    nodes_by_lane: dict[int, list[tuple[str, float]]] = defaultdict(list)
    for n, data in g.nodes(data=True):
        kind = data.get("kind", "")
        lane = ZONE_BY_KIND.get(kind, 3)  # default unknowns into Artifacts
        nodes_by_lane[lane].append((n, x_for(earliest[n])))

    # ----- Vertical stacking on collision ------------------------------------
    # Sweep each lane left-to-right. A node tries the centre slot first, then
    # ±1, ±2 — if all 5 slots collide, instead of stacking further (which
    # would spill into the next lane), we *bump X* by half a budget and try
    # again. That keeps every node inside its semantic lane while still
    # honouring the temporal order.
    positions: dict[str, tuple[float, float]] = {}
    for lane, nodes in nodes_by_lane.items():
        nodes.sort(key=lambda nx_pair: nx_pair[1])
        centre_y = HEADER_H + (lane - 1) * LANE_H + LANE_H / 2
        placed_per_slot: dict[int, list[float]] = defaultdict(list)

        for node_id, x in nodes:
            # Find a (slot, x) pair that doesn't collide.
            tries = 0
            chosen_slot, chosen_x = 0, x
            while tries < 6:
                placed_slot = None
                for slot in SLOT_PATTERN:
                    if all(abs(chosen_x - prev_x) > NODE_X_BUDGET
                           for prev_x in placed_per_slot[slot]):
                        placed_slot = slot
                        break
                if placed_slot is not None:
                    chosen_slot = placed_slot
                    break
                # All slots collided at this X — nudge X forward and retry.
                chosen_x += NODE_X_BUDGET * 0.5
                tries += 1
            placed_per_slot[chosen_slot].append(chosen_x)
            y = centre_y + chosen_slot * NODE_VSPACE
            positions[node_id] = (chosen_x, y)

    return LayoutResult(
        positions=positions,
        t_min=t_min,
        t_max=t_max,
        px_per_sec=px_per_sec,
        plot_w=plot_w,
        plot_h=4 * LANE_H,
    )


# ---------------------------------------------------------------------------
# Manhattan / orthogonal edge routing
# ---------------------------------------------------------------------------


def route_manhattan(
    p1: QPointF,
    p2: QPointF,
    *,
    src_lane: int = 0,
    dst_lane: int = 0,
) -> QPainterPath:
    """Build an orthogonal three-segment path (horizontal → vertical → horizontal).

    The vertical leg sits at half the X-distance, except if the two endpoints
    are in different lanes — in that case we pin the vertical leg to ¾ of the
    distance (closer to the destination) so signals "land" cleanly into their
    target lane like wires landing on a circuit pad.
    """
    path = QPainterPath(p1)
    dx = p2.x() - p1.x()
    dy = p2.y() - p1.y()

    if abs(dx) < 4 and abs(dy) < 4:
        path.lineTo(p2)
        return path

    if abs(dy) < 4:
        # Already on the same horizontal line.
        path.lineTo(p2)
        return path

    if abs(dx) < 4:
        # Already on the same vertical line — straight down.
        path.lineTo(p2)
        return path

    # Pick the elbow's X coordinate.
    if src_lane and dst_lane and src_lane != dst_lane and dx > 0:
        elbow_x = p1.x() + dx * 0.65   # land closer to the target
    else:
        elbow_x = (p1.x() + p2.x()) / 2

    # Three-segment path: H → V → H
    path.lineTo(elbow_x, p1.y())
    path.lineTo(elbow_x, p2.y())
    path.lineTo(p2.x(), p2.y())
    return path


# ---------------------------------------------------------------------------
# Lane bands + time ruler
# ---------------------------------------------------------------------------


class LaneBand(QGraphicsItem):
    """Background band painted across a single lane, with a label gutter."""

    def __init__(self, name: str, lane: int, layout: LayoutResult, parent=None) -> None:
        super().__init__(parent)
        self._name = name
        self._lane = lane
        self._layout = layout
        self.setZValue(-10)

    def boundingRect(self) -> QRectF:
        return QRectF(
            0,
            HEADER_H + (self._lane - 1) * LANE_H,
            self._layout.total_width(),
            LANE_H,
        )

    def paint(self, p: QPainter, option, widget=None) -> None:  # noqa: ARG002
        rect = self.boundingRect()
        # Alternating tint
        bg = QColor(C.BG_PANEL_2 if self._lane % 2 else C.BG_PANEL)
        p.fillRect(rect, QBrush(bg))

        # Top border line
        p.setPen(QPen(QColor(C.BORDER), 1))
        p.drawLine(rect.left(), rect.top(), rect.right(), rect.top())

        # Lane label gutter on the left — vertical chip
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        chip_rect = QRectF(rect.left() + 12, rect.top() + LANE_H / 2 - 18,
                            PAD_LEFT_GUTTER - 24, 36)
        p.setPen(QPen(QColor(_lane_accent(self._lane)), 1.4))
        p.setBrush(QBrush(QColor(C.BG_CARD)))
        p.drawRoundedRect(chip_rect, 8, 8)
        p.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        p.setPen(QPen(QColor(_lane_accent(self._lane))))
        p.drawText(chip_rect, Qt.AlignmentFlag.AlignCenter, self._name.upper())

        # Lane number badge under the label
        p.setFont(QFont("Segoe UI", 7))
        p.setPen(QPen(QColor(C.TEXT_MUTED)))
        zone_rect = QRectF(chip_rect.left(), chip_rect.bottom() + 4,
                           chip_rect.width(), 12)
        p.drawText(zone_rect, Qt.AlignmentFlag.AlignCenter, f"ZONE {self._lane}")


def _lane_accent(lane: int) -> str:
    return {
        1: C.NETWORK,
        2: C.PROCESS,
        3: C.FILE,
        4: C.SUSPICIOUS,
    }.get(lane, C.ACCENT)


class TimeRuler(QGraphicsItem):
    """Top strip with major / minor tick marks plus second labels."""

    def __init__(self, layout: LayoutResult, parent=None) -> None:
        super().__init__(parent)
        self._layout = layout
        self.setZValue(-5)

    def boundingRect(self) -> QRectF:
        return QRectF(0, 0, self._layout.total_width(), HEADER_H)

    def paint(self, p: QPainter, option, widget=None) -> None:  # noqa: ARG002
        layout = self._layout
        rect = self.boundingRect()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(rect, QBrush(QColor(C.BG_CARD)))
        p.setPen(QPen(QColor(C.BORDER), 1))
        p.drawLine(rect.left(), rect.bottom(), rect.right(), rect.bottom())

        # Title in the gutter
        p.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        p.setPen(QPen(QColor(C.TEXT_DIM)))
        p.drawText(QRectF(8, 0, PAD_LEFT - 16, HEADER_H),
                   Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                   "TIMELINE")

        # Choose tick density based on px-per-second so labels never collide.
        pps = layout.px_per_sec
        if pps >= 200:
            major_step, minor_step = 0.5, 0.1
        elif pps >= 80:
            major_step, minor_step = 1.0, 0.2
        elif pps >= 30:
            major_step, minor_step = 2.0, 0.5
        else:
            major_step, minor_step = 5.0, 1.0

        # Minor ticks
        t = layout.t_min
        while t <= layout.t_max + 1e-6:
            x = layout.x_for(t)
            p.setPen(QPen(QColor(C.BORDER_BRIGHT), 1))
            p.drawLine(x, HEADER_H - 6, x, HEADER_H)
            t += minor_step

        # Major ticks + labels
        t = math.floor(layout.t_min / major_step) * major_step
        while t <= layout.t_max + 1e-6:
            if t >= layout.t_min - 1e-6:
                x = layout.x_for(t)
                p.setPen(QPen(QColor(C.ACCENT_2), 1.5))
                p.drawLine(x, HEADER_H - 12, x, HEADER_H)
                p.setFont(QFont("Segoe UI", 8, QFont.Weight.DemiBold))
                p.setPen(QPen(QColor(C.TEXT)))
                label = f"{t:.1f}s" if major_step < 1.0 else f"{int(t)}s"
                p.drawText(QRectF(x - 22, 4, 44, 16),
                           Qt.AlignmentFlag.AlignCenter, label)
            t += major_step


# ---------------------------------------------------------------------------
# Visual items — node, edge, evidence line
# ---------------------------------------------------------------------------


class NodeRect(QGraphicsItem):
    def __init__(self, node_id: str, title: str, sub: str, kind: str,
                 hub: _SignalHub) -> None:
        super().__init__()
        self.node_id = node_id
        self.title = title
        self.sub = sub
        self.kind = kind
        self._hub = hub
        self._highlighted = False
        self._hover = False
        self._pixmap = get_kind_pixmap(kind, 22)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)
        self.setAcceptHoverEvents(True)
        self.setZValue(2)

        glow = QGraphicsDropShadowEffect()
        glow.setBlurRadius(20 if kind != "yara" else 28)
        glow.setOffset(0, 0)
        col = QColor(kind_color(kind))
        # YARA gets a more saturated red glow per the spec.
        if kind == "yara":
            col = QColor(C.SUSPICIOUS)
        col.setAlpha(180)
        glow.setColor(col)
        self.setGraphicsEffect(glow)

    def boundingRect(self) -> QRectF:
        return QRectF(-NODE_W / 2, -NODE_H / 2, NODE_W, NODE_H)

    def set_highlight(self, on: bool) -> None:
        self._highlighted = on
        self.update()

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            self._hub.node_moved.emit(self.node_id)
        return super().itemChange(change, value)

    def mousePressEvent(self, event) -> None:
        self._hub.node_clicked.emit(self.node_id)
        super().mousePressEvent(event)

    def hoverEnterEvent(self, event) -> None:  # noqa: ARG002
        self._hover = True
        self.update()

    def hoverLeaveEvent(self, event) -> None:  # noqa: ARG002
        self._hover = False
        self.update()

    def paint(self, p: QPainter, option, widget=None) -> None:  # noqa: ARG002
        color = QColor(kind_color(self.kind))
        bg = QColor(C.BG_PANEL)
        if self._highlighted:
            bg = QColor(C.BG_CARD)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen_w = 2.4 if (self._highlighted or self._hover or self.isSelected()) else 1.4
        p.setPen(QPen(color, pen_w))
        p.setBrush(QBrush(bg))
        p.drawRoundedRect(self.boundingRect(), 9, 9)

        # Left accent stripe
        stripe = QRectF(-NODE_W / 2 + 1, -NODE_H / 2 + 1, 4, NODE_H - 2)
        p.fillRect(stripe, QBrush(color))

        # Icon area
        icon_x = -NODE_W / 2 + 14
        icon_y = -11
        if self._pixmap is not None and not self._pixmap.isNull():
            p.drawPixmap(int(icon_x), int(icon_y), self._pixmap)
        else:
            disc = QRectF(icon_x, icon_y, 22, 22)
            p.setBrush(QBrush(color))
            p.setPen(QPen(color.darker(140), 1))
            p.drawEllipse(disc)
            p.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            p.setPen(QPen(QColor(C.BG_DEEP)))
            glyph = "M" if self.kind == "memory" else (
                "⚠" if self.kind == "yara" else (self.kind[:1] or "?").upper()
            )
            p.drawText(disc, Qt.AlignmentFlag.AlignCenter, glyph)

        # Text
        text_x = icon_x + 22 + 8
        text_w = NODE_W - (text_x - (-NODE_W / 2)) - 12

        p.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
        p.setPen(QPen(color))
        p.drawText(QRectF(text_x, -NODE_H / 2 + 6, text_w, 12),
                   Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft,
                   self.kind.upper())

        title_font = QFont("Segoe UI", 10, QFont.Weight.DemiBold)
        p.setFont(title_font)
        p.setPen(QPen(QColor(C.TEXT)))
        title = QFontMetrics(title_font).elidedText(
            self.title, Qt.TextElideMode.ElideMiddle, int(text_w)
        )
        p.drawText(QRectF(text_x, -NODE_H / 2 + 18, text_w, 16),
                   Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft,
                   title)

        if self.sub:
            sub_font = QFont("Segoe UI", 8)
            p.setFont(sub_font)
            p.setPen(QPen(QColor(C.TEXT_DIM)))
            sub = QFontMetrics(sub_font).elidedText(
                self.sub, Qt.TextElideMode.ElideMiddle, int(text_w)
            )
            p.drawText(QRectF(text_x, NODE_H / 2 - 14, text_w, 12),
                       Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignLeft,
                       sub)


class EdgeItem(QGraphicsPathItem):
    """Manhattan-routed edge with arrowhead. Reroutes if either endpoint moves."""

    def __init__(
        self,
        src: NodeRect,
        dst: NodeRect,
        action: str,
        ts: float,
        event_type: str,
        event_id: int,
        src_lane: int,
        dst_lane: int,
    ) -> None:
        super().__init__()
        self.event_id = event_id
        self.ts = ts
        self.event_type = event_type
        self._src = src
        self._dst = dst
        self._src_lane = src_lane
        self._dst_lane = dst_lane
        self._action = action
        self._color = QColor(kind_color(event_type))
        self._highlighted = False
        self.label: Optional["EdgeLabel"] = None  # populated by canvas
        self.setZValue(1)
        self.refresh()

    def set_highlight(self, on: bool) -> None:
        self._highlighted = on
        self._apply_pen()

    def _apply_pen(self) -> None:
        color = QColor(self._color)
        if self._highlighted:
            color = QColor(C.ACCENT_2)
        pen = QPen(color)
        pen.setWidthF(2.4 if self._highlighted else 1.4)
        # Subtle dotting for network so the analyst can tell C2 traffic at a glance
        if self.event_type in ("network", "domain", "ip", "url"):
            pen.setStyle(Qt.PenStyle.DashLine)
        pen.setJoinStyle(Qt.PenJoinStyle.MiterJoin)
        pen.setCapStyle(Qt.PenCapStyle.FlatCap)
        self.setPen(pen)

    def refresh(self) -> None:
        p1 = self._exit_point(self._src, towards=self._dst.scenePos())
        p2 = self._enter_point(self._dst, frm=self._src.scenePos())
        path = route_manhattan(p1, p2,
                               src_lane=self._src_lane, dst_lane=self._dst_lane)
        self.setPath(path)
        self._apply_pen()

    @staticmethod
    def _exit_point(node: NodeRect, towards: QPointF) -> QPointF:
        """Pick the right or bottom edge of ``node`` as the start point."""
        c = node.scenePos()
        if towards.x() >= c.x():
            return QPointF(c.x() + NODE_W / 2, c.y())
        return QPointF(c.x() - NODE_W / 2, c.y())

    @staticmethod
    def _enter_point(node: NodeRect, frm: QPointF) -> QPointF:
        c = node.scenePos()
        if frm.x() <= c.x():
            return QPointF(c.x() - NODE_W / 2, c.y())
        return QPointF(c.x() + NODE_W / 2, c.y())

    def paint(self, p: QPainter, option, widget=None) -> None:
        super().paint(p, option, widget)
        path = self.path()
        if path.elementCount() < 2:
            return
        end_e = path.elementAt(path.elementCount() - 1)
        prev_e = path.elementAt(path.elementCount() - 2)
        end = QPointF(end_e.x, end_e.y)
        prev = QPointF(prev_e.x, prev_e.y)
        angle = math.atan2(end.y() - prev.y(), end.x() - prev.x())
        size = 9
        a1 = QPointF(end.x() - size * math.cos(angle - math.pi / 7),
                     end.y() - size * math.sin(angle - math.pi / 7))
        a2 = QPointF(end.x() - size * math.cos(angle + math.pi / 7),
                     end.y() - size * math.sin(angle + math.pi / 7))
        head = QPolygonF([end, a1, a2])
        color = QColor(C.ACCENT_2) if self._highlighted else self._color
        p.setBrush(QBrush(color))
        p.setPen(QPen(color, 0))
        p.drawPolygon(head)


class EdgeLabel(QGraphicsItem):
    """Compact timestamp chip painted near the Manhattan elbow of an edge.

    Renders a rounded pill with the timestamp + (optional) action so the
    analyst can read exact ts on every connection. Designed to be tiny enough
    to drop multiple per second of activity without crowding.
    """

    PADDING = 4
    H = 16

    def __init__(self, edge: "EdgeItem") -> None:
        super().__init__()
        self._edge = edge
        ts = edge.ts
        self._text = f"{ts:.2f}s"
        if edge._action:
            self._text = f"{ts:.2f}s  ·  {edge._action}"
        self._font = QFont("Segoe UI", 8, QFont.Weight.DemiBold)
        self._fm = QFontMetrics(self._font)
        self._w = self._fm.horizontalAdvance(self._text) + self.PADDING * 2
        self._color = edge._color
        self._highlighted = False
        self.setZValue(1.6)
        self.refresh()

    def boundingRect(self) -> QRectF:
        return QRectF(-self._w / 2, -self.H / 2, self._w, self.H)

    def set_highlight(self, on: bool) -> None:
        self._highlighted = on
        self.update()

    def refresh(self) -> None:
        """Place the label near the **destination end** of the edge so each
        timestamp belongs unambiguously to the arrow it sits next to.

        For Manhattan three-segment paths (H → V → H) we pin the label to
        the start of the final horizontal segment (i.e. the second elbow),
        offset just above the line. That way the chip floats right next to
        the arrowhead but never *covers* the destination node.

        For straight same-lane edges we place the label one third of the way
        from the destination, again above the line.
        """
        path = self._edge.path()
        if path.elementCount() >= 4:
            # H → V → H: elbow_a at element 1, elbow_b at element 2,
            # destination at element 3. The "approach" segment is elbow_b → end.
            elbow_b = path.elementAt(2)
            end_pt = path.elementAt(3)
            # Anchor the chip a third of the way along that final segment so
            # it sits next to the arrowhead but doesn't cover the dest node.
            x = elbow_b.x + (end_pt.x - elbow_b.x) * 0.5
            # Slight bias toward the arrow's tip so visually it "ends with" ts.
            self.setPos(x, end_pt.y - self.H - 6)
        else:
            # Straight edge: place near the destination third
            p1 = self._edge._src.scenePos()
            p2 = self._edge._dst.scenePos()
            x = p1.x() + (p2.x() - p1.x()) * 0.7
            self.setPos(x, p2.y() - 18)

    def paint(self, p: QPainter, option, widget=None) -> None:  # noqa: ARG002
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        bg = QColor(C.BG_PANEL_2)
        bg.setAlpha(235)
        accent = QColor(C.ACCENT_2 if self._highlighted else self._color)
        p.setPen(QPen(accent, 1))
        p.setBrush(QBrush(bg))
        p.drawRoundedRect(self.boundingRect(), 6, 6)
        p.setFont(self._font)
        p.setPen(QPen(QColor(C.TEXT)))
        p.drawText(self.boundingRect(), Qt.AlignmentFlag.AlignCenter, self._text)


class EvidenceLine(QGraphicsPathItem):
    """Dashed vertical link from a Detection (Zone 4) to its target above."""

    def __init__(self, det: NodeRect, target: NodeRect) -> None:
        super().__init__()
        self._det = det
        self._target = target
        self.setZValue(0.5)
        self.refresh()

    def refresh(self) -> None:
        det = self._det.scenePos()
        tgt = self._target.scenePos()
        # Pure vertical leg from the detection up to the target's lane,
        # then a short horizontal hop (if their X differs).
        path = QPainterPath(QPointF(det.x(), det.y() - NODE_H / 2))
        path.lineTo(det.x(), tgt.y() + NODE_H / 2)
        if abs(det.x() - tgt.x()) > 2:
            path.lineTo(tgt.x(), tgt.y() + NODE_H / 2)
        self.setPath(path)
        pen = QPen(QColor(C.SUSPICIOUS))
        pen.setStyle(Qt.PenStyle.DashLine)
        pen.setWidthF(1.4)
        pen.setDashPattern([4, 3])
        self.setPen(pen)


# ---------------------------------------------------------------------------
# Canvas + public widget
# ---------------------------------------------------------------------------


class _SwimlaneCanvas(QGraphicsView):
    node_clicked = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self._hub = _SignalHub()
        self._hub.node_clicked.connect(self.node_clicked.emit)
        self._hub.node_moved.connect(self._on_node_moved)

        self.setRenderHints(
            QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing
        )
        self.setBackgroundBrush(QBrush(QColor(C.BG_PANEL)))
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setDragMode(QGraphicsView.DragMode.NoDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)

        self._nodes: dict[str, NodeRect] = {}
        self._node_lane: dict[str, int] = {}
        self._edges: list[EdgeItem] = []
        self._edge_labels: list = []
        self._edges_by_node: dict[str, list[EdgeItem]] = defaultdict(list)
        self._evidence: list[EvidenceLine] = []
        self._callouts: list = []  # kept for back-compat with tests
        self._mappings: list[MitreMapping] = []
        self._current_layout: Optional[LayoutResult] = None
        self._px_per_sec: float = DEFAULT_PX_PER_SEC

    # ---- Public API -------------------------------------------------------

    def set_graph(self, g: nx.MultiDiGraph,
                  mappings: Optional[list[MitreMapping]] = None) -> None:
        self._scene.clear()
        self._nodes.clear()
        self._node_lane.clear()
        self._edges.clear()
        self._edge_labels.clear()
        self._edges_by_node.clear()
        self._evidence.clear()
        self._callouts.clear()
        self._mappings = list(mappings or [])

        if g.number_of_nodes() == 0:
            empty = QGraphicsSimpleTextItem(
                "No graph data — click Load Demo or Load Sample…"
            )
            empty.setBrush(QColor(C.TEXT_MUTED))
            empty.setFont(QFont("Segoe UI", 12))
            self._scene.addItem(empty)
            self.setSceneRect(self._scene.itemsBoundingRect())
            return

        layout = compute_layout(g, px_per_sec=self._px_per_sec)
        self._current_layout = layout

        # ---- Lane backgrounds (the in-canvas time ruler was dropped — the
        # bottom Timeline / Replay panel already anchors time and the time
        # axis is implicit in node X-positions).
        for name, lane, _ in LANES:
            self._scene.addItem(LaneBand(name, lane, layout))

        # ---- Nodes ------
        for node_id, data in g.nodes(data=True):
            kind = data.get("kind", "unknown")
            label = data.get("label") or node_id
            title, sub = _split_node_label(label, kind, data)
            node = NodeRect(node_id, title, sub, kind, self._hub)
            x, y = layout.positions.get(node_id, (PAD_LEFT, layout.lane_centre_y(3)))
            node.setPos(x, y)
            self._scene.addItem(node)
            self._nodes[node_id] = node
            self._node_lane[node_id] = ZONE_BY_KIND.get(kind, 3)

        # ---- Edges ------
        for u, v, _k, data in g.edges(keys=True, data=True):
            if u not in self._nodes or v not in self._nodes:
                continue
            edge = EdgeItem(
                self._nodes[u],
                self._nodes[v],
                action=str(data.get("action") or ""),
                ts=float(data.get("ts", 0) or 0),
                event_type=str(data.get("event_type") or ""),
                event_id=int(data.get("event_id", 0) or 0),
                src_lane=self._node_lane.get(u, 0),
                dst_lane=self._node_lane.get(v, 0),
            )
            self._scene.addItem(edge)
            self._edges.append(edge)
            self._edges_by_node[u].append(edge)
            self._edges_by_node[v].append(edge)

        # ---- Edge timestamp chips with collision avoidance --------------
        # Walk edges in temporal order so labels stack the same way every
        # render. For each placement we test against everything already
        # placed in scene-space and shift Y by ±LABEL_H_GAP until we find an
        # empty slot.
        self._edge_labels: list[EdgeLabel] = []
        placed_rects: list[QRectF] = []
        LABEL_H_GAP = 18
        for edge in sorted(self._edges, key=lambda e: e.ts):
            label = EdgeLabel(edge)
            edge.label = label
            base = QPointF(label.pos())
            # Try the natural elbow position, then nudge upward, then downward.
            offsets = [0, -LABEL_H_GAP, +LABEL_H_GAP, -2 * LABEL_H_GAP, +2 * LABEL_H_GAP]
            chosen_pos = base
            for off in offsets:
                pos = QPointF(base.x(), base.y() + off)
                rect = label.boundingRect().translated(pos)
                if not any(_rects_overlap(rect, prev) for prev in placed_rects):
                    chosen_pos = pos
                    break
            label.setPos(chosen_pos)
            placed_rects.append(label.boundingRect().translated(chosen_pos))
            self._scene.addItem(label)
            self._edge_labels.append(label)

        # ---- Evidence lines from Detections (lane 4) up to their targets
        self._add_evidence_lines(g)

        # ---- Scene rect
        bounds = QRectF(
            0, 0, layout.total_width(), layout.total_height(),
        )
        self.setSceneRect(bounds)
        self.fitInView(bounds, Qt.AspectRatioMode.KeepAspectRatio)
        # When fitInView shrinks the scale below 1.0, scrollbars take over —
        # users can horizontally pan even at fitted zoom.

    def fit_view(self) -> None:
        if self._current_layout is None:
            return
        bounds = QRectF(0, 0,
                        self._current_layout.total_width(),
                        self._current_layout.total_height())
        self.setSceneRect(bounds)
        self.fitInView(bounds, Qt.AspectRatioMode.KeepAspectRatio)

    def set_cutoff(self, ts: Optional[float]) -> None:
        for edge in self._edges:
            visible = ts is None or edge.ts <= ts
            edge.setVisible(visible)
            if edge.label is not None:
                edge.label.setVisible(visible)
        for ev in self._evidence:
            ev.setVisible(True if ts is None else any(
                e.isVisible() and e._dst is ev._target and e.ts <= ts
                for e in self._edges
            ))
        if ts is None:
            for n in self._nodes.values():
                n.setVisible(True)
            return
        active: set[str] = set()
        for e in self._edges:
            if e.isVisible():
                active.add(e._src.node_id)
                active.add(e._dst.node_id)
        for nid, n in self._nodes.items():
            n.setVisible(nid in active)

    def highlight_event_ids(self, event_ids: Iterable[int]) -> None:
        ids = set(event_ids or [])
        if not ids:
            for n in self._nodes.values():
                n.set_highlight(False)
                n.setOpacity(1.0)
            for e in self._edges:
                e.set_highlight(False)
                e.setOpacity(1.0)
                if e.label is not None:
                    e.label.set_highlight(False)
                    e.label.setOpacity(1.0)
            return
        active_nodes: set[str] = set()
        for e in self._edges:
            on = e.event_id in ids
            e.set_highlight(on)
            e.setOpacity(1.0 if on else 0.20)
            if e.label is not None:
                e.label.set_highlight(on)
                e.label.setOpacity(1.0 if on else 0.20)
            if on:
                active_nodes.add(e._src.node_id)
                active_nodes.add(e._dst.node_id)
        for nid, n in self._nodes.items():
            n.set_highlight(nid in active_nodes)
            n.setOpacity(1.0 if nid in active_nodes else 0.30)

    # ---- Zoom -------------------------------------------------------------

    def zoom_x(self, factor: float) -> None:
        """Horizontal-only zoom — re-runs the layout at a new pixels-per-second."""
        self._px_per_sec = max(20.0, min(2000.0, self._px_per_sec * factor))
        # We can't easily re-run set_graph without the original graph. The
        # caller (SwimlaneView.zoom_in / out) does that by reusing the cached
        # graph reference.

    # ---- Internals --------------------------------------------------------

    def _on_node_moved(self, node_id: str) -> None:
        for edge in self._edges_by_node.get(node_id, ()):
            edge.refresh()
            if edge.label is not None:
                edge.label.refresh()
        for ev in self._evidence:
            if ev._det.node_id == node_id or ev._target.node_id == node_id:
                ev.refresh()

    def _add_evidence_lines(self, g: nx.MultiDiGraph) -> None:
        """Drop a dashed vertical line from each Detection node up to whichever
        node the YARA rule (or alert) was fired against."""
        for det_id, det_node in self._nodes.items():
            if self._node_lane.get(det_id) != 4:
                continue
            target_id = self._yara_target_for(g, det_id)
            if target_id is None or target_id not in self._nodes:
                continue
            tgt_node = self._nodes[target_id]
            line = EvidenceLine(det_node, tgt_node)
            self._scene.addItem(line)
            self._evidence.append(line)

    @staticmethod
    def _yara_target_for(g: nx.MultiDiGraph, det_id: str) -> Optional[str]:
        """A YARA hit's evidence target is whichever node the actor pointed at,
        or the actor itself if it's the most direct connection."""
        # Look at incoming edges first (the YARA event's "actor → yara" edge).
        for u, _v, _k in g.in_edges(det_id, keys=True):
            if g.nodes[u].get("kind") in ("file", "process"):
                return u
        # Then outbound (less common — yara → file)
        for _u, v, _k in g.out_edges(det_id, keys=True):
            if g.nodes[v].get("kind") in ("file", "process"):
                return v
        return None

    # ---- Qt overrides -----------------------------------------------------

    def wheelEvent(self, event) -> None:
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            # Ctrl + wheel = horizontal-only timeline zoom.
            zoom_in = event.angleDelta().y() > 0
            factor = 1.20 if zoom_in else 1 / 1.20
            transform = self.transform()
            transform.scale(factor, 1.0)
            self.setTransform(transform)
            event.accept()
            return
        # Plain wheel = uniform zoom.
        zoom_in = event.angleDelta().y() > 0
        factor = 1.15 if zoom_in else 1 / 1.15
        self.scale(factor, factor)
        event.accept()


class SwimlaneView(QWidget):
    """Public widget — just the canvas. The earlier zoom toolbar was removed
    per analyst feedback; the canvas accepts ``Ctrl+wheel`` for horizontal
    zoom, plain wheel for uniform zoom, and the topbar's "Fit View" button
    for reset. The API matches the older ``GraphView`` so existing callers
    keep working unchanged.
    """

    node_clicked = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.canvas = _SwimlaneCanvas(self)
        self.canvas.node_clicked.connect(self.node_clicked.emit)
        layout.addWidget(self.canvas, 1)

        # Cached so we can re-layout on zoom without the caller re-passing.
        self._graph: Optional[nx.MultiDiGraph] = None
        self._mappings: list[MitreMapping] = []

    # ---- Zoom slots (still callable from the topbar / scripts) -----------

    def zoom_in(self) -> None:
        self._rezoom(1.4)

    def zoom_out(self) -> None:
        self._rezoom(1 / 1.4)

    def reset_zoom(self) -> None:
        self.canvas._px_per_sec = DEFAULT_PX_PER_SEC
        self._reapply()

    def _rezoom(self, factor: float) -> None:
        self.canvas.zoom_x(factor)
        self._reapply()

    def _reapply(self) -> None:
        if self._graph is None:
            return
        self.canvas.set_graph(self._graph, mappings=self._mappings)

    # ---- Pass-through API (matches GraphView) -----------------------------

    def set_graph(self, g, mappings=None) -> None:
        self._graph = g
        self._mappings = list(mappings or [])
        self.canvas.set_graph(g, mappings=mappings)

    def fit_view(self) -> None:
        self.canvas.fit_view()

    def set_cutoff(self, ts) -> None:
        self.canvas.set_cutoff(ts)

    def highlight_event_ids(self, ids) -> None:
        self.canvas.highlight_event_ids(ids)

    # Backwards-compat hooks the tests / main_window read directly
    @property
    def _edges(self):
        return self.canvas._edges

    @property
    def _nodes(self):
        return self.canvas._nodes

    @property
    def _callouts(self):
        return self.canvas._callouts


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rects_overlap(a: QRectF, b: QRectF, slack: float = 2.0) -> bool:
    """Axis-aligned overlap test with a small slack so chips that *touch*
    don't count as colliding (looks tidy when timestamps line up)."""
    return not (
        a.right()  + slack <= b.left()
        or b.right()  + slack <= a.left()
        or a.bottom() + slack <= b.top()
        or b.bottom() + slack <= a.top()
    )


def _split_node_label(label: str, kind: str, data: dict) -> tuple[str, str]:
    label = (label or "").strip()
    if kind == "process":
        if "\n" in label:
            top, _, bottom = label.partition("\n")
            return top, bottom
        pid = data.get("pid")
        return label, (f"PID: {pid}" if pid else "")
    if kind == "file":
        if "\\" in label or "/" in label:
            sep = "\\" if "\\" in label else "/"
            base = label.rsplit(sep, 1)[-1]
            parent = label.rsplit(sep, 1)[0]
            return base, parent
        return label, ""
    if kind == "registry":
        if "\\" in label:
            top = label.split("\\", 1)[0]
            tail = "\\" + label.split("\\", 1)[1]
            return top, tail
        return label, ""
    if kind in ("domain", "url", "ip"):
        return label, "443 / HTTPS"
    if kind == "yara":
        return label, "YARA rule"
    if kind == "memory":
        return label, "MEMORY"
    return label, ""
