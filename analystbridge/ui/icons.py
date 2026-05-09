"""Icon loader for the AnalystBridge GUI.

Two registries are exposed:

  * ``get_kind_pixmap(kind)``   — node icons for the behaviour graph,
    looked up under ``assets/icons/<kind>.png``.
  * ``get_nav_pixmap(name)``    — sidebar navigation icons, looked up under
    ``assets/icons/nav/<name>.png`` first, then falls back to the kind-icon
    registry (so a single ``process.png`` covers both the sidebar item and the
    graph node).

Both registries colour-tint the loaded pixmap to ``C.TEXT`` (a near-white) by
default, so that the typical case — drop in black-on-transparent Heroicons /
Tabler icons — automatically renders white-on-dark, matching the theme. Pass
``tint=None`` to keep the original colours, or any colour string to recolour.

If a PNG is missing, the loader returns ``None`` and the caller falls back to
a coloured geometric glyph so the GUI keeps working before the user drops
icons in.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from PySide6.QtCore import QPointF, QRectF, QSize, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QImage,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)

from analystbridge.ui.theme import C


from analystbridge.paths import ICONS_ROOT as ICON_ROOT, NAV_ICONS_ROOT as NAV_ICON_ROOT

# Some kinds share a fallback icon (network is the umbrella for ip/domain/url).
_KIND_FALLBACKS: dict[str, str] = {
    "ip": "network",
    "ipv4": "network",
    "ipv6": "network",
    "domain": "network",
    "url": "network",
}

# Sidebar items map onto file names under assets/icons/nav/.
_NAV_FALLBACKS: dict[str, str] = {
    "Dashboard": "dashboard",
    "Graph": "graph",
    "Processes": "process",        # also falls back to assets/icons/process.png
    "Network": "network",
    "Files": "file",
    "Registry": "registry",
    "YARA": "yara",
    "MITRE ATT&CK": "mitre",
    "Indicators": "indicators",
    "Compare": "compare",
    "Reports": "reports",
    "Settings": "settings",
    "About": "about",
}

_cache: dict[str, Optional[QPixmap]] = {}


# ---------------------------------------------------------------------------
# Tinting — the magic that turns black icons white
# ---------------------------------------------------------------------------


def tint_pixmap(pix: QPixmap, target: str | QColor) -> QPixmap:
    """Recolour every non-transparent pixel of ``pix`` to ``target``.

    Alpha is preserved, so anti-aliased edges stay smooth. This is what lets
    the user drop in standard Heroicons / Tabler outlines (black-on-transparent)
    and have them render white-on-dark.
    """
    if pix.isNull():
        return pix
    color = QColor(target) if isinstance(target, str) else target
    img = pix.toImage().convertToFormat(QImage.Format.Format_ARGB32_Premultiplied)
    painter = QPainter(img)
    painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
    painter.fillRect(img.rect(), color)
    painter.end()
    return QPixmap.fromImage(img)


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def _load_scaled(path: Path, size: int) -> Optional[QPixmap]:
    if not path.exists():
        return None
    pix = QPixmap(str(path))
    if pix.isNull():
        return None
    return pix.scaled(
        size,
        size,
        Qt.AspectRatioMode.KeepAspectRatio,
        Qt.TransformationMode.SmoothTransformation,
    )


def get_kind_pixmap(
    kind: str,
    size: int = 22,
    tint: Optional[str] = "auto",
) -> Optional[QPixmap]:
    """Return a tinted, scaled QPixmap for ``kind`` or ``None`` if missing.

    ``tint`` semantics:
      * ``"auto"`` (default) — tint to ``C.TEXT`` so dark icons read on dark UI.
      * any colour string  — tint to that colour (used to colour-code by kind).
      * ``None``           — keep the original pixel colours.
    """
    if not kind:
        return None
    cache_key = f"kind:{kind}@{size}/{tint}"
    if cache_key in _cache:
        return _cache[cache_key]

    candidates = [kind]
    if kind in _KIND_FALLBACKS:
        candidates.append(_KIND_FALLBACKS[kind])

    for name in candidates:
        pix = _load_scaled(ICON_ROOT / f"{name}.png", size)
        if pix is None:
            continue
        if tint is not None:
            color = C.TEXT if tint == "auto" else tint
            pix = tint_pixmap(pix, color)
        _cache[cache_key] = pix
        return pix

    _cache[cache_key] = None
    return None


def get_nav_pixmap(
    label: str,
    size: int = 18,
    tint: Optional[str] = "auto",
) -> Optional[QPixmap]:
    """Return the sidebar icon for ``label`` (a NAV_ITEMS entry).

    Looks for ``assets/icons/nav/<name>.png`` first, then falls back to
    ``assets/icons/<name>.png``. If neither exists, draws a procedural glyph
    so every sidebar item has a visual marker even before the user supplies
    PNGs. Procedural glyphs are auto-tinted to ``C.TEXT`` (white) by default
    just like real icons, so they read against the dark theme.
    """
    cache_key = f"nav:{label}@{size}/{tint}"
    if cache_key in _cache:
        return _cache[cache_key]

    name = _NAV_FALLBACKS.get(label, label.lower().replace(" ", "_").replace("&", ""))
    candidates = [
        NAV_ICON_ROOT / f"{name}.png",
        ICON_ROOT / f"{name}.png",
    ]
    for path in candidates:
        pix = _load_scaled(path, size)
        if pix is None:
            continue
        if tint is not None:
            color = C.TEXT if tint == "auto" else tint
            pix = tint_pixmap(pix, color)
        _cache[cache_key] = pix
        return pix

    # Nothing on disk — draw a procedural glyph so the sidebar still renders
    # a recognisable icon for every nav item.
    pix = _procedural_nav_glyph(label, size)
    if pix is not None and tint is not None and tint != "auto":
        pix = tint_pixmap(pix, tint)
    _cache[cache_key] = pix
    return pix


# ---------------------------------------------------------------------------
# Procedural fallback glyphs — pure-Qt drawn icons, one per sidebar item.
# Designed at the same 18 px nominal size as the real icons so swapping is
# zero-effort once the user drops PNGs in.
# ---------------------------------------------------------------------------


def _procedural_nav_glyph(label: str, size: int) -> QPixmap:
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor(C.TEXT))
    pen.setWidthF(1.6)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)

    s = size  # local alias
    pad = 2

    if label == "Dashboard":
        # 2x2 grid of rectangles
        w = (s - pad * 3) / 2
        for i in range(2):
            for j in range(2):
                p.drawRect(QRectF(pad + i * (w + pad), pad + j * (w + pad), w, w))
    elif label == "Graph":
        # Three connected circles
        r = 2.5
        pts = [(s * 0.25, s * 0.5), (s * 0.5, s * 0.25), (s * 0.75, s * 0.65)]
        for x, y in pts:
            p.drawEllipse(QPointF(x, y), r, r)
        p.drawLine(QPointF(*pts[0]), QPointF(*pts[1]))
        p.drawLine(QPointF(*pts[1]), QPointF(*pts[2]))
    elif label == "Processes":
        # Terminal prompt: > _
        path = QPainterPath()
        path.moveTo(s * 0.20, s * 0.30)
        path.lineTo(s * 0.45, s * 0.50)
        path.lineTo(s * 0.20, s * 0.70)
        p.drawPath(path)
        p.drawLine(QPointF(s * 0.55, s * 0.72), QPointF(s * 0.85, s * 0.72))
    elif label == "Network":
        # Globe — circle + two ellipses
        c = QPointF(s / 2, s / 2)
        p.drawEllipse(c, s * 0.40, s * 0.40)
        p.drawEllipse(c, s * 0.20, s * 0.40)
        p.drawLine(QPointF(s * 0.10, s / 2), QPointF(s * 0.90, s / 2))
    elif label == "Files":
        # Document outline with a folded corner
        page = QPainterPath()
        page.moveTo(s * 0.28, s * 0.15)
        page.lineTo(s * 0.62, s * 0.15)
        page.lineTo(s * 0.78, s * 0.32)
        page.lineTo(s * 0.78, s * 0.85)
        page.lineTo(s * 0.28, s * 0.85)
        page.closeSubpath()
        p.drawPath(page)
        # fold
        p.drawLine(QPointF(s * 0.62, s * 0.15), QPointF(s * 0.62, s * 0.32))
        p.drawLine(QPointF(s * 0.62, s * 0.32), QPointF(s * 0.78, s * 0.32))
    elif label == "Registry":
        # Stacked database cylinders
        for y_off in (s * 0.18, s * 0.42, s * 0.66):
            p.drawEllipse(QRectF(s * 0.22, y_off, s * 0.56, s * 0.16))
        p.drawLine(QPointF(s * 0.22, s * 0.26), QPointF(s * 0.22, s * 0.74))
        p.drawLine(QPointF(s * 0.78, s * 0.26), QPointF(s * 0.78, s * 0.74))
    elif label == "YARA":
        # Magnifying glass
        p.drawEllipse(QPointF(s * 0.42, s * 0.42), s * 0.26, s * 0.26)
        p.drawLine(QPointF(s * 0.62, s * 0.62), QPointF(s * 0.85, s * 0.85))
    elif label == "MITRE ATT&CK":
        # Crosshair / target
        c = QPointF(s / 2, s / 2)
        p.drawEllipse(c, s * 0.38, s * 0.38)
        p.drawEllipse(c, s * 0.16, s * 0.16)
        p.drawLine(QPointF(s / 2, s * 0.06), QPointF(s / 2, s * 0.20))
        p.drawLine(QPointF(s / 2, s * 0.80), QPointF(s / 2, s * 0.94))
        p.drawLine(QPointF(s * 0.06, s / 2), QPointF(s * 0.20, s / 2))
        p.drawLine(QPointF(s * 0.80, s / 2), QPointF(s * 0.94, s / 2))
    elif label == "Indicators":
        # Warning triangle with exclamation
        path = QPainterPath()
        path.moveTo(s * 0.5, s * 0.10)
        path.lineTo(s * 0.92, s * 0.85)
        path.lineTo(s * 0.08, s * 0.85)
        path.closeSubpath()
        p.drawPath(path)
        p.drawLine(QPointF(s / 2, s * 0.40), QPointF(s / 2, s * 0.62))
        p.drawPoint(QPointF(s / 2, s * 0.74))
    elif label == "Compare":
        # Two arrows facing each other
        p.drawLine(QPointF(s * 0.10, s * 0.35), QPointF(s * 0.90, s * 0.35))
        p.drawLine(QPointF(s * 0.78, s * 0.22), QPointF(s * 0.92, s * 0.35))
        p.drawLine(QPointF(s * 0.78, s * 0.48), QPointF(s * 0.92, s * 0.35))
        p.drawLine(QPointF(s * 0.10, s * 0.65), QPointF(s * 0.90, s * 0.65))
        p.drawLine(QPointF(s * 0.22, s * 0.52), QPointF(s * 0.08, s * 0.65))
        p.drawLine(QPointF(s * 0.22, s * 0.78), QPointF(s * 0.08, s * 0.65))
    elif label == "Reports":
        # Document with horizontal lines
        p.drawRect(QRectF(s * 0.20, s * 0.12, s * 0.60, s * 0.76))
        for y in (s * 0.30, s * 0.45, s * 0.60, s * 0.75):
            p.drawLine(QPointF(s * 0.30, y), QPointF(s * 0.70, y))
    elif label == "Settings":
        # Gear: outer circle + inner circle + 6 teeth
        c = QPointF(s / 2, s / 2)
        p.drawEllipse(c, s * 0.34, s * 0.34)
        p.drawEllipse(c, s * 0.13, s * 0.13)
        import math as _m
        for i in range(6):
            a = i * _m.pi / 3
            x1 = c.x() + _m.cos(a) * s * 0.34
            y1 = c.y() + _m.sin(a) * s * 0.34
            x2 = c.x() + _m.cos(a) * s * 0.46
            y2 = c.y() + _m.sin(a) * s * 0.46
            p.drawLine(QPointF(x1, y1), QPointF(x2, y2))
    elif label == "About":
        # i-in-a-circle
        c = QPointF(s / 2, s / 2)
        p.drawEllipse(c, s * 0.38, s * 0.38)
        p.drawLine(QPointF(s / 2, s * 0.40), QPointF(s / 2, s * 0.72))
        p.drawPoint(QPointF(s / 2, s * 0.30))
    else:
        # Generic dot fallback
        c = QPointF(s / 2, s / 2)
        p.drawEllipse(c, s * 0.30, s * 0.30)

    p.end()
    return pix


def has_any_icons() -> bool:
    """Used by tests / status — True if at least one PNG has been dropped in."""
    if not ICON_ROOT.exists():
        return False
    if any(p.suffix.lower() == ".png" for p in ICON_ROOT.iterdir()):
        return True
    if NAV_ICON_ROOT.exists():
        return any(p.suffix.lower() == ".png" for p in NAV_ICON_ROOT.iterdir())
    return False
