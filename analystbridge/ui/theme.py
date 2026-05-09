"""AnalystBridge dark theme — palette + base stylesheet."""
from __future__ import annotations


class C:
    BG_DEEP = "#070d1a"
    BG_PANEL = "#0f1827"
    BG_PANEL_2 = "#131e30"
    BG_CARD = "#172238"
    BORDER = "#1f2c45"
    BORDER_BRIGHT = "#2a3a5f"
    TEXT = "#e6f1ff"
    TEXT_DIM = "#8a9bbc"
    TEXT_MUTED = "#5d6e8e"
    ACCENT = "#3aa9ff"
    ACCENT_2 = "#6cd0ff"
    SUSPICIOUS = "#ff5b5b"
    WARNING = "#ffb84d"
    SUCCESS = "#3edc97"
    PROCESS = "#3aa9ff"
    FILE = "#3edc97"
    NETWORK = "#6cd0ff"
    REGISTRY = "#b384ff"
    YARA = "#ffb84d"


def kind_color(kind: str | None) -> str:
    return {
        "process": C.PROCESS,
        "file": C.FILE,
        "ip": C.NETWORK,
        "domain": C.NETWORK,
        "url": C.NETWORK,
        "network": C.NETWORK,
        "registry": C.REGISTRY,
        "yara": C.YARA,
        "module": C.WARNING,
        "api": C.TEXT_DIM,
        "memory": C.TEXT_MUTED,
    }.get(kind or "", C.TEXT_DIM)


QSS = f"""
/* Only the top-level window paints the deep navy. Every child QWidget stays
   transparent so it inherits the colour of its actual parent (a card, panel,
   or main view) — this is what eliminates the harsh black voids that used to
   show through inside cards and the right-panel. */
QMainWindow, QDialog {{
    background-color: {C.BG_DEEP};
}}
QWidget {{
    color: {C.TEXT};
    font-family: 'Segoe UI', 'Inter', sans-serif;
    font-size: 12px;
}}
QFrame#Card, QFrame#Panel, QFrame#Sidebar, QFrame#TopBar {{
    background-color: {C.BG_PANEL};
    border: 1px solid {C.BORDER};
    border-radius: 8px;
}}
QFrame#Card {{ background-color: {C.BG_CARD}; }}
/* When a wrapper panel sits inside the central widget (e.g. the right-panel
   wrapper, dashboard host, etc.) it can opt-in to the elevated panel tint by
   setting objectName "Surface". */
QWidget#Surface {{ background-color: {C.BG_PANEL}; }}
QWidget#Canvas  {{ background-color: {C.BG_PANEL}; border-radius: 8px; }}
QPushButton {{
    background-color: {C.BG_CARD};
    color: {C.TEXT};
    border: 1px solid {C.BORDER};
    padding: 7px 14px;
    border-radius: 5px;
}}
QPushButton:hover {{ border-color: {C.ACCENT}; color: {C.ACCENT_2}; }}
QPushButton:pressed {{ background-color: {C.BG_PANEL_2}; }}
QPushButton#Primary {{
    background-color: {C.ACCENT};
    color: #021022;
    border: 1px solid {C.ACCENT};
    font-weight: 600;
}}
QPushButton#Primary:hover {{ background-color: {C.ACCENT_2}; border-color: {C.ACCENT_2}; }}
QPushButton#NavItem {{
    text-align: left;
    padding: 9px 14px;
    border-radius: 6px;
    border: 1px solid transparent;
    background-color: transparent;
    color: {C.TEXT_DIM};
}}
QPushButton#NavItem:hover {{ background-color: {C.BG_PANEL_2}; color: {C.TEXT}; }}
QPushButton#NavItem:checked {{
    background-color: {C.BG_CARD};
    border-color: {C.ACCENT};
    color: {C.ACCENT_2};
}}
QLabel#Title {{ font-size: 18px; font-weight: 600; color: {C.TEXT}; }}
QLabel#Subtitle {{ font-size: 11px; color: {C.ACCENT_2}; }}
QLabel#H2 {{ font-size: 14px; font-weight: 600; color: {C.TEXT}; }}
QLabel#H3 {{ font-size: 11px; font-weight: 600; color: {C.TEXT_DIM}; letter-spacing: 0.5px; }}
QLabel#Stat {{ font-size: 22px; font-weight: 700; color: {C.ACCENT_2}; }}
QLabel#Muted {{ color: {C.TEXT_MUTED}; }}
QLabel#Dim {{ color: {C.TEXT_DIM}; }}
QListWidget, QTableWidget, QTableView, QTreeView {{
    background-color: {C.BG_PANEL};
    border: 1px solid {C.BORDER};
    border-radius: 6px;
    selection-background-color: {C.BG_CARD};
    selection-color: {C.ACCENT_2};
    gridline-color: {C.BORDER};
    alternate-background-color: {C.BG_PANEL_2};
}}
QHeaderView::section {{
    background-color: {C.BG_PANEL_2};
    color: {C.TEXT_DIM};
    padding: 4px 8px;
    border: none;
    border-right: 1px solid {C.BORDER};
}}
QTabWidget::pane {{ border: 1px solid {C.BORDER}; border-radius: 6px; top: -1px; }}
QTabBar::tab {{
    background: transparent; color: {C.TEXT_DIM};
    padding: 6px 12px; border: 1px solid transparent;
    border-top-left-radius: 5px; border-top-right-radius: 5px;
}}
QTabBar::tab:selected {{ color: {C.ACCENT_2}; border-color: {C.BORDER}; border-bottom-color: transparent; }}
QSlider::groove:horizontal {{
    border: 1px solid {C.BORDER}; height: 4px;
    background: {C.BG_PANEL_2}; border-radius: 2px;
}}
QSlider::handle:horizontal {{
    background: {C.ACCENT}; width: 14px; margin: -6px 0; border-radius: 7px;
}}
QScrollBar:vertical, QScrollBar:horizontal {{
    background: {C.BG_PANEL_2}; border: none; width: 12px; height: 12px;
    margin: 2px;
}}
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
    background: #c4cee0;
    border-radius: 5px;
    min-height: 28px;
    min-width: 28px;
    border: 1px solid #e6f1ff;
}}
QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {{
    background: #ffffff;
}}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0px; height: 0px; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QStatusBar {{
    background: {C.BG_PANEL}; color: {C.TEXT_DIM};
    border-top: 1px solid {C.BORDER};
}}
QComboBox, QLineEdit {{
    background-color: {C.BG_PANEL_2};
    border: 1px solid {C.BORDER};
    border-radius: 4px;
    padding: 5px 8px;
}}
QGraphicsView {{ border: 1px solid {C.BORDER}; border-radius: 6px; background-color: {C.BG_PANEL}; }}
"""
