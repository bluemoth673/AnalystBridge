"""Reports page — lists every SOC Action Pack file generated to date.

Reads the ``exports/`` tree (one subdirectory per sample), shows what's
available, and lets the analyst open the file or its parent folder in the OS
file manager.
"""
from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QDesktopServices
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from analystbridge.ui.theme import C
from analystbridge.ui.widgets import make_card


def _open_in_file_manager(path: Path) -> None:
    if not path.exists():
        return
    if platform.system() == "Windows":
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif platform.system() == "Darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


class ReportsPage(QWidget):
    def __init__(self, exports_root: Path | str = "exports", parent=None) -> None:
        super().__init__(parent)
        self._root = Path(exports_root)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(10)

        # ---- Header card -------------------------------------------------
        head = make_card()
        hl = QVBoxLayout(head)
        hl.setContentsMargins(20, 16, 20, 16)
        hl.setSpacing(4)

        h_top = QHBoxLayout()
        title = QLabel("SOC Action Pack Reports")
        title.setStyleSheet(f"color:{C.TEXT}; font-size:18px; font-weight:700;")
        h_top.addWidget(title)
        h_top.addStretch()

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        h_top.addWidget(self.refresh_btn)

        self.open_root_btn = QPushButton("Open exports/")
        self.open_root_btn.clicked.connect(self._open_root)
        h_top.addWidget(self.open_root_btn)
        hl.addLayout(h_top)

        sub = QLabel(
            "Every Action Pack you generate from the Generate SOC Action Pack "
            "button (or the CLI) lands here. Click Open to launch a file in "
            "the OS default app, or Open folder to inspect the directory."
        )
        sub.setObjectName("Muted")
        sub.setStyleSheet(f"color:{C.TEXT_DIM};")
        sub.setWordWrap(True)
        hl.addWidget(sub)

        outer.addWidget(head)

        # ---- Scroll area for sample reports ------------------------------
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._content = QWidget()
        self._content_layout = QVBoxLayout(self._content)
        self._content_layout.setContentsMargins(0, 0, 0, 0)
        self._content_layout.setSpacing(10)
        self._content_layout.addStretch()
        self._scroll.setWidget(self._content)
        outer.addWidget(self._scroll, 1)

        self.refresh()

    # ------------------------------------------------------------------
    def refresh(self) -> None:
        # Clear existing cards (everything except the trailing stretch).
        while self._content_layout.count() > 1:
            item = self._content_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not self._root.exists():
            self._content_layout.insertWidget(
                self._content_layout.count() - 1,
                self._empty_state(
                    f"<b>No reports yet.</b><br>"
                    f"<span style='color:{C.TEXT_DIM};'>"
                    f"Click 'Generate SOC Action Pack' to write the first one.</span>"
                ),
            )
            return

        sample_dirs = sorted(
            (p for p in self._root.iterdir() if p.is_dir()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not sample_dirs:
            self._content_layout.insertWidget(
                self._content_layout.count() - 1,
                self._empty_state(
                    f"<b>No reports yet.</b><br>"
                    f"<span style='color:{C.TEXT_DIM};'>"
                    f"Click 'Generate SOC Action Pack' to write the first one.</span>"
                ),
            )
            return

        for d in sample_dirs:
            self._content_layout.insertWidget(
                self._content_layout.count() - 1,
                self._sample_card(d),
            )

    def _empty_state(self, html: str) -> QFrame:
        card = make_card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(28, 28, 28, 28)
        label = QLabel(html)
        label.setTextFormat(Qt.TextFormat.RichText)
        label.setWordWrap(True)
        label.setStyleSheet(f"color:{C.TEXT};")
        layout.addWidget(label)
        return card

    def _sample_card(self, sample_dir: Path) -> QFrame:
        card = make_card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(20, 14, 20, 14)
        layout.setSpacing(8)

        header = QHBoxLayout()
        title = QLabel(sample_dir.name)
        title.setStyleSheet(f"color:{C.ACCENT_2}; font-size:13px; font-weight:700;")
        header.addWidget(title)
        header.addStretch()

        open_dir_btn = QPushButton("Open folder")
        open_dir_btn.clicked.connect(lambda: _open_in_file_manager(sample_dir))
        header.addWidget(open_dir_btn)
        layout.addLayout(header)

        files = sorted(p for p in sample_dir.iterdir() if p.is_file())
        if not files:
            empty = QLabel("(empty)")
            empty.setStyleSheet(f"color:{C.TEXT_MUTED};")
            layout.addWidget(empty)
            return card

        for f in files:
            row = QFrame()
            row.setStyleSheet(
                f"background:{C.BG_PANEL_2}; border:1px solid {C.BORDER};"
                f"border-radius:6px;"
            )
            rl = QHBoxLayout(row)
            rl.setContentsMargins(12, 6, 12, 6)
            rl.setSpacing(10)

            name = QLabel(f.name)
            name.setStyleSheet(f"color:{C.TEXT}; font-family: 'Consolas', monospace;")
            rl.addWidget(name, 1)

            size = QLabel(f"{f.stat().st_size:,} bytes")
            size.setStyleSheet(f"color:{C.TEXT_DIM}; font-size:11px;")
            rl.addWidget(size)

            open_btn = QPushButton("Open")
            open_btn.setFixedWidth(70)
            open_btn.clicked.connect(lambda _=False, p=f: QDesktopServices.openUrl(QUrl.fromLocalFile(str(p))))
            rl.addWidget(open_btn)

            layout.addWidget(row)

        return card

    def _open_root(self) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        _open_in_file_manager(self._root)
