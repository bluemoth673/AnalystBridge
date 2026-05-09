"""About page — project credits and team information."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from analystbridge import __version__
from analystbridge.ui.theme import C
from analystbridge.ui.widgets import make_card

TEAM_MEMBERS = (
    "Omar Azab",
    "Mahmoud Abdelnaser",
    "Abdulrahman Najdy",
)
SUPERVISOR = "Dr. Mohamed Hamahmy"


class _PersonChip(QFrame):
    def __init__(self, name: str, role: str, accent: str, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        # Slightly wider so two-word Arabic names + role label fit without
        # any clipping, and let the chip grow vertically if WordWrap kicks in.
        self.setMinimumWidth(260)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(4)

        # initials avatar
        initials = "".join(part[0] for part in name.replace("Dr.", "").split() if part)[:2].upper()
        avatar = QLabel(initials)
        avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        avatar.setFixedSize(44, 44)
        avatar.setStyleSheet(
            f"background:{C.BG_PANEL_2}; color:{accent}; border:1px solid {accent};"
            f"border-radius:22px; font-weight:700; font-size:14px;"
        )

        name_label = QLabel(name)
        name_label.setObjectName("H2")
        name_label.setStyleSheet(f"color:{C.TEXT};")
        name_label.setWordWrap(True)

        role_label = QLabel(role.upper())
        role_label.setObjectName("H3")
        role_label.setStyleSheet(f"color:{accent}; letter-spacing:1px;")
        role_label.setWordWrap(True)

        top = QHBoxLayout()
        top.setSpacing(12)
        top.addWidget(avatar, 0, Qt.AlignmentFlag.AlignTop)
        text_box = QVBoxLayout()
        text_box.setSpacing(2)
        text_box.addWidget(name_label)
        text_box.addWidget(role_label)
        top.addLayout(text_box, 1)
        layout.addLayout(top)


class AboutPage(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        # Outer layout just hosts a scroll area so the page never crops on
        # smaller windows or maximized layouts where the available height
        # changes.
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        outer.addWidget(scroll)

        body = QWidget()
        scroll.setWidget(body)
        root = QVBoxLayout(body)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(12)

        # --- Hero card -----------------------------------------------------
        hero = make_card()
        hl = QVBoxLayout(hero)
        hl.setContentsMargins(28, 24, 28, 24)
        hl.setSpacing(6)

        title = QLabel("AnalystBridge")
        title.setStyleSheet(
            f"font-size: 28px; font-weight: 700; color: {C.TEXT};"
        )
        subtitle = QLabel("Malware Visual Intelligence Engine")
        subtitle.setStyleSheet(f"font-size: 14px; color: {C.ACCENT_2};")
        version = QLabel(f"Version {__version__}  ·  Python · PySide6 · SQLite · networkx")
        version.setObjectName("Muted")

        tagline = QLabel(
            "AnalystBridge converts prerecorded sandbox behaviour logs into an interactive "
            "visual investigation workspace — MITRE ATT&CK mapping, evidence-linked malice "
            "scoring, kill-chain storyline, and ready-to-ship SOC Action Pack outputs."
        )
        tagline.setWordWrap(True)
        tagline.setStyleSheet(f"color: {C.TEXT_DIM}; font-size: 12px; padding-top: 4px;")

        hl.addWidget(title)
        hl.addWidget(subtitle)
        hl.addWidget(version)
        hl.addWidget(tagline)
        root.addWidget(hero)

        # --- Team card -----------------------------------------------------
        team_card = make_card()
        tl = QVBoxLayout(team_card)
        tl.setContentsMargins(20, 18, 20, 18)
        tl.setSpacing(12)

        team_title = QLabel("PROJECT TEAM")
        team_title.setObjectName("H3")
        tl.addWidget(team_title)

        chips_row = QHBoxLayout()
        chips_row.setSpacing(12)
        for name in TEAM_MEMBERS:
            chips_row.addWidget(_PersonChip(name, "Developer", C.ACCENT_2))
        chips_row.addStretch()
        tl.addLayout(chips_row)

        tl.addSpacing(6)
        super_title = QLabel("SUPERVISOR")
        super_title.setObjectName("H3")
        tl.addWidget(super_title)

        super_row = QHBoxLayout()
        super_row.setSpacing(12)
        super_row.addWidget(_PersonChip(SUPERVISOR, "Faculty Supervisor", C.WARNING))
        super_row.addStretch()
        tl.addLayout(super_row)

        root.addWidget(team_card)

        # --- Acknowledgements / Notes -------------------------------------
        notes_card = make_card()
        nl = QVBoxLayout(notes_card)
        nl.setContentsMargins(20, 18, 20, 18)
        nl.setSpacing(6)

        notes_title = QLabel("NOTES")
        notes_title.setObjectName("H3")
        nl.addWidget(notes_title)

        notes_body = QLabel(
            "•  AnalystBridge is a graduation project. It does not execute or detonate "
            "binaries — it analyses prerecorded sandbox JSON only.\n"
            "•  MITRE ATT&CK technique mapping uses ATT&CK v15.\n"
            "•  All network indicators are defanged on export for safe sharing.\n"
            "•  SOC Action Pack outputs include Sigma rules, KQL hunts, Splunk SPL, "
            "JSON/CSV IOCs and a markdown analyst report."
        )
        notes_body.setWordWrap(True)
        notes_body.setStyleSheet(f"color: {C.TEXT_DIM}; line-height: 1.6;")
        nl.addWidget(notes_body)

        root.addWidget(notes_card)

        # --- Roadmap card -------------------------------------------------
        roadmap_card = make_card()
        rl = QVBoxLayout(roadmap_card)
        rl.setContentsMargins(20, 18, 20, 18)
        rl.setSpacing(8)

        roadmap_title = QLabel("ROADMAP")
        roadmap_title.setObjectName("H3")
        rl.addWidget(roadmap_title)

        # Featured: AI Assist
        ai_chip = QFrame()
        ai_chip.setStyleSheet(
            f"background:{C.BG_PANEL_2}; border:1px solid {C.WARNING};"
            f"border-radius:8px; padding:0;"
        )
        ai_layout = QVBoxLayout(ai_chip)
        ai_layout.setContentsMargins(14, 10, 14, 12)
        ai_layout.setSpacing(2)

        ai_head = QLabel(
            f"<span style='color:{C.WARNING};'>● BETA — COMING SOON</span>"
            f"  <span style='color:{C.TEXT}; font-weight:700;'>"
            "AI-Generated SOC Action Pack &amp; Executive Summary</span>"
        )
        ai_head.setTextFormat(Qt.TextFormat.RichText)
        ai_layout.addWidget(ai_head)

        ai_body = QLabel(
            "Drop-in offline LLM (<b>Gemma 2</b>, runs on-device via Ollama or "
            "llama.cpp — no cloud, no telemetry) that rewrites the executive "
            "summary, drafts a containment plan, suggests SIEM hunts and lists "
            "the open questions an analyst should still answer. The toggle is "
            "already in the export dialog and the AI Insights tab — switch on "
            "as soon as a local model is detected."
        )
        ai_body.setWordWrap(True)
        ai_body.setTextFormat(Qt.TextFormat.RichText)
        ai_body.setStyleSheet(f"color: {C.TEXT_DIM}; line-height: 1.55;")
        ai_layout.addWidget(ai_body)

        rl.addWidget(ai_chip)

        # Other planned items
        other = QLabel(
            "<ul style='margin-left:0; padding-left:14px; color:#8a9bbc;'>"
            "<li>CAPE / Cuckoo / Sysmon importers — broader sandbox &amp; "
            "endpoint log support.</li>"
            "<li>MISP integration — push the STIX 2.1 bundle straight into a "
            "TIP instance.</li>"
            "<li>Behaviour similarity comparison across previously analysed "
            "samples.</li>"
            "<li>Packaged Windows installer via PyInstaller for one-click "
            "deployment.</li>"
            "</ul>"
        )
        other.setTextFormat(Qt.TextFormat.RichText)
        other.setWordWrap(True)
        rl.addWidget(other)

        root.addWidget(roadmap_card)
        root.addStretch()
