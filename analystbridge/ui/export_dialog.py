"""Polished SOC Action Pack export dialog.

Shows the analyst:
  * Output directory (with [...] picker)
  * Per-artifact checkboxes (all selected by default)
  * AI Assist toggle for AI-enhanced summary — disabled with a "Coming soon"
    badge while the local LLM (Gemma 2, offline) integration is still pending

The dialog returns a populated `ExportSelection` on accept.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from analystbridge.ai import LLMAssistEngine
from analystbridge.exports.action_pack import ARTIFACTS
from analystbridge.ui.theme import C


ARTIFACT_DESCRIPTIONS = {
    "report.md": "Analyst-facing Markdown report (executive summary, MITRE table, IOCs, storyline).",
    "iocs.json": "Structured IOC list with type, severity, confidence, source events.",
    "iocs.csv": "IOC list in CSV form for SIEM / TIP import.",
    "detection_sigma.yml": "Sigma rule with stable UUID and per-technique selectors.",
    "hunting_defender.kql": "Microsoft Defender Advanced Hunting (KQL) blocks.",
    "hunting_splunk.spl": "Splunk SPL hunt searches.",
    "stix2_bundle.json": "STIX 2.1 bundle (Indicators + Malware SDO) for MISP / OpenCTI.",
    "soc_action_pack.json": "Master JSON pack — every section in one file.",
}


@dataclass
class ExportSelection:
    out_dir: Path
    selected: List[str]
    use_ai: bool = False


class ExportDialog(QDialog):
    def __init__(
        self,
        default_out_dir: Path | str = "exports",
        llm_engine: LLMAssistEngine | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Generate SOC Action Pack")
        self.setMinimumWidth(620)
        self.setStyleSheet(parent.styleSheet() if parent else "")

        self._llm = llm_engine or LLMAssistEngine()
        self._checkboxes: dict[str, QCheckBox] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 14)
        layout.setSpacing(12)

        # ---- Heading ------------------------------------------------------
        title = QLabel("Generate SOC Action Pack")
        title.setObjectName("H2")
        subtitle = QLabel(
            "Pick the artifacts to write. Files land in "
            "<code>&lt;output&gt;/&lt;sample_id&gt;/</code> and overwrite any "
            "previous run."
        )
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        # ---- Output directory --------------------------------------------
        dir_row = QHBoxLayout()
        dir_row.setSpacing(8)
        dir_row.addWidget(QLabel("Output directory:"))
        self.dir_edit = QLineEdit(str(default_out_dir))
        dir_row.addWidget(self.dir_edit, 1)
        browse_btn = QPushButton("…")
        browse_btn.setFixedWidth(36)
        browse_btn.setToolTip("Pick a directory")
        browse_btn.clicked.connect(self._on_browse)
        dir_row.addWidget(browse_btn)
        layout.addLayout(dir_row)

        # ---- Artifact list ------------------------------------------------
        artifacts_card = self._make_card("ARTIFACTS")
        for name in ARTIFACTS:
            cb = QCheckBox(name)
            cb.setChecked(True)
            cb.setToolTip(ARTIFACT_DESCRIPTIONS.get(name, ""))
            artifacts_card.layout().addWidget(cb)
            desc = QLabel("    " + ARTIFACT_DESCRIPTIONS.get(name, ""))
            desc.setObjectName("Muted")
            desc.setStyleSheet(f"color: {C.TEXT_MUTED}; padding-left: 18px;")
            artifacts_card.layout().addWidget(desc)
            self._checkboxes[name] = cb
        layout.addWidget(artifacts_card)

        # ---- AI Assist (Beta — coming soon) -------------------------------
        ai_card = self._make_ai_card()
        layout.addWidget(ai_card)

        # ---- Buttons ------------------------------------------------------
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel
        )
        self.generate_btn = QPushButton("Generate")
        self.generate_btn.setObjectName("Primary")
        self.generate_btn.setDefault(True)
        self.generate_btn.clicked.connect(self.accept)
        btns.addButton(self.generate_btn, QDialogButtonBox.ButtonRole.AcceptRole)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    # ------------------------------------------------------------------
    def _make_card(self, header: str) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        card.setStyleSheet(
            f"QFrame#Card {{ background:{C.BG_CARD}; border:1px solid {C.BORDER};"
            f"border-radius:8px; }}"
        )
        v = QVBoxLayout(card)
        v.setContentsMargins(14, 12, 14, 12)
        v.setSpacing(2)
        title = QLabel(header)
        title.setObjectName("H3")
        v.addWidget(title)
        return card

    def _make_ai_card(self) -> QFrame:
        card = self._make_card("AI ASSIST  (BETA — COMING SOON)")
        v = card.layout()

        status = self._llm.status()

        self.ai_checkbox = QCheckBox(
            "Generate AI-enhanced executive summary and analyst Q&A"
        )
        # Disabled until a model is connected
        self.ai_checkbox.setEnabled(status.available)
        self.ai_checkbox.setChecked(False)
        v.addWidget(self.ai_checkbox)

        info = QLabel(
            f"Local model: <b>{status.model}</b>  ·  Backend: <b>{status.backend}</b><br>"
            f"<span style='color:{C.TEXT_MUTED};'>{status.detail}</span>"
        )
        info.setWordWrap(True)
        info.setTextFormat(Qt.TextFormat.RichText)
        info.setStyleSheet(
            f"color: {C.TEXT_DIM}; padding: 4px 0; line-height: 1.5;"
        )
        v.addWidget(info)

        if not status.available:
            badge = QLabel(
                "● Model not detected — runs locally, no cloud, no telemetry. "
                "AI-generated summary will land in a future release."
            )
            badge.setStyleSheet(
                f"background:{C.BG_PANEL_2}; color:{C.WARNING};"
                f"border:1px solid {C.WARNING}; border-radius:6px;"
                f"padding:6px 10px; margin-top:4px;"
            )
            badge.setWordWrap(True)
            v.addWidget(badge)

        return card

    # ------------------------------------------------------------------
    def _on_browse(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self, "Choose output directory", self.dir_edit.text() or "."
        )
        if chosen:
            self.dir_edit.setText(chosen)

    # ------------------------------------------------------------------
    def selection(self) -> ExportSelection:
        selected = [name for name, cb in self._checkboxes.items() if cb.isChecked()]
        return ExportSelection(
            out_dir=Path(self.dir_edit.text() or "exports"),
            selected=selected,
            use_ai=self.ai_checkbox.isChecked() and self.ai_checkbox.isEnabled(),
        )
