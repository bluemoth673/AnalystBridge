"""Offline LLM Assist — backend interface + deterministic preview generator.

Architecture
------------
* `LLMBackend` is the protocol any concrete adapter (Ollama, llama.cpp,
  llamafile, vLLM, …) must implement.
* `LLMAssistEngine` is the orchestrator the UI talks to. When no backend is
  available — the typical state during the graduation demo — it falls back to
  a *deterministic* preview that derives the AI-style narrative directly from
  the rule-based analysis (`bundle.result`). The output is clearly tagged
  `generated_by_llm = False` so reviewers can see it is not yet model output.

This means the UI ships today with credible content for every screen, and on
the day the model adapter is wired in nothing else changes — `is_available()`
flips to True and `AISummary.generated_by_llm` becomes True.

Default target model: **Gemma 2** (Google, 2024) — 9B-instruct quantised to
Q4_K_M runs comfortably on laptop CPUs/integrated GPUs, fully offline.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Protocol

from analystbridge.ui.services import AnalysisBundle


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class LLMConfig:
    """Configuration for the local LLM. Default values point at Gemma 2 9B."""

    model_name: str = "gemma-2-9b-instruct"
    display_name: str = "Gemma 2 (9B, instruct)"
    quantization: str = "Q4_K_M"
    backend: str = "ollama"  # one of: "ollama", "llama.cpp", "llamafile"
    endpoint: str = "http://127.0.0.1:11434"  # default Ollama port
    context_window: int = 8192
    max_tokens: int = 1024
    temperature: float = 0.2
    offline: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LLMStatus:
    """Run-time status of the local model — surfaced by the UI."""

    available: bool
    backend: str
    model: str
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AISummary:
    """The structured payload the AI Assist produces (or previews)."""

    executive_summary: str
    containment_plan: List[str] = field(default_factory=list)
    suggested_hunts: List[str] = field(default_factory=list)
    open_questions: List[str] = field(default_factory=list)
    confidence: float = 0.0
    model: str = "preview-deterministic"
    generated_by_llm: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Backend protocol — adapters must implement this
# ---------------------------------------------------------------------------


class LLMBackend(Protocol):
    """Minimal contract a real local-model adapter has to honour."""

    def status(self) -> LLMStatus: ...
    def generate_summary(self, bundle: AnalysisBundle, config: LLMConfig) -> AISummary: ...


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class LLMAssistEngine:
    """Orchestrator the UI uses. Optionally wraps a real `LLMBackend`."""

    def __init__(
        self,
        backend: Optional[LLMBackend] = None,
        config: Optional[LLMConfig] = None,
    ) -> None:
        self.backend = backend
        self.config = config or LLMConfig()

    # -- Discovery -----------------------------------------------------------

    def is_available(self) -> bool:
        if self.backend is None:
            return False
        try:
            return bool(self.backend.status().available)
        except Exception:  # noqa: BLE001
            return False

    def status(self) -> LLMStatus:
        if self.backend is None:
            return LLMStatus(
                available=False,
                backend=self.config.backend,
                model=self.config.display_name,
                detail=(
                    "No local model adapter is connected. AI-generated text is "
                    "shown as a deterministic preview derived from rule output. "
                    "Install Ollama and pull `gemma2:9b` to enable."
                ),
            )
        return self.backend.status()

    # -- Generation ----------------------------------------------------------

    def generate_summary(self, bundle: AnalysisBundle) -> AISummary:
        """Always returns an `AISummary` — real if a backend is connected,
        deterministic preview otherwise. The UI never has to branch on this."""
        if self.is_available():
            try:
                return self.backend.generate_summary(bundle, self.config)
            except Exception as exc:  # noqa: BLE001
                preview = build_preview_summary(bundle)
                preview.note = (
                    f"Falling back to preview — backend error: {exc}"
                )
                return preview
        return build_preview_summary(bundle)


# ---------------------------------------------------------------------------
# Deterministic preview — keeps the UI demo-ready before a model is plugged in
# ---------------------------------------------------------------------------


def build_preview_summary(bundle: AnalysisBundle) -> AISummary:
    """Compose AI-style narrative from the existing rule-based analysis.

    This is deterministic (same input → same output) so the preview is testable
    and consistent across screenshots, presentations, and the slide deck.
    """
    sample = bundle.sample
    result = bundle.result

    filename = sample.get("filename") or "this sample"
    platform = sample.get("platform") or "Windows"
    score = result.score.score
    risk = result.score.risk_level

    # ----- Executive summary --------------------------------------------------
    technique_titles = [m.technique_name for m in result.mappings]
    top_techniques = ", ".join(technique_titles[:3]) if technique_titles else "(no techniques mapped)"

    ioc_count = len(result.iocs)
    ioc_types = sorted({i.ioc_type for i in result.iocs})
    ioc_types_text = ", ".join(ioc_types) if ioc_types else "no extracted indicators"

    storyline_titles = [s.title for s in result.storyline]
    arc = " → ".join(storyline_titles) if storyline_titles else "no kill-chain arc reconstructed"

    executive_summary = (
        f"{filename} executes on {platform} with a malice score of {score}/100 "
        f"({risk}). The behaviour matches {len(result.mappings)} MITRE ATT&CK "
        f"techniques — most notably {top_techniques}. The reconstructed arc is: "
        f"{arc}. {ioc_count} unique indicators were extracted across {ioc_types_text}; "
        f"recommend isolating the host, preserving forensic state, and pivoting on "
        f"the network indicators across the fleet before declaring containment."
    )

    # ----- Containment plan ---------------------------------------------------
    containment_plan = _derive_containment_plan(bundle)

    # ----- Suggested hunts ----------------------------------------------------
    suggested_hunts = _derive_hunts(bundle)

    # ----- Open questions for the analyst ------------------------------------
    open_questions = _derive_open_questions(bundle)

    return AISummary(
        executive_summary=executive_summary,
        containment_plan=containment_plan,
        suggested_hunts=suggested_hunts,
        open_questions=open_questions,
        confidence=min(0.95, max(0.5, score / 100.0)),
        model="preview-deterministic",
        generated_by_llm=False,
        note=(
            "Preview content — derived from rule-based analysis. The local LLM "
            "(Gemma 2, offline) will replace this narrative once the adapter is "
            "wired in."
        ),
    )


def _derive_containment_plan(bundle: AnalysisBundle) -> List[str]:
    techniques = {m.technique_id for m in bundle.result.mappings}
    plan: List[str] = []

    plan.append(
        "Network-isolate the host immediately at the switch / disable Wi-Fi to "
        "halt active C2 communication and stop further lateral movement."
    )
    plan.append(
        "Capture volatile state before reboot: full memory image, running "
        "process tree, open handles, and TCP connection table."
    )

    if "T1547.001" in techniques:
        plan.append(
            "Remove the offending Run-key persistence under "
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run after "
            "evidence has been preserved."
        )
    if "T1071.001" in techniques or "T1105" in techniques:
        plan.append(
            "Block the C2 domain and IP at the perimeter proxy and DNS firewall, "
            "then sinkhole the domain to surface other infected hosts."
        )
    if "T1490" in techniques:
        plan.append(
            "Do NOT trust local volume shadow copies for recovery — they were "
            "deleted by the actor. Restore from out-of-band backups."
        )
    if "T1486" in techniques:
        plan.append(
            "Treat all encrypted files as compromised; engage IR and legal before "
            "considering any ransom communication."
        )

    plan.append(
        "Reset credentials for every account that was active on the host during "
        "the execution window; rotate any service-account secrets touched by the "
        "process tree."
    )
    plan.append(
        "Add the SHA256, dropped-payload hashes, and C2 indicators to the "
        "block-list / EDR custom IOC set across the fleet."
    )
    return plan


def _derive_hunts(bundle: AnalysisBundle) -> List[str]:
    techniques = {m.technique_id for m in bundle.result.mappings}
    hunts: List[str] = []

    if "T1059.001" in techniques:
        hunts.append(
            "PowerShell launches with `-enc` / `-EncodedCommand` / `-w hidden` / "
            "`DownloadString` — high-fidelity initial access signal."
        )
    if "T1218.005" in techniques:
        hunts.append(
            "`mshta.exe` spawned by Office, browser, or Explorer — proxy-execution "
            "pattern with very low benign baseline."
        )
    if "T1547.001" in techniques:
        hunts.append(
            "Writes to Run / RunOnce keys by non-installer processes — pivot on "
            "the value-data path to find the persistence binary."
        )
    if "T1490" in techniques:
        hunts.append(
            "`vssadmin delete shadows` / `wbadmin delete catalog` — pre-encryption "
            "anti-recovery preparation, page on first hit."
        )
    if "T1486" in techniques:
        hunts.append(
            "≥5 file renames on a single host into `.locked` / `.encrypted` / "
            "`.crypt` extensions within a 60-second window — late-stage detection."
        )
    if not hunts:
        hunts.append(
            "Hunt for outbound HTTPS to newly-registered domains from interactive "
            "user processes (Office, browsers, scripting hosts)."
        )
    return hunts


def _derive_open_questions(bundle: AnalysisBundle) -> List[str]:
    questions: List[str] = []
    questions.append(
        "How did the dropper reach the host — phishing attachment, drive-by "
        "download, USB, or operator action?"
    )
    questions.append(
        "Are any other hosts in the fleet showing the same Run-key, the same "
        "parent-child process chain, or beaconing to the same C2?"
    )
    questions.append(
        "What user accounts had active sessions on the host during execution, "
        "and which secrets / tokens did those processes touch?"
    )
    questions.append(
        "Are out-of-band backups recent enough to fully restore the impacted "
        "files without paying any ransom?"
    )
    questions.append(
        "Was there any precursor reconnaissance activity (LDAP, SMB enumeration, "
        "credential dumping) in the 72 hours before this sample fired?"
    )
    return questions
