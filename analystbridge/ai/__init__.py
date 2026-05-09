"""AI Assist subsystem — pluggable offline LLM integration.

Phase 7 ships the architecture and a deterministic preview (so the GUI can
demo the *experience*) without binding to any specific model yet. A future
adapter (Ollama / llama.cpp) only needs to implement `LLMBackend` and the rest
of the application picks it up automatically.
"""
from analystbridge.ai.llm_assist import (
    AISummary,
    LLMAssistEngine,
    LLMBackend,
    LLMConfig,
    LLMStatus,
)

__all__ = [
    "AISummary",
    "LLMAssistEngine",
    "LLMBackend",
    "LLMConfig",
    "LLMStatus",
]
