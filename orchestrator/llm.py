"""Reasoning LLM = corporate Claude via Vertex (LiteLLM route, ADC mounted).

Maps the standard Anthropic-on-Vertex env vars (ANTHROPIC_VERTEX_PROJECT_ID,
CLOUD_ML_REGION) onto what LiteLLM/CrewAI read.

Provider tiering: NDVM_LLM_PROVIDER selects which backend get_llm() builds.
Default stays "vertex" (corporate Claude) so existing behavior is unchanged.
An "openai" tier is wired in for cheap/fast agent runs (e.g. cost-sensitive
users) but is inactive until NDVM_LLM_PROVIDER=openai is set and
OPENAI_API_KEY is exported.
"""
import os
from crewai import LLM

_PROJECT = os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID") or os.environ.get("VERTEXAI_PROJECT")
_LOCATION = os.environ.get("CLOUD_ML_REGION") or os.environ.get("VERTEXAI_LOCATION", "us-east5")
if _PROJECT:
    os.environ.setdefault("VERTEXAI_PROJECT", _PROJECT)
os.environ.setdefault("VERTEXAI_LOCATION", _LOCATION)

_MODEL = os.environ.get("NDVM_LLM_MODEL", "vertex_ai/claude-sonnet-4-5@20250929")
# Fast tier (router, RAG retriever, Wave C synth). Prefer Haiku when Model Garden allows it.
_FAST_MODEL = os.environ.get("NDVM_FAST_LLM_MODEL", "vertex_ai/claude-haiku-4-5@20251001")
_TIMEOUT = float(os.environ.get("NDVM_LLM_TIMEOUT", "90"))

# --- OpenAI tier (opt-in, not active by default) -----------------------------
# Set NDVM_LLM_PROVIDER=openai + OPENAI_API_KEY to switch a deployment/user
# tier to OpenAI's cheap/fast models instead of Vertex Claude. Model strings
# use LiteLLM's "openai/<model>" convention, e.g. openai/gpt-4o-mini.
_PROVIDER = os.environ.get("NDVM_LLM_PROVIDER", "vertex")  # "vertex" (default) | "openai"
_OPENAI_MODEL = os.environ.get("NDVM_OPENAI_LLM_MODEL", "openai/gpt-4o-mini")
_OPENAI_FAST_MODEL = os.environ.get("NDVM_OPENAI_FAST_LLM_MODEL", "openai/gpt-4o-mini")
_OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")


def get_llm(temperature: float = 0.2, fast: bool = False,
            timeout: float | None = None, max_tokens: int | None = None,
            provider: str | None = None) -> LLM:
    provider = provider or _PROVIDER
    resolved_timeout = timeout if timeout is not None else _TIMEOUT

    if provider == "openai":
        # Cheap/fast tier: routes agents through OpenAI instead of Vertex.
        if not _OPENAI_API_KEY:
            raise RuntimeError("NDVM_LLM_PROVIDER=openai requires OPENAI_API_KEY to be set")
        return LLM(model=_OPENAI_FAST_MODEL if fast else _OPENAI_MODEL,
                   temperature=temperature, api_key=_OPENAI_API_KEY,
                   timeout=resolved_timeout, max_tokens=max_tokens)

    # Default: corporate Claude via Vertex.
    return LLM(model=_FAST_MODEL if fast else _MODEL, temperature=temperature,
               vertex_project=_PROJECT, vertex_location=_LOCATION,
               timeout=resolved_timeout, max_tokens=max_tokens)
