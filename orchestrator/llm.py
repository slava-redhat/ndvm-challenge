"""Reasoning LLM = corporate Claude via Vertex (LiteLLM route, ADC mounted).

Maps the standard Anthropic-on-Vertex env vars (ANTHROPIC_VERTEX_PROJECT_ID,
CLOUD_ML_REGION) onto what LiteLLM/CrewAI read.
"""
import os
from crewai import LLM

_PROJECT = os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID") or os.environ.get("VERTEXAI_PROJECT")
_LOCATION = os.environ.get("CLOUD_ML_REGION") or os.environ.get("VERTEXAI_LOCATION", "us-east5")
if _PROJECT:
    os.environ.setdefault("VERTEXAI_PROJECT", _PROJECT)
os.environ.setdefault("VERTEXAI_LOCATION", _LOCATION)

_MODEL = os.environ.get("NDVM_LLM_MODEL", "vertex_ai/claude-sonnet-4-5@20250929")
_FAST_MODEL = os.environ.get("NDVM_FAST_LLM_MODEL", _MODEL)
_TIMEOUT = float(os.environ.get("NDVM_LLM_TIMEOUT", "90"))


def get_llm(temperature: float = 0.2, fast: bool = False,
            timeout: float | None = None) -> LLM:
    return LLM(model=_FAST_MODEL if fast else _MODEL, temperature=temperature,
               vertex_project=_PROJECT, vertex_location=_LOCATION,
               timeout=timeout if timeout is not None else _TIMEOUT)
