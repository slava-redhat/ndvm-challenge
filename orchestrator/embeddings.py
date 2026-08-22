"""Local embeddings via host Ollama (AMD 780M GPU / Vulkan). Claude has no embeddings API.

nomic-embed-text requires task prefixes: search_document at ingest, search_query at retrieve.
"""
import os
import requests

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://host.containers.internal:11434")
EMBED_MODEL = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")
EMBED_DIM = 768


def _prefix(text: str, task: str) -> str:
    if text.startswith(("search_document:", "search_query:")):
        return text
    return f"{task}: {text}"


def embed(text: str, *, task: str = "search_query") -> list[float]:
    r = requests.post(f"{OLLAMA_HOST}/api/embed",
                      json={"model": EMBED_MODEL, "input": _prefix(text, task)}, timeout=120)
    r.raise_for_status()
    vec = r.json()["embeddings"][0]
    if len(vec) != EMBED_DIM:
        raise ValueError(f"expected {EMBED_DIM}-d embedding, got {len(vec)}")
    return vec
