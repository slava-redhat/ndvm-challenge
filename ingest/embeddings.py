"""Local embeddings via host Ollama (AMD 780M GPU / Vulkan), with model pull.

Keep task prefixes in sync with orchestrator/embeddings.py (nomic-embed-text contract).
"""
import os
import requests

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://host.containers.internal:11434")
EMBED_MODEL = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")
EMBED_DIM = 768
_BATCH = 32


def ensure_model() -> None:
    requests.post(f"{OLLAMA_HOST}/api/pull",
                  json={"model": EMBED_MODEL, "stream": False}, timeout=600).raise_for_status()


def _prefix(text: str, task: str) -> str:
    if text.startswith(("search_document:", "search_query:")):
        return text
    return f"{task}: {text}"


def embed(text: str, *, task: str = "search_document") -> list[float]:
    return embed_batch([text], task=task)[0]


def embed_batch(texts: list[str], *, task: str = "search_document") -> list[list[float]]:
    """Batch embed (Ollama accepts a list). Returns one vector per input text."""
    if not texts:
        return []
    out: list[list[float]] = []
    for i in range(0, len(texts), _BATCH):
        chunk = [_prefix(t, task) for t in texts[i:i + _BATCH]]
        r = requests.post(f"{OLLAMA_HOST}/api/embed",
                          json={"model": EMBED_MODEL, "input": chunk}, timeout=300)
        r.raise_for_status()
        vecs = r.json()["embeddings"]
        if len(vecs) != len(chunk):
            raise ValueError(f"embed batch size mismatch: {len(vecs)} != {len(chunk)}")
        for v in vecs:
            if len(v) != EMBED_DIM:
                raise ValueError(f"expected {EMBED_DIM}-d embedding, got {len(v)}")
        out.extend(vecs)
    return out
