"""Local embeddings via host Ollama (AMD 780M GPU / Vulkan). Claude/Vertex has no embeddings API."""
import os
import requests

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://host.containers.internal:11434")
EMBED_MODEL = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")


def embed(text: str) -> list[float]:
    r = requests.post(f"{OLLAMA_HOST}/api/embed",
                      json={"model": EMBED_MODEL, "input": text}, timeout=120)
    r.raise_for_status()
    return r.json()["embeddings"][0]
