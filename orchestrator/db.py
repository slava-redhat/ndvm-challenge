"""Postgres + pgvector access: RAG search over doc_chunk + audit writes."""
import json
import os

import psycopg

from embeddings import embed


def _conn():
    return psycopg.connect(
        host=os.environ.get("PGHOST", "db"),
        port=os.environ.get("PGPORT", "5432"),
        dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
    )


def _vec_literal(v: list[float]) -> str:
    return "[" + ",".join(f"{x:.6f}" for x in v) + "]"


def rag_search(query: str, platform: str | None = None, k: int = 6) -> list[dict]:
    """Semantic search with an optional exact platform filter (personalization)."""
    qvec = _vec_literal(embed(query))
    sql = "SELECT text, source_url, metadata FROM doc_chunk"
    params: list = []
    if platform and platform != "other":
        # match this platform OR platform-agnostic docs
        sql += " WHERE metadata->>'platform' IN (%s, 'any')"
        params.append(platform)
    sql += " ORDER BY embedding <=> %s::vector LIMIT %s"
    params += [qvec, k]
    with _conn() as c, c.cursor() as cur:
        cur.execute(sql, params)
        return [
            {"text": t, "source_url": s, "metadata": m}
            for (t, s, m) in cur.fetchall()
        ]


def save_recommendation(payload: dict) -> None:
    with _conn() as c, c.cursor() as cur:
        cur.execute(
            "INSERT INTO recommendation (persona, cve_id, platform, payload) "
            "VALUES (%s, %s, %s, %s)",
            (
                payload.get("persona"),
                payload.get("vulnerability", {}).get("cve_id"),
                payload.get("platform"),
                json.dumps(payload),
            ),
        )
        c.commit()
