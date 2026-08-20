"""Postgres + pgvector access: RAG search over doc_chunk + audit writes."""
import json
import os
from contextlib import contextmanager

import psycopg
from psycopg_pool import ConnectionPool

from embeddings import embed

_pool: ConnectionPool | None = None


def _pool_conninfo() -> str:
    return (
        f"host={os.environ.get('PGHOST', 'db')} "
        f"port={os.environ.get('PGPORT', '5432')} "
        f"dbname={os.environ['POSTGRES_DB']} "
        f"user={os.environ['POSTGRES_USER']} "
        f"password={os.environ['POSTGRES_PASSWORD']}"
    )


def _get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        # ponytail: sized for uvicorn + Crew wave threads; raise if advise concurrency grows
        _pool = ConnectionPool(conninfo=_pool_conninfo(), min_size=1, max_size=8, open=True)
    return _pool


@contextmanager
def _conn():
    with _get_pool().connection() as c:
        yield c


def _vec_literal(v: list[float]) -> str:
    return "[" + ",".join(f"{x:.6f}" for x in v) + "]"


def rag_search(query: str, platform: str | None = None, k: int = 6) -> list[dict]:
    """Dense-only search (eval helper). Production uses rag_search_hybrid."""
    qvec = _vec_literal(embed(query, task="search_query"))
    sql = "SELECT text, source_url, metadata FROM doc_chunk"
    params: list = []
    if platform and platform != "other":
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


RRF_K = 60  # standard Reciprocal Rank Fusion constant
# Curated mitigation-catalog chunks get a small prior worth ~one top rank, applied
# ONLY to chunks already retrieved by dense∪lexical (never injects off-topic options).
CURATED_BOOST = 1.0 / (RRF_K + 1)


def rag_search_hybrid(query: str, platform: str | None = None, k: int = 6,
                      pool: int = 20) -> list[dict]:
    """Dense (pgvector) + lexical (Postgres FTS), fused with Reciprocal Rank Fusion.

    Dense catches paraphrase; FTS catches exact identifiers (CVE ids, kpatch,
    NetworkPolicy) that embeddings bury under prose. RRF fuses by RANK, so no score
    calibration between cosine distance and ts_rank is needed. Same platform filter
    as the dense path (personalization). No new dependency — all in the DB we run.
    """
    qvec = _vec_literal(embed(query, task="search_query"))
    where, params = "", []
    if platform and platform != "other":
        where = " WHERE metadata->>'platform' IN (%s, 'any')"
        params = [platform]
    with _conn() as c, c.cursor() as cur:
        cur.execute(f"SELECT id FROM doc_chunk{where} "
                    f"ORDER BY embedding <=> %s::vector LIMIT %s", params + [qvec, pool])
        dense = [r[0] for r in cur.fetchall()]
        # lexical: one plainto_tsquery via CTE; empty query (all stopwords) -> no rows
        lex_where = (where + " AND" if where else " WHERE")
        cur.execute(
            f"WITH q AS (SELECT plainto_tsquery('english', %s) AS tsq) "
            f"SELECT id FROM doc_chunk{lex_where} tsv @@ (SELECT tsq FROM q) "
            f"ORDER BY ts_rank_cd(tsv, (SELECT tsq FROM q)) DESC LIMIT %s",
            params + [query, pool])
        lexical = [r[0] for r in cur.fetchall()]
        scores: dict = {}
        for ranked in (dense, lexical):
            for rank, doc_id in enumerate(ranked, 1):
                scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (RRF_K + rank)
        if not scores:
            return []
        cand = list(scores)
        cur.execute("SELECT id, text, source_url, metadata FROM doc_chunk WHERE id = ANY(%s)",
                    (cand,))
        rows = {r[0]: r for r in cur.fetchall()}
        for doc_id, r in rows.items():
            if (r[3] or {}).get("doc_type") == "mitigation":
                scores[doc_id] += CURATED_BOOST
        top = sorted(scores, key=scores.get, reverse=True)[:k]
        return [{"text": rows[i][1], "source_url": rows[i][2], "metadata": rows[i][3]}
                for i in top if i in rows]


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
