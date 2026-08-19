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


RRF_K = 60  # standard Reciprocal Rank Fusion constant
# Curated mitigation-catalog chunks are the vetted, scored, source-cited option menu
# the retriever exists to surface; PDF prose is supporting depth. Give the catalog a
# small prior worth ~one top rank, applied ONLY to chunks already retrieved as
# relevant (never injects an off-topic option). Not tuned to the eval set.
CURATED_BOOST = 1.0 / (RRF_K + 1)


def rag_search_hybrid(query: str, platform: str | None = None, k: int = 6,
                      pool: int = 20) -> list[dict]:
    """Dense (pgvector) + lexical (Postgres FTS), fused with Reciprocal Rank Fusion.

    Dense catches paraphrase; FTS catches exact identifiers (CVE ids, kpatch,
    NetworkPolicy) that embeddings bury under prose. RRF fuses by RANK, so no score
    calibration between cosine distance and ts_rank is needed. Same platform filter
    as the dense path (personalization). No new dependency — all in the DB we run.
    """
    qvec = _vec_literal(embed(query))
    where, params = "", []
    if platform and platform != "other":
        where = " WHERE metadata->>'platform' IN (%s, 'any')"
        params = [platform]
    with _conn() as c, c.cursor() as cur:
        cur.execute(f"SELECT id FROM doc_chunk{where} "
                    f"ORDER BY embedding <=> %s::vector LIMIT %s", params + [qvec, pool])
        dense = [r[0] for r in cur.fetchall()]
        # lexical: skip rows with no lexeme match; empty query (all stopwords) -> no rows
        lex_where = (where + " AND" if where else " WHERE")
        cur.execute(f"SELECT id FROM doc_chunk{lex_where} "
                    f"tsv @@ plainto_tsquery('english', %s) "
                    f"ORDER BY ts_rank_cd(tsv, plainto_tsquery('english', %s)) DESC LIMIT %s",
                    params + [query, query, pool])
        lexical = [r[0] for r in cur.fetchall()]
        scores: dict = {}
        for ranked in (dense, lexical):
            for rank, doc_id in enumerate(ranked, 1):
                scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (RRF_K + rank)
        if not scores:
            return []
        # Boost curated catalog chunks that are already candidates, then pick top k.
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
