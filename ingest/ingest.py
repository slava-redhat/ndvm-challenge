"""Incremental ingest: mitigation catalog + hardening PDFs + seed CVEs -> pgvector.

Idempotent by content hash: each source (yaml/pdf basename or CVE id) is recorded
in `ingested_source` with a sha256. Unchanged sources are skipped (no re-embed);
changed ones have their old chunks dropped and re-loaded. `INGEST_RESET=1` wipes
the corpus first (full rebuild). Drop hardening PDFs in data/pdfs/ then re-run.
"""
import glob
import hashlib
import json
import os

import psycopg
import requests
import yaml
from pypdf import PdfReader

from embeddings import embed, embed_batch, ensure_model

DATA = os.environ.get("DATA_DIR", "/app/data")
SECDATA = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"
SEED_CVES = os.environ.get(
    "INGEST_CVES",
    "CVE-2024-3094,CVE-2023-3390,CVE-2021-44228,CVE-2022-0847",
).split(",")


def conn():
    return psycopg.connect(
        host=os.environ.get("PGHOST", "db"), port=os.environ.get("PGPORT", "5432"),
        dbname=os.environ["POSTGRES_DB"], user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
    )


def vec(v: list[float]) -> str:
    return "[" + ",".join(f"{x:.6f}" for x in v) + "]"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ponytail: ledger table also lives in db/schema.sql (fresh installs); this
# CREATE IF NOT EXISTS keeps already-provisioned pgdata volumes working too.
def ensure_schema(cur):
    cur.execute(
        "CREATE TABLE IF NOT EXISTS ingested_source ("
        " source TEXT PRIMARY KEY, kind TEXT NOT NULL, sha256 TEXT NOT NULL,"
        " chunks INT NOT NULL DEFAULT 0, ingested_at TIMESTAMPTZ DEFAULT now())"
    )
    # Lexical half of hybrid retrieval (see db.rag_search_hybrid). Idempotent so
    # already-provisioned pgdata volumes gain the column without a full re-init.
    cur.execute("ALTER TABLE doc_chunk ADD COLUMN IF NOT EXISTS tsv tsvector "
                "GENERATED ALWAYS AS (to_tsvector('english', text)) STORED")
    cur.execute("CREATE INDEX IF NOT EXISTS doc_chunk_tsv_idx ON doc_chunk USING GIN (tsv)")


def seen(cur, source, digest) -> bool:
    cur.execute("SELECT sha256 FROM ingested_source WHERE source=%s", (source,))
    row = cur.fetchone()
    return bool(row) and row[0] == digest


def mark(cur, source, kind, digest, chunks):
    cur.execute(
        "INSERT INTO ingested_source (source, kind, sha256, chunks, ingested_at) "
        "VALUES (%s,%s,%s,%s, now()) ON CONFLICT (source) DO UPDATE SET "
        "kind=EXCLUDED.kind, sha256=EXCLUDED.sha256, chunks=EXCLUDED.chunks, "
        "ingested_at=now()",
        (source, kind, digest, chunks),
    )


def drop_chunks(cur, source):
    cur.execute("DELETE FROM doc_chunk WHERE metadata->>'source' = %s", (source,))


def add_chunk(cur, text, source_url, platform, doc_type, source, embedding=None,
              extra_meta: dict | None = None):
    meta = {"platform": platform, "doc_type": doc_type, "source": source}
    if extra_meta:
        meta.update(extra_meta)
    emb = embedding if embedding is not None else embed(text, task="search_document")
    cur.execute(
        "INSERT INTO doc_chunk (text, source_url, metadata, embedding) "
        "VALUES (%s, %s, %s::jsonb, %s::vector)",
        (text, source_url, json.dumps(meta), vec(emb)),
    )


def load_mitigations(cur):
    for path in sorted(glob.glob(f"{DATA}/mitigations/*.yaml")):
        raw = open(path, "rb").read()
        src, digest = os.path.basename(path), sha(raw)
        if seen(cur, src, digest):
            print(f"unchanged: {src}"); continue
        doc = yaml.safe_load(raw)
        platform = doc["platform"]
        drop_chunks(cur, src)
        # Structured scores live in doc_chunk.metadata (runtime RAG); skip write-only
        # mitigation table — Makefile stats count mitigation chunks instead.
        rows = []
        for m in doc["mitigations"]:
            text = f"{m['title']} ({m['action_type']}, disruption={m['disruption']}). " \
                   f"{m['description']} Applies when: {m.get('applies_when','')}"
            rows.append((text, m))
        vecs = embed_batch([t for t, _ in rows], task="search_document")
        for (text, m), emb in zip(rows, vecs):
            add_chunk(cur, text, m.get("source_url", ""), platform, "mitigation", src,
                      embedding=emb,
                      extra_meta={"title": m["title"], "action_type": m["action_type"],
                                  "disruption": m["disruption"],
                                  "effectiveness": m["effectiveness"],
                                  "effort": m["effort"]})
        mark(cur, src, "mitigation", digest, len(rows))
        print(f"mitigations loaded: {src} ({len(rows)})")


def chunk(text: str, size: int = 800, overlap: int = 100):
    text = " ".join(text.split())
    i = 0
    while i < len(text):
        yield text[i:i + size]
        i += size - overlap


def load_pdfs(cur):
    for path in sorted(glob.glob(f"{DATA}/pdfs/*.pdf")):
        raw = open(path, "rb").read()
        src, digest = os.path.basename(path), sha(raw)
        if seen(cur, src, digest):
            print(f"unchanged: {src}"); continue
        try:
            reader = PdfReader(path)
        except Exception as e:
            print(f"skip {src}: {e}"); continue
        full = "\n".join((p.extract_text() or "") for p in reader.pages)
        drop_chunks(cur, src)
        texts = [c for c in chunk(full) if c.strip()]
        vecs = embed_batch(texts, task="search_document") if texts else []
        for t, emb in zip(texts, vecs):
            add_chunk(cur, t, src, "any", "pdf", src, embedding=emb)
        mark(cur, src, "pdf", digest, len(texts))
        print(f"pdf loaded: {src} ({len(texts)} chunks)")


def load_cves(cur):
    for cve in [c.strip() for c in SEED_CVES if c.strip()]:
        try:
            r = requests.get(SECDATA.format(cve=cve),
                             params={"isCompressed": "false"}, timeout=30)
            if r.status_code != 200:
                print(f"skip {cve}: HTTP {r.status_code}"); continue
            digest = sha(r.content)
            data = r.json()
        except Exception as e:
            print(f"skip {cve}: {e}"); continue
        if seen(cur, cve, digest):
            print(f"unchanged: {cve}"); continue
        sev = data.get("threat_severity", "unknown")
        try:
            raw = (data.get("cvss3") or {}).get("cvss3_base_score")
            cvss = float(raw) if raw is not None else None
        except (TypeError, ValueError):
            cvss = None
        summary = (data.get("bugzilla", {}) or {}).get("description") or \
                  " ".join(data.get("details", []) or [])[:500]
        url = f"https://access.redhat.com/security/cve/{cve}"
        drop_chunks(cur, cve)
        cur.execute("DELETE FROM cve_product_state WHERE cve_id=%s", (cve,))
        cur.execute(
            "INSERT INTO cve (cve_id, threat_severity, cvss3, summary, source_url) "
            "VALUES (%s,%s,%s,%s,%s) ON CONFLICT (cve_id) DO UPDATE SET "
            "threat_severity=EXCLUDED.threat_severity, cvss3=EXCLUDED.cvss3, "
            "summary=EXCLUDED.summary, fetched_at=now()",
            (cve, sev, cvss, summary, url),
        )
        for st in data.get("package_state", []) or []:
            cur.execute(
                "INSERT INTO cve_product_state (cve_id, product_name, fix_state) "
                "VALUES (%s,%s,%s)",
                (cve, st.get("product_name"), st.get("fix_state")),
            )
        for rel in data.get("affected_release", []) or []:
            cur.execute(
                "INSERT INTO cve_product_state (cve_id, product_name, fix_state, rhsa, fixed_nvra) "
                "VALUES (%s,%s,'Fixed',%s,%s)",
                (cve, rel.get("product_name"), rel.get("advisory"), rel.get("package")),
            )
        add_chunk(cur, f"{cve} ({sev}). {summary}", url, "any", "cve", cve)
        mark(cur, cve, "cve", digest, 1)
        print(f"cve loaded: {cve} ({sev})")


def main():
    ensure_model()
    with conn() as c, c.cursor() as cur:
        ensure_schema(cur)
        if os.environ.get("INGEST_RESET") == "1":
            cur.execute("TRUNCATE doc_chunk, mitigation, cve_product_state, cve, "
                        "ingested_source RESTART IDENTITY CASCADE")
            print("reset: corpus cleared")
        load_mitigations(cur)
        load_pdfs(cur)
        load_cves(cur)
        c.commit()
    print("ingest complete")


if __name__ == "__main__":
    main()
