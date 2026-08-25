"""Incremental ingest: mitigation catalog + hardening PDFs -> pgvector.

Idempotent by content hash: each source (yaml/pdf basename) is recorded in
`ingested_source` with a sha256. Unchanged sources are skipped (no re-embed);
changed ones have their old chunks dropped and re-loaded. `INGEST_RESET=1` wipes
the corpus first (full rebuild). Drop hardening PDFs in data/pdfs/ then re-run.

CVE facts are NOT ingested here — runtime uses the live Red Hat Security Data API
(and optional /cve.json search-cache into table `cve`). Embedding CVE blurbs into
RAG caused dense search to return similar wrong-CVE pages as "mitigations".
"""
import glob
import hashlib
import json
import os

import psycopg
import yaml
from pypdf import PdfReader

from embeddings import embed, embed_batch, ensure_model
from fetch_pdfs import GUIDES, build as build_pdf_url

DATA = os.environ.get("DATA_DIR", "/app/data")

def _pdf_platform(product: str) -> str:
    if product == "openshift_container_platform":
        return "openshift"
    if product in {"red_hat_enterprise_linux", "red_hat_insights", "red_hat_satellite"}:
        return "rhel"
    return "other"


PDF_SOURCES = {
    filename: (url, _pdf_platform(product))
    for product, _title, _version, _guide, _guide_title in GUIDES
    for url, filename in [build_pdf_url(product, _title, _version, _guide, _guide_title)]
}


def conn():
    return psycopg.connect(
        host=os.environ.get("PGHOST", "db"), port=os.environ.get("PGPORT", "5432"),
        dbname=os.environ["POSTGRES_DB"], user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
    )


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def ensure_schema(cur):
    cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ingested_source (
            source TEXT PRIMARY KEY, kind TEXT NOT NULL, sha256 TEXT NOT NULL,
            chunks INT NOT NULL DEFAULT 0, ingested_at TIMESTAMPTZ DEFAULT now())""")


def seen(cur, source, digest) -> bool:
    cur.execute("SELECT sha256 FROM ingested_source WHERE source=%s", (source,))
    row = cur.fetchone()
    return bool(row and row[0] == digest)


def mark(cur, source, kind, digest, chunks):
    cur.execute(
        "INSERT INTO ingested_source (source, kind, sha256, chunks) VALUES (%s,%s,%s,%s) "
        "ON CONFLICT (source) DO UPDATE SET kind=EXCLUDED.kind, sha256=EXCLUDED.sha256, "
        "chunks=EXCLUDED.chunks, ingested_at=now()",
        (source, kind, digest, chunks),
    )


def drop_chunks(cur, source):
    cur.execute("DELETE FROM doc_chunk WHERE metadata->>'source' = %s", (source,))


def add_chunk(cur, text, source_url, platform, doc_type, source, embedding=None,
              extra_meta=None):
    meta = {"platform": platform, "doc_type": doc_type, "source": source}
    if extra_meta:
        meta.update(extra_meta)
    emb = embedding if embedding is not None else embed(text, task="search_document")
    cur.execute(
        "INSERT INTO doc_chunk (text, source_url, metadata, embedding) "
        "VALUES (%s,%s,%s::jsonb,%s::vector)",
        (text, source_url, json.dumps(meta), "[" + ",".join(f"{x:.6f}" for x in emb) + "]"),
    )


def chunk(text, size=1200, overlap=150):
    """ponytail: fixed windows; upgrade to sentence-aware splitter if recall dips."""
    out, i, n = [], 0, len(text)
    while i < n:
        out.append(text[i:i + size])
        i += max(1, size - overlap)
    return out


def load_mitigations(cur):
    # ponytail: fail-fast on duplicate catalog_ids across all YAML files
    global_ids: dict[str, str] = {}
    for path in sorted(glob.glob(f"{DATA}/mitigations/*.yaml")):
        doc = yaml.safe_load(open(path, "rb").read())
        src = os.path.basename(path)
        for m in doc.get("mitigations") or []:
            cid = (m.get("id") or "").strip()
            if cid and cid in global_ids:
                raise ValueError(
                    f"Duplicate catalog_id '{cid}' in {src} "
                    f"(first seen in {global_ids[cid]})")
            if cid:
                global_ids[cid] = src

    for path in sorted(glob.glob(f"{DATA}/mitigations/*.yaml")):
        raw = open(path, "rb").read()
        src, digest = os.path.basename(path), sha(raw)
        if seen(cur, src, digest):
            print(f"unchanged: {src}"); continue
        doc = yaml.safe_load(raw)
        platform = doc.get("platform") or "any"
        drop_chunks(cur, src)
        cur.execute("DELETE FROM mitigation WHERE platform=%s", (platform,))
        rows = []
        for m in doc.get("mitigations") or []:
            cid = (m.get("id") or "").strip()
            if not cid:
                raise ValueError(f"{src}: mitigation missing stable id: {m.get('title')}")
            cur.execute(
                "INSERT INTO mitigation (platform, title, action_type, description, "
                "disruption, effectiveness, effort, applies_when, source_url) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (platform, m["title"], m["action_type"], m["description"],
                 m["disruption"], m["effectiveness"], m["effort"],
                 m.get("applies_when"), m.get("source_url")),
            )
            text = (f"[{cid}] {m['title']}. {m['description']} "
                    f"Applies when: {m.get('applies_when') or ''}")
            rows.append((text, m))
        vecs = embed_batch([t for t, _ in rows], task="search_document")
        for (text, m), emb in zip(rows, vecs):
            cid = m["id"].strip()
            add_chunk(cur, text, m.get("source_url", ""), platform, "mitigation", src,
                      embedding=emb,
                      extra_meta={
                          "catalog_id": cid,
                          "action_type": m.get("action_type"),
                          "title": m.get("title"),
                          "description": m.get("description"),
                          "disruption": m.get("disruption"),
                          "effectiveness": m.get("effectiveness"),
                          "effort": m.get("effort"),
                          "components": m.get("components") or [],
                          "exclude_components": m.get("exclude_components") or [],
                          "fix_states": m.get("fix_states") or [],
                          "requires": m.get("requires") or [],
                          "scope": m.get("scope") or "",
                          "steps": m.get("steps") or [],
                      })
        mark(cur, src, "mitigation", digest, len(rows))
        print(f"mitigation loaded: {src} ({len(rows)})")


def load_pdfs(cur):
    # Older ingestions stored only local filenames and a generic platform. Updating
    # metadata does not alter vectors, so unchanged PDFs do not need re-embedding.
    # They must not leak into platform-specific RAG retrieval as generic "any" content.
    cur.execute(
        "UPDATE doc_chunk SET metadata = jsonb_set(metadata, '{platform}', '\"other\"'::jsonb) "
        "WHERE metadata->>'doc_type' = 'pdf' AND metadata->>'platform' = 'any'"
    )
    for path in sorted(glob.glob(f"{DATA}/pdfs/*.pdf")):
        raw = open(path, "rb").read()
        src, digest = os.path.basename(path), sha(raw)
        source_url, platform = PDF_SOURCES.get(src, (src, "any"))
        cur.execute(
            "UPDATE doc_chunk SET source_url = %s, "
            "metadata = jsonb_set(metadata, '{platform}', to_jsonb(%s::text)) "
            "WHERE metadata->>'source' = %s",
            (source_url, platform, src),
        )
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
            add_chunk(cur, t, source_url, platform, "pdf", src, embedding=emb)
        mark(cur, src, "pdf", digest, len(texts))
        print(f"pdf loaded: {src} ({len(texts)} chunks)")


def main():
    ensure_model()
    with conn() as c, c.cursor() as cur:
        ensure_schema(cur)
        if os.environ.get("INGEST_RESET") == "1":
            cur.execute("TRUNCATE doc_chunk, mitigation, cve_product_state, cve, "
                        "ingested_source RESTART IDENTITY CASCADE")
            print("reset: corpus cleared")
        # One-shot cleanup: older builds embedded CVE blurbs into RAG; drop them.
        cur.execute("DELETE FROM doc_chunk WHERE metadata->>'doc_type' = 'cve'")
        cur.execute("DELETE FROM ingested_source WHERE kind = 'cve'")
        load_mitigations(cur)
        load_pdfs(cur)
        c.commit()
    print("ingest complete")


if __name__ == "__main__":
    main()
