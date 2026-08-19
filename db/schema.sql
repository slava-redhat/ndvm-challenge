-- NDVM single DB: pgvector for RAG + relational for facts/audit.
CREATE EXTENSION IF NOT EXISTS vector;

-- RAG corpus chunks (embeddings + provenance).
CREATE TABLE IF NOT EXISTS doc_chunk (
    id          BIGSERIAL PRIMARY KEY,
    text        TEXT NOT NULL,
    source_url  TEXT,
    metadata    JSONB NOT NULL DEFAULT '{}',   -- {platform, cve, doc_type}
    embedding   vector(768) NOT NULL
);
CREATE INDEX IF NOT EXISTS doc_chunk_embedding_idx
    ON doc_chunk USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS doc_chunk_platform_idx
    ON doc_chunk ((metadata->>'platform'));

-- Per-platform mitigation catalog (data-driven; "general" = add rows).
CREATE TABLE IF NOT EXISTS mitigation (
    id            BIGSERIAL PRIMARY KEY,
    platform      TEXT NOT NULL,
    title         TEXT NOT NULL,
    action_type   TEXT NOT NULL,        -- livepatch|selinux|network|disable|config|compensating|verify
    description   TEXT NOT NULL,
    disruption    TEXT NOT NULL,        -- none|low|medium|high
    effectiveness INT  NOT NULL,        -- 1..4
    effort        INT  NOT NULL,        -- 1..4
    applies_when  TEXT,                 -- free-text applicability hint for retrieval
    source_url    TEXT
);

-- CVE facts cache (from Red Hat Security Data API).
CREATE TABLE IF NOT EXISTS cve (
    cve_id         TEXT PRIMARY KEY,
    threat_severity TEXT,
    cvss3          REAL,
    summary        TEXT,
    source_url     TEXT,
    fetched_at     TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS cve_product_state (
    id           BIGSERIAL PRIMARY KEY,
    cve_id       TEXT REFERENCES cve(cve_id) ON DELETE CASCADE,
    product_name TEXT,
    fix_state    TEXT,     -- Affected|Fix deferred|Will not fix|Out of support scope|Not affected|New
    rhsa         TEXT,
    fixed_nvra   TEXT
);

-- Recommendation audit trail (trust = traceable output).
CREATE TABLE IF NOT EXISTS recommendation (
    id           BIGSERIAL PRIMARY KEY,
    persona      TEXT,
    cve_id       TEXT,
    platform     TEXT,
    payload      JSONB NOT NULL,       -- the full AdviceResult
    created_at   TIMESTAMPTZ DEFAULT now()
);
