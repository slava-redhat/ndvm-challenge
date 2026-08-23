# Single Source of Truth (SSoT) — Data Feeds & Hybrid RAG

This document maps every CVE/exploit data source (including local decision
tables such as SSVC) and explains how Hybrid RAG retrieves non-disruptive
mitigation options.

---

## 1. CVE / Exploit Data Sources

### 1.1 Red Hat Security Data API (Authoritative)

**Source:** `https://access.redhat.com/hydra/rest/securitydata/`

**What it provides:**
- **One CVE:** `/cve/{CVE}.json` — canonical fix state, severity, CVSS v3, fixing RHSA/NVRA, affected packages
- **CVE catalog:** `/cve.json` — searchable list (filterable by package, product, severity, date, advisory)

**How we use it:**
```python
# orchestrator/tools.py: RedHatSecurityDataTool
lookup_vuln_finding(cve: str, product: str) -> VulnFinding
# Parses fix_state (Fix deferred / Will not fix / Fixed / Not affected)
# Determines if NDVM applies (only when fix_state = "Fix deferred" etc.)
```

**Caching:** LRU cache per CVE per process (1024-entry max). Network errors propagate; 404s return gracefully.

**Trust tier:** 🛡️ Red Hat official — the highest trust. Never guessed by LLM.

---

### 1.2 CISA Known Exploited Vulnerabilities (KEV)

**Source:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

**What it provides:**
- Binary flag: CVE is exploited in the wild (yes/no)
- Used to rank urgency — "act_now" tier if KEV + high EPSS

**How we use it:**
```python
# orchestrator/priority.py: in_kev(cve: str) -> bool
# TTL-cached (6h refresh) so catalog updates land without restart
```

**Degradation:** If CISA feed unreachable, return `None` (unknown, not "not listed")

**Trust tier:** 🚨 CISA (US government) — authoritative exploitation signal.

---

### 1.3 FIRST EPSS (Exploit Probability Score)

**Source:** `https://api.first.org/data/v1/epss?cve={CVE}`

**What it provides:**
- Floating-point probability (0.0–1.0) of exploitation in the next 30 days
- Percentile rank among all CVEs

**How we use it:**
```python
# orchestrator/priority.py: fetch_epss(cve: str) -> (float, float)
# Returns (epss_score, percentile) or (None, None) if unavailable
# Tiers: high EPSS (>0.75) → "prioritize" / "act_now"
```

**Caching:** Per-CVE, 6h TTL, in-process dict (not shared across replicas yet).

**Degradation:** If FIRST unreachable, degrade to severity-only tiering.

**Trust tier:** 📊 FIRST EPSS — statistical model from public exploit data, not guessed.

---

### 1.4 CISA/SEI SSVC (action decision — not a feed)

**Source:** Local decision table — [CISA SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)
(CISA Stakeholder-Specific Vulnerability Categorization Guide, **Table 9**).
There is **no** EPSS-style “SSVC for CVE-X” API for David’s estate. The CISA
calculator is a web UI; Vulnrichment (when present on a CVE) is CISA’s *own*
coordinator decision, not Meridian’s. NDVM **runs the tree in Python**.

**What it provides:**
- Action priority: `Act` / `Attend` / `Track*` / `Track` (what to *do*)
- Complements KEV/EPSS (likelihood) — does **not** replace them
- Under a change freeze, **Act** means non-disruptive interim mitigation now,
  not an emergency reboot

**How we use it:**
```python
# orchestrator/ssvc.py — CISA Table 9 encoded verbatim
decide_for_context(kev, epss, severity, answers, internet_facing, industry, freeze)
# Inputs derived from existing facts (no new HTTP):
#   Exploitation     ← KEV → active; EPSS ≥ 0.1 → poc; else none
#   Automatable      ← internet-facing estate / answers
#   Technical Impact ← Red Hat severity (Critical/Important → total)
#   Mission+Wellbeing← industry / answers (telecom/health/finance → high)
# Attached onto ExploitSignal via priority.apply_ssvc_context(...)
```

**Caching / network:** None — pure function. No PDF ingest required for SSVC.

**Trust tier:** 🚨 CISA / SEI methodology — deterministic table, LLM never invents the decision.

---

### 1.5 Red Hat Compliance Data (Optional)

**Source:** Insights OpenSCAP posture (loaded into `doc_chunk.metadata`)

**What it provides:**
- Customer compliance scoring per host (OpenSCAP profile, % pass rate)
- Flagged rules (failed security baselines)

**How we use it:**
```python
# orchestrator/priority.py: compliance_signal(account, cve)
# Boosts priority if a CVE affects a host with low compliance score
```

**Trust tier:** 🛡️ Red Hat official (from customer's Insights scan).

---

## 2. Mitigation Catalog (pgvector + FTS)

### 2.1 Data Store

**Database:** Postgres + pgvector extension

**Table:** `doc_chunk` — vectorized mitigation knowledge
```sql
CREATE TABLE doc_chunk (
    id UUID PRIMARY KEY,
    text TEXT,                    -- mitigation prose ("use kpatch", "enable SELinux", etc.)
    source_url TEXT,              -- provenance (Red Hat docs, CISA, etc.)
    metadata JSONB,               -- {platform, doc_type, control_name, ...}
    embedding vector(768),        -- dense (nomic-embed-text)
    tsv tsvector,                 -- lexical (full-text search)
    doc_type TEXT                 -- "mitigation" | "control" | "guidance"
);
```

**Index:** GIN on `tsv` (fast Postgres FTS).

### 2.2 Ingest Pipeline

**Sources ingested into `doc_chunk`:**
1. **YAML mitigations catalog** (`data/mitigations/{rhel,openshift,other}.yaml`)
   - Curated non-disruptive options per platform
   - Scored: disruption (none/low/medium/high), effectiveness (1–4), effort (1–4)
   - Tagged by doc_type = "mitigation"

2. **PDF knowledge base** (`data/pdfs/*.pdf`)
   - Red Hat docs, CISA guidance, best practices
   - Ingested on first launch, stored in DB

3. **Programmatically generated controls**
   - SELinux policies, firewall rules, compliance controls
   - Added dynamically via `account_cves()` lookups

**Embedding:** 
```python
# orchestrator/embeddings.py
embed(text: str, task: str) -> list[float]
# Via Ollama host (AMD 780M GPU, Vulkan)
# Model: nomic-embed-text (768-dim)
# Task-prefix: "search_document:" at ingest, "search_query:" at retrieve
```

---

## 3. Hybrid RAG: Dense + Lexical Fusion

### 3.1 Why Hybrid?

**Problem:** Dense embeddings alone bury exact identifiers.
- CVE ids (CVE-2023-3390)
- Errata (RHSA-2024:2394)
- Package names (kpatch, selinux-policy)
- Platform targets (RHEL 8, OpenShift 4.12)

**Solution:** Combine two rankers:
1. **Dense:** cosine similarity (captures paraphrase)
2. **Lexical:** Postgres full-text search `ts_rank_cd` (catches exact tokens)

### 3.2 Implementation

```python
# orchestrator/db.py: rag_search_hybrid(query, platform, k=6, pool=20)

1. DENSE SEARCH
   SELECT id FROM doc_chunk
   WHERE metadata->>'platform' IN (?, 'any')  -- platform personalization
   ORDER BY embedding <=> qvec::vector LIMIT pool
   # Top 20 by cosine distance

2. LEXICAL SEARCH
   SELECT id FROM doc_chunk
   WHERE metadata->>'platform' IN (?, 'any')
   AND tsv @@ plainto_tsquery('english', ?)  -- exact tokens
   ORDER BY ts_rank_cd(tsv, query) DESC LIMIT pool
   # Top 20 by FTS rank

3. RECIPROCAL RANK FUSION (RRF)
   For each chunk in (dense ∪ lexical):
       score[chunk] += 1/(RRF_K + rank_in_dense)
       score[chunk] += 1/(RRF_K + rank_in_lexical)
   # RRF_K = 60 (standard constant, no calibration needed)

4. CURATED PRIOR
   For chunks where doc_type = 'mitigation' AND already in top pool:
       score[chunk] += CURATED_BOOST  # ~0.016 (one rank boost)
   # Never injects off-topic options; only boosts what's already relevant

5. RETURN
   Top k=6 by fused score (platform-filtered)
```

**Why RRF?**
- Fuses by *rank*, not score → no calibration between cosine distance (unbounded) and `ts_rank_cd` (0–1)
- Proven in TREC retrieval evaluations
- No new dependency (algorithm, not a library)

### 3.3 Measured Impact (from `tests/eval_retrieval.py`)

**Before (dense-only):**
- Recall@6: 0.75
- MRR (Mean Reciprocal Rank): 0.69

**After (hybrid RRF):**
- Recall@6: 0.92 (+17 percentage points)
- MRR: 0.85 (+16 percentage points)

**Notable failure (still missing):**
- SCC "reduce pod privileges" — a genuine semantic gap, not overfit.

---

## 4. Trust Chain: Query → Result

### Flow: Query → Hybrid RAG → LLM → Output

```
User asks:
"My billing system on RHEL 8 is flagged with CVE-2023-3390.
 Can't reboot until quarter-end. What can I do?"

↓ Router extracts: platform=RHEL 8, CVE=CVE-2023-3390, constraint="no reboot"

↓ Analyst tool fetches: Red Hat API → fix_state, severity, CVSS
  Source: 🛡️ access.redhat.com
  Python-parsed: ndvm_applies = True (fix_state = "Fix deferred")

↓ Analyst also checks: CISA KEV (is it exploited?), FIRST EPSS (how likely?)
  Sources: 🚨 cisa.gov, 📊 first.org
  Result: tier = "prioritize" (EPSS = 0.68, not in KEV)

↓ Python also runs: SSVC Table 9 (what should we *do*?)
  Source: 🚨 CISA/SEI method (local) — inputs from KEV/EPSS + estate answers
  Result: ssvc_decision = "attend" (example) · freeze → Act means NDVM interim

↓ Retriever searches: rag_search_hybrid(
     query="non-disruptive mitigation for CVE-2023-3390 on RHEL 8",
     platform="rhel"
  )
  Dense: cosine → top paraphrases
  Lexical: ts_rank → exact CVE hits
  RRF fusion → rank by relevance + curated boost
  Returns: 6 mitigation options
  Sources: 🛡️ Red Hat docs + CISA guidance

↓ Validator checks: "Does SELinux/firewall already mitigate this?"
  Reasons over: control definitions + CVE properties
  Returns: partial mitigation (SELinux; VLANs internal-only)

↓ Strategist ranks: by constraint ("no reboot")
  Scores: disruption (0–4), effectiveness (1–4), effort (1–4)
  Picks: "Deploy kpatch + update SELinux policy" (disruption: none)

↓ Synthesizer writes: explanation, playbook, business-risk summary
  All facts tagged by source tier: 🛡️ 🚨 📊 🏛️

↓ Output: AdviceResult
  {
    "vulnerability": { "cve_id": "CVE-2023-3390", ... },  # ← Python-parsed
    "priority": {  # ← Facts (Python)
      "tier": "prioritize", "in_kev": false, "epss": 0.68,
      "ssvc_decision": "attend", "ssvc_label": "Attend"
    },
    "options": [ ... ],  # ← RAG retrieved + LLM ranked
    "existing_controls": [ ... ],  # ← Validated, not guessed
    "explanation": "...",  # ← LLM narration only
    "audit": [ ... ]  # ← Step-by-step what was consulted (incl. SSVC)
  }
```

---

## 5. Guardrails: Never Hallucinate Data

### Rule: Facts on Tools, Prose on LLM

| Fact | Tool | Python-owned | LLM scope |
|------|------|---|---|
| fix_state | Red Hat API | `cve_parse.analyze_cve_json` | Never; LLM reads Python result |
| CVSS, RHSA | Red Hat API | `cve_parse.analyze_cve_json` | Never |
| In KEV? | CISA feed | `priority.in_kev()` | Never |
| EPSS score | FIRST API | `priority.fetch_epss()` | Never |
| SSVC decision | Local Table 9 | `ssvc.decide_for_context()` | Never; LLM only narrates |
| Available mitigations | pgvector RAG | `db.rag_search_hybrid()` | Never; LLM reads retrieval output |
| Does SELinux mitigate? | ControlValidator agent | LLM + context | LLM reasons; typed `ControlReport` pins verdict |
| Ranking | LLM strategist | — | LLM weighs disruption/eff/effort vs constraint |
| Narration, explanation | — | — | LLM writes prose; facts provided as context |

**Input validation:** All tool inputs validated in Python before any HTTP fetch.

---

## 6. Caching & Resilience

| Source | Cache | TTL | Strategy |
|--------|-------|-----|---|
| Red Hat CVE (one) | lru_cache | 1024 entries / process lifetime | Per-CVE; 404 returns gracefully; network errors propagate |
| Red Hat CVE list | Postgres `cve` table | on successful search | Cache-aside: upsert slim hits after live `/cve.json`; on network failure, best-effort `SELECT` (severity + summary/cve_id ILIKE). Advisory/`after`-only filters need the API. |
| CISA KEV | Frozenset, in-memory | 6h | TTL refresh; returns None (not False) on network error |
| FIRST EPSS | Dict, in-memory | 6h per CVE | Per-CVE cache; (None, None) on unavailable |
| SSVC (Table 9) | — | — | Pure local function; no cache/network |
| RAG embeddings | Postgres + pgvector | ∞ | Immutable after ingest; updated only via schema migration |

**Degradation:** If feeds are unreachable, `priority.classify()` returns:
```python
("routine", "Risk could not be assessed — feeds unreachable. Re-run to get urgency rating.")
```
Never fabricates priority. Tells the user the truth.

---

## 7. Future Improvements

### Roadmap

1. ~~**DB caching for Red Hat CVE list**~~ **Done** — cache-aside in `db.upsert_cve_list_rows` / `search_cve_cache`, wired from `RedHatCveSearchTool`.

2. **Shared EPSS/KEV cache**
   - Move from in-process dict to Redis or Postgres
   - Needed for multi-replica deployments
   - Estimated: +100 lines; new dependency (Redis or just Postgres)

3. **Cross-encoder re-ranker**
   - Add a smaller model after RRF to re-score top-k by semantic relevance
   - Current gap: SCC "reduce pod privileges" still misses (embedding semantic gap)
   - Estimated: +30 lines; new model load (+50MB VRAM)

4. **Compliance-aware RAG weighting**
   - Boost mitigations that address customer's specific failed compliance rules
   - Requires schema migration: `doc_chunk.compliance_tags` (array)
   - Estimated: +50 lines; schema change

---

## 8. SSoT Summary

**What NDVM trusts:**
- ✅ Red Hat Security Data API (fix_state, severity, CVSS, RHSA)
- ✅ CISA KEV (exploitation in the wild)
- ✅ FIRST EPSS (30-day exploit probability)
- ✅ CISA/SEI SSVC Table 9 (action: Act / Attend / Track* / Track — local, not a DB)
- ✅ Local pgvector RAG (non-disruptive mitigation options)
- ✅ Postgres FTS (exact token matching: CVE ids, RHSA, package names)
- ✅ Red Hat Compliance (Insights OpenSCAP posture)

**What NDVM never guesses:**
- ❌ CVE fix states (Python-owned, never LLM)
- ❌ Exploitation status (facts from CISA/FIRST, not model opinion)
- ❌ SSVC action decision (Table 9 in Python, not model opinion)
- ❌ Mitigation existence (RAG-retrieved, not fabricated)
- ❌ Control effectiveness (typed validator verdict, not prose)

**Why Hybrid RAG?**
- Dense (cosine) catches paraphrase; Lexical (FTS) catches exact tokens
- RRF fuses without score calibration
- Measured +17 recall, +16 MRR vs. dense-only
- No new dependencies; all in Postgres

**Audit trail:** Every step is logged (`audit_trail` in result), so users see what was consulted and why they can trust the answer.

---

**Last updated:** 2026-08-23
**Responsible teams:** NDVM core (feed integration) + Retrieval (RAG + indexing)
