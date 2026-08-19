# NDVM — Non-Disruptive Vulnerability Mitigation (Challenge 2)

When patching isn't feasible yet, David (a Platform Owner) describes his environment
and a CVE and immediately gets **viable mitigation options → risk trade-offs → a
recommended approach** — each **trusted** (traceable to Red Hat security data) and
**personalized** to his platform. A CrewAI multi-agent flow does the reasoning.

See [`DESIGN.md`](DESIGN.md) for the architecture, [`CONTEXT.md`](CONTEXT.md) for the
glossary, and [`docs/adr/`](docs/adr) for decisions.

## How it works
A **router** agent classifies the user (Primary customer vs Secondary Red Hat TAM)
and scopes the situation, then routes to a crew:

```
Router ─▶ Profiler ─▶ CVE Researcher ─▶ Vulnerability Analyst ─▶ Mitigation Retriever ─▶ Strategist ─▶ Advisor / TAM Briefer
                      (RH CVE catalog)    (RH Security Data)       (local RAG, pgvector)    (ranking)   (persona-specific)
```

The **CVE Researcher** searches Red Hat's public CVE catalog (the data behind
`access.redhat.com/security/security-updates`) by package / product / severity / date,
or pivots an RHSA advisory to its CVEs — so a customer who names *software* but no CVE
still gets grounded findings. No login required (that catalog is public; your Red Hat
account only matters for per-system Insights data, which is out of scope here).

Trust comes from Red Hat's own data: the Analyst reads each CVE's **`fix_state`**
(`Fix deferred` / `Will not fix` = "patching isn't feasible", the NDVM trigger) and
VEX (`known_not_affected` = provable "do nothing"). Every option cites its source.

## Services (podman-compose)
| service | role |
|---|---|
| `db` | Postgres + pgvector — vectors **and** relational facts/audit (one DB) |
| `ingest` | one-shot: mitigation catalog + PDFs + seed CVEs → pgvector |
| `orchestrator` | FastAPI + CrewAI flow (`POST /advise`) |
| `ui` | Streamlit chat + ranked option cards |

Embeddings use your **host Ollama** (`nomic-embed-text`) on the AMD 780M GPU via
Vulkan, reached at `host.containers.internal:11434` — no ollama container.

## Prerequisites
- podman + `podman compose`
- Corporate Claude on Vertex reachable via ADC:
  `gcloud auth application-default login` (creates `~/.config/gcloud/application_default_credentials.json`, mounted read-only into the containers)
- **Host Ollama serving on all interfaces** so containers can reach it (GPU via Vulkan):
  ```bash
  systemctl --user set-environment OLLAMA_HOST=0.0.0.0:11434
  systemctl --user restart ollama
  ollama pull nomic-embed-text   # already present if you've used it
  ```

## Run
```bash
cp .env.example .env
# edit .env: set VERTEXAI_PROJECT, VERTEXAI_LOCATION, and NDVM_LLM_MODEL to your
# corporate Claude-on-Vertex model id.
podman compose --env-file .env up --build
```
`ingest` runs once and exits (it pulls the embed model + loads the corpus). Then open:
- UI: http://localhost:8501
- API: http://localhost:8000/health

> First run must start from a fresh `pgdata` volume so the schema initializes.
> Re-run ingest anytime after adding data: `podman compose run --rm ingest`.

## Demo (David's scenario)
In the UI, leave persona on **Auto-detect** and enter:
> *CVE-2023-3390 is flagged on my RHEL 8 fleet. I can't reboot for patching until
> the quarter-end maintenance window. What can I do right now without breaking production?*

You'll see the router pick the **Customer flow**, the CVE's Red Hat `fix_state`, and
ranked non-disruptive options (disruption / effectiveness / effort) with a recommended
banner and citations. Switch the toggle to **Red Hat Support / TAM** to get the denser,
evidence-first briefing from the same data.

## Make targets
```
make up        # build + start the full stack
make ingest    # incremental: embed only new/changed sources
make reingest  # force full rebuild (clears + re-embeds)
make sources   # the ledger — exactly what's ingested (kind, source, chunks, when)
make stats     # corpus totals
make pdfs      # where to drop PDFs + what's there
make down / make clean   # stop / stop+wipe data volume
```

## Adding platforms / mitigations / CVEs / docs
Ingest is **incremental**: each source (yaml/pdf basename or CVE id) is recorded in
the `ingested_source` ledger with a content hash, so `make ingest` only embeds what's
new or changed (`make sources` shows the ledger).
- Mitigations: drop a `data/mitigations/<platform>.yaml`, `make ingest`.
- Hardening docs: **drop PDFs in `data/pdfs/`**, `make ingest`.
- CVEs: edit `INGEST_CVES` in `.env`, `make ingest`.

## Tests
```bash
cd orchestrator && PYTHONPATH=. python tests/test_cve_parse.py   # trust-critical parser
```
