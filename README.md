# NDVM — Non-Disruptive Vulnerability Mitigation

When patching isn't feasible yet, a Platform Owner describes their environment
and a CVE and immediately gets **viable mitigation options → risk trade-offs → a
recommended approach** — each **trusted** (traceable to Red Hat security data) and
**personalized** to their platform. A CrewAI multi-agent flow does the reasoning, and a
Python "trust spine" (Red Hat `fix_state` + CISA KEV + FIRST EPSS + CISA/SEI SSVC)
supplies the facts so the model never guesses the things that must be right.

## How it works
A **router** agent classifies the user (Primary customer vs Secondary Red Hat TAM),
a **sufficiency gate** refuses to advise until it understands *this* environment
(asking a few tick-box questions if not), then a crew reasons over grounded data:

```
Router ─▶ Sufficiency Gate ─▶ Profiler ─▶ CVE Researcher ─▶ Vulnerability Analyst ─▶ Retriever ─▶ Control Validator ─▶ Strategist ─▶ Advisor / TAM Briefer
         (ask if unclear)                 (RH CVE catalog)   (RH Security Data)      (hybrid RAG)  (already-protected?)  (ranking)   (persona-specific)
```

Alongside the crew, a deterministic **prioritization** step (`orchestrator/priority.py`)
computes exploitation urgency from public feeds — **CISA KEV** (is it being actively
exploited?) and **FIRST EPSS** (30-day exploit probability) — into a tier
(`act_now` / `prioritize` / `scheduled` / `routine`). Separately, **SSVC**
(`orchestrator/ssvc.py`, CISA Table 9) turns those signals plus estate context into an
action decision (`Act` / `Attend` / `Track*` / `Track`). Both are computed in Python,
never LLM-guessed, and drive the UI urgency badge, the ranking prompt, and the
plain-language **business risk** paragraph. Under a change freeze, SSVC **Act** means
apply a non-disruptive interim now — not an emergency reboot.

The **CVE Researcher** searches Red Hat's public CVE catalog (the data behind
`access.redhat.com/security/security-updates`) by package / product / severity / date,
or pivots an RHSA advisory to its CVEs — so a customer who names *software* but no CVE
still gets grounded findings. No login required (that catalog is public; your Red Hat
account only matters for per-system Insights data, simulated here — see below).

Trust comes from Red Hat's own data: the Analyst reads each CVE's **`fix_state`**
(`Fix deferred` / `Will not fix` = "patching isn't feasible", the NDVM trigger) and
VEX (`known_not_affected` = provable "do nothing"). Every option cites its source, and
the UI tags each source by **provenance tier** (Red Hat authoritative → curated catalog
→ external) so trust is visible, not assumed.

## What it does (feature map)
| Capability | Where | Trust mechanism |
|---|---|---|
| **Grounded CVE facts** (fix_state, CVSS, RHSA/NVRA) | Analyst + `redhat_security_data` | parsed in Python from Red Hat's public API |
| **Exploitation urgency** (KEV + EPSS → tier) | `priority.py` | computed from CISA/FIRST feeds, not the LLM |
| **SSVC action decision** (Act / Attend / Track*) | `ssvc.py` | CISA Table 9 in Python; inputs from KEV/EPSS + estate |
| **Non-disruptive options** ranked by disruption/effectiveness/effort | Retriever + Strategist | options only from the local catalog/RAG; each cites a source |
| **"You may already be protected"** | Control Validator | judges only controls the customer *stated* they run |
| **Business-language risk** for a non-technical manager | synth `business_risk` | bounded by severity + exposure + KEV/EPSS + SSVC above |
| **Ask-before-advising** gate | Sufficiency Judge | withholds advice + asks tick-box questions until the case fits |
| **Respond at scale** — rank a whole estate's CVEs | `GET /triage` | KEV+EPSS+SSVC ordering, customer-specific "not affected → routine" |
| **Compliance context** (OpenSCAP) | account estate view | carried from the simulated Insights account |
| **Provenance tiers** on every citation | UI + md/pdf export | source URL classified Red Hat / curated / external |
| **Hybrid retrieval** (dense + lexical) | `db.rag_search_hybrid` | pgvector + Postgres FTS fused with RRF; golden-set eval |

## Services (podman-compose)
| service | role |
|---|---|
| `db` | Postgres + pgvector — vectors **and** relational facts/audit (one DB) |
| `ingest` | one-shot: mitigation YAML catalog + PDFs → pgvector (not CVE pages) |
| `orchestrator` | FastAPI + CrewAI flow (`POST /advise`, `GET /triage`, `GET /accounts`) |
| `ui` | Streamlit chat + ranked option cards + TAM estate/triage board |

Embeddings use your **host Ollama** (`nomic-embed-text`) on the AMD 780M GPU via
Vulkan, reached at `host.containers.internal:11434` — no ollama container.

## Prerequisites
- podman + `podman compose`
- Corporate Claude on Vertex reachable via ADC:
  `gcloud auth application-default login` (creates
  `~/.config/gcloud/application_default_credentials.json`)
- **Host Ollama serving on all interfaces** so containers can reach it (GPU via Vulkan):
  ```bash
  systemctl --user set-environment OLLAMA_HOST=0.0.0.0:11434
  systemctl --user restart ollama
  ollama pull nomic-embed-text   # already present if you've used it
  ```

## Run
```bash
cp .env.example .env
# edit .env: set Vertex project/model values, then copy ADC credentials to the repo.
cp ~/.config/gcloud/application_default_credentials.json .application_default_credentials.json
podman compose --env-file .env up --build
```
`ingest` runs once and exits (it pulls the embed model + loads the corpus). Then open:
- UI: http://localhost:8501
- API: http://localhost:8000/health

> First run must start from a fresh `pgdata` volume so the schema initializes.
> Re-run ingest anytime after adding data: `podman compose run --rm ingest`.

## Demo — Primary
In the UI, leave persona on **Auto-detect** and enter:
> *CVE-2023-3390 is flagged on my RHEL 8 fleet. I can't reboot for patching until
> the quarter-end maintenance window. What can I do right now without breaking production?*

You'll see the router pick the **Customer flow**, the gate confirm/ask about the case,
the CVE's Red Hat `fix_state`, an **urgency badge** (KEV/EPSS tier) plus an **SSVC**
action label (Act/Attend/Track*), ranked
non-disruptive options (disruption / effectiveness / effort) with a recommended banner
and citations, plus a plain-language **business-risk** summary the owner can forward to a
non-technical manager.

Try one without a CVE to see the Researcher discover it:
> *Our RHEL 8 web tier runs an old OpenSSH and I can't take downtime this month —
> what should I worry about and what can I do now?*

## Demo — Secondary (Red Hat Support / TAM)
Switch the toggle to **Red Hat Support / TAM**. The same data produces a denser,
evidence-first briefing (raw `fix_state` / RHSA / source URLs), and you unlock the
**customer estate** flow backed by three synthetic Insights-style accounts:

| Account | Industry | Tracked CVEs (simulated Insights) |
|---|---|---|
| **Meridian Telecom Group** | Telecommunications | CVE-2024-1086, CVE-2023-3390, CVE-2024-3094 |
| **Helios Health Systems** | Healthcare | CVE-2023-3390, CVE-2024-6387 |
| **Northwind Financial Services** | Banking / FSI | CVE-2024-1086, CVE-2023-44487 |

**Examples a TAM can run:**

1. **Whole-estate triage (respond at scale).** Pick *Meridian Telecom Group* — before
   deep-diving one CVE you get a **triage board** ranking every tracked CVE by KEV+EPSS
   urgency and SSVC decision. CVE-2024-1086 (in CISA KEV) sorts to `act_now`; the not-affected xz backdoor
   (CVE-2024-3094) is correctly demoted to `routine` for *this* estate even though it's
   scary globally — because no host here is exposed.
   ```bash
   curl -s "http://localhost:8000/triage?account=Meridian%20Telecom%20Group" | jq
   ```

2. **Deep-dive one CVE for a named customer.** With *Northwind Financial Services*
   selected, ask:
   > *What are the non-disruptive options for CVE-2024-1086 on our RHEL nodes? We're in a
   > change freeze until the next banking maintenance window.*

   The estate answers the sufficiency gate automatically (exposure, controls, reboot
   window come from the account), so it goes straight to a TAM briefing with the affected
   hosts, compliance (OpenSCAP) context, and citations.

3. **TAM naming a customer in free text** (auto-routes to the TAM view):
   > *Helios Health is asking about CVE-2024-6387 (regreSSHion) on their RHEL 9 fleet and
   > can't reboot the clinical systems during business hours — what do I tell them?*

4. **Consistent answers across the team.** Because facts come from Red Hat's data + KEV/EPSS
   + SSVC (Python) and every option cites a source, two TAMs asking the same question get the
   same grounded briefing — the export (Markdown/PDF) carries the provenance tags so it can
   be relayed as-is.

5. **Compare the same CVE across two accounts.** CVE-2023-3390 is tracked by both
   *Meridian Telecom Group* and *Helios Health Systems*, but the estates differ (exposure,
   controls, reboot windows). Run each and the briefings personalize accordingly — same CVE,
   different affected-host counts and different recommended option order:
   ```bash
   curl -s "http://localhost:8000/triage?account=Meridian%20Telecom%20Group" | jq '.cves[] | select(.cve=="CVE-2023-3390")'
   curl -s "http://localhost:8000/triage?account=Helios%20Health%20Systems"  | jq '.cves[] | select(.cve=="CVE-2023-3390")'
   ```

6. **"Are we even affected?" (fast do-nothing answer).** A TAM fielding panic about the
   xz backdoor can show the customer they're clear in one call — the estate's VEX/affected
   data demotes it to `routine`:
   > *Northwind is worried about the xz-utils backdoor CVE-2024-3094 on their RHEL boxes —
   > are they exposed and do they need an emergency change?*

   The gate doesn't need to interrogate: the account says no host is affected, so the
   briefing leads with "not affected → no action" and cites the VEX source.

7. **Estate roll-up for a status report.** Pull the whole ranked list for one account and
   turn it straight into a customer-facing summary (act-now first, routine last):
   ```bash
   curl -s "http://localhost:8000/triage?account=Northwind%20Financial%20Services" \
     | jq -r '.cves[] | "\(.tier)\t\(.cve)\taffected=\(.affected_count)"'
   ```

8. **List the accounts a TAM can look up** (the estate directory for outreach):
   ```bash
   curl -s "http://localhost:8000/accounts" | jq -r '.[] | "\(.account_name) — \(.industry)"'
   ```

## API
```
GET  /health                     # liveness
GET  /accounts                   # synthetic customer accounts (TAM lookup)
GET  /triage?account=<name|org>  # rank a customer's CVEs by KEV+EPSS+SSVC urgency
POST /advise                     # {message, persona?, answers?, force?, account?} → advice
```

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

## GKE deployment

The production GKE workflow, rendered Kubernetes manifests, and Python deployment
command are in [`gcp/GKE-WORKFLOW.md`](gcp/GKE-WORKFLOW.md). It deploys Postgres,
the orchestrator, and the UI using the untracked ADC credential file stored as a
Kubernetes Secret; `make vector-db-backup` and `make vector-db-restore` clone the
local pgvector database into the target cluster.

## Adding platforms / mitigations / docs
Ingest is **incremental**: each source (yaml/pdf basename) is recorded in
the `ingested_source` ledger with a content hash, so `make ingest` only embeds what's
new or changed (`make sources` shows the ledger).
- Mitigations: drop a `data/mitigations/<platform>.yaml`, `make ingest`. Grow the
  allow-list via YAML — not by embedding CVE pages. Option synthesis searches
  `doc_type=mitigation` only and fails closed when nothing curated applies.
  Each YAML row has a stable `id`; Python returns only those catalog records
  (LLM may rank/explain, never invent options or URLs). Applicability uses
  `components` / `exclude_components` / `fix_states` / `requires`.
  PDF chunks are secondary evidence for the **validator** (existing-control prose),
  not for inventing new options.
- Hardening docs: **drop PDFs in `data/pdfs/`**, `make ingest`.
- CVE **facts** are not ingested — runtime reads Red Hat Security Data live (and may
  cache `/cve.json` search hits in table `cve`). Do not embed CVE blurbs into RAG.

## Retrieval — dense + lexical hybrid
`mitigation_rag_search` fuses two rankings with **Reciprocal Rank Fusion (RRF)**: dense
(pgvector cosine, catches paraphrase) and lexical (Postgres full-text `ts_rank_cd`,
catches exact tokens like CVE ids / `kpatch` / `NetworkPolicy` that embeddings bury).
No new dependency — the FTS is a generated `tsvector` column in the same DB. The curated
mitigation catalog gets a small relevance-gated prior. Measure it against a golden set:
```bash
cd orchestrator && PYTHONPATH=. python tests/eval_retrieval.py --mode catalog --k 6
# curated allow-list recall; also --mode both for dense vs hybrid
```

## Tests
```bash
cd orchestrator && PYTHONPATH=. python tests/test_cve_parse.py   # trust-critical parser
cd orchestrator && PYTHONPATH=. python tests/eval_retrieval.py --mode both  # retrieval quality
python orchestrator/priority.py     # KEV/EPSS classifier self-check (network-free)
python orchestrator/ssvc.py         # CISA SSVC Table 9 self-check (network-free)
python orchestrator/models.py       # AdviceResult JSON-string coercion self-check
```
