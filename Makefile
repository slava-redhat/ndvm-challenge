.PHONY: help up down logs ingest reingest stats sources pdfs health test clean

# Bare `make` shows help. (`make -h`/`--help` are GNU make's own flags and print
# make's usage — they can't be overridden by a target; use `make` or `make help`.)
.DEFAULT_GOAL := help

# .env supplies POSTGRES_USER/DB; fall back to the defaults in .env.example.
POSTGRES_USER ?= ndvm
POSTGRES_DB   ?= ndvm
DC = podman-compose --env-file .env

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n",$$1,$$2}'

up: ## Build + start the full stack (db, orchestrator, ui)
	$(DC) up -d --build

down: ## Stop the stack (keeps the data volume)
	$(DC) down

logs: ## Tail all service logs
	$(DC) logs -f

ingest: ## Incremental ingest: only new/changed PDFs, YAMLs, CVEs get embedded
	$(DC) up -d db
	$(DC) build ingest
	$(DC) run --rm ingest

reingest: ## Force full rebuild: clear the corpus and re-embed everything
	$(DC) up -d db
	$(DC) build ingest
	$(DC) run --rm -e INGEST_RESET=1 ingest

stats: ## Corpus totals (chunks / mitigations / cves)
	@$(DC) exec -T db psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -c \
	  "SELECT (SELECT count(*) FROM doc_chunk) AS chunks, \
	          (SELECT count(*) FROM doc_chunk WHERE metadata->>'doc_type'='mitigation') AS mitigations, \
	          (SELECT count(*) FROM cve) AS cves;"

sources: ## Show exactly what has been ingested (the ledger)
	@$(DC) exec -T db psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -c \
	  "SELECT kind, source, chunks, to_char(ingested_at,'YYYY-MM-DD HH24:MI') AS ingested \
	   FROM ingested_source ORDER BY kind, source;"

pdfs: ## Where to drop hardening PDFs, and what's there now
	@echo "Drop *.pdf into  data/pdfs/  then run:  make ingest"
	@ls -1 data/pdfs/*.pdf 2>/dev/null || echo "(none yet)"

health: ## Orchestrator health check
	@curl -s http://localhost:8000/health | python3 -m json.tool || echo "orchestrator not up"

test: ## Run the trust-critical CVE parser test
	cd orchestrator && PYTHONPATH=. python3 tests/test_cve_parse.py

clean: ## Stop the stack AND delete the data volume (full reset)
	$(DC) down -v
