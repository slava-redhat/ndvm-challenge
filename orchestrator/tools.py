"""CrewAI tools: Red Hat Security Data lookup + local RAG search."""
import json
import re
from functools import lru_cache
from typing import Type

import requests
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from cve_parse import analyze_cve_json, search_params, slim_rows, valid_cve
from db import rag_search_hybrid, search_cve_cache, upsert_cve_list_rows
from models import VulnFinding

SECDATA = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"
CVE_LIST = "https://access.redhat.com/hydra/rest/securitydata/cve.json"


@lru_cache(maxsize=1024)
def _fetch_cve_json(cve: str):
    """Red Hat Security Data for one CVE, cached per process (same pattern as the KEV
    feed). Returns the raw JSON, or None for a 404. Network/HTTP errors propagate so
    lru_cache doesn't memoize a transient failure. Cached by CVE only — product
    filtering happens in analyze_cve_json, so different products reuse one fetch."""
    r = requests.get(SECDATA.format(cve=cve), params={"isCompressed": "false"}, timeout=30)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def lookup_vuln_finding(cve: str, product: str = "") -> VulnFinding:
    """Authoritative VulnFinding from Red Hat JSON — Python-owned, never LLM-copied."""
    cve = (cve or "").strip()
    if not valid_cve(cve):
        return VulnFinding(cve_id=cve, fix_state="unknown",
                           rationale=f"not a valid CVE id: '{cve}'", ndvm_applies=True)
    try:
        data = _fetch_cve_json(cve.upper())
    except requests.RequestException as e:
        return VulnFinding(cve_id=cve.upper(), fix_state="unknown",
                           rationale=f"Red Hat Security Data unreachable: {e}",
                           ndvm_applies=True)
    if data is None:
        return VulnFinding(cve_id=cve.upper(), fix_state="unknown",
                           rationale="CVE not found in Red Hat data", ndvm_applies=True)
    return VulnFinding(**analyze_cve_json(data, product))


def _pkg_base(nvra: str) -> str:
    """NVRA -> package base name, e.g. 'cockpit-0:344-2.el9_7' -> 'cockpit'."""
    name = (nvra or "").split(":", 1)[0]       # drop epoch:version.. -> 'cockpit-0'
    return re.sub(r"-\d.*$", "", name).strip("-")  # drop trailing '-<epoch/version>'


def cve_affected_packages(cve: str) -> set[str]:
    """Authoritative affected-package base names for a CVE from Red Hat data (cached).

    Empty set means 'can't verify' (unknown/unreachable CVE) — callers must NOT read
    it as 'affects nothing'. Used to check a discovered CVE actually concerns the
    software the user named, before it is pinned as authoritative.
    """
    cve = (cve or "").strip()
    if not valid_cve(cve):
        return set()
    try:
        data = _fetch_cve_json(cve.upper())
    except requests.RequestException:
        return set()
    if not data:
        return set()
    pkgs = set()
    for st in data.get("package_state") or []:            # clean names: 'openssh', 'cockpit'
        name = (st.get("package_name") or "").strip().lower()
        if name:
            pkgs.add(name)
    for rel in data.get("affected_release") or []:        # NVRA -> base name
        base = _pkg_base((rel.get("package") or "").strip().lower())
        if base:
            pkgs.add(base)
    bz = ((data.get("bugzilla") or {}).get("description") or "").strip().lower()
    if ":" in bz:                                          # 'cockpit: <desc>' -> component
        head = bz.split(":", 1)[0].strip()
        if head and " " not in head:
            pkgs.add(head)
    return {p for p in pkgs if p}


class SecDataInput(BaseModel):
    cve: str = Field(description="CVE id, e.g. CVE-2023-3390")
    product: str = Field(default="", description="product name hint, e.g. 'Red Hat Enterprise Linux 8'")


class RedHatSecurityDataTool(BaseTool):
    name: str = "redhat_security_data"
    description: str = (
        "Look up a CVE in Red Hat's authoritative Security Data API. Returns the "
        "product fix_state (Fix deferred / Will not fix / Fixed / Not affected...), "
        "severity, CVSS, fixing RHSA/NVRA, and the source URL. Use this to ground "
        "every claim about whether patching is feasible."
    )
    args_schema: Type[BaseModel] = SecDataInput

    def _run(self, cve: str, product: str = "") -> str:
        return lookup_vuln_finding(cve, product).model_dump_json()


class CveSearchInput(BaseModel):
    package: str = Field(default="", description="affected package name, e.g. 'openssl' or 'kernel'")
    product: str = Field(default="", description="product name substring, e.g. 'Red Hat Enterprise Linux 8'")
    severity: str = Field(default="", description="low | moderate | important | critical")
    advisory: str = Field(default="", description="RHSA id to list the CVEs it fixes, e.g. RHSA-2024:2394")
    after: str = Field(default="", description="only CVEs public on/after this date, YYYY-MM-DD")


class RedHatCveSearchTool(BaseTool):
    name: str = "redhat_cve_search"
    description: str = (
        "Search Red Hat's authoritative CVE catalog — the same public data behind "
        "access.redhat.com/security/security-updates/cve and .../security-advisories "
        "(no login needed). Filter by package, product, severity, publish date, or an "
        "RHSA advisory id. Use this to DISCOVER which CVEs affect a customer's software "
        "when they don't name a specific CVE, or to list the CVEs an advisory fixes. "
        "Returns a list (newest first): cve, severity, date, cvss3, advisories, affected "
        "packages, summary, url. Give at least one filter."
    )
    args_schema: Type[BaseModel] = CveSearchInput

    def _run(self, package: str = "", product: str = "", severity: str = "",
             advisory: str = "", after: str = "") -> str:
        try:
            params = search_params(package, product, severity, advisory, after)
        except ValueError as e:
            return json.dumps({"error": str(e)})
        try:
            r = requests.get(CVE_LIST, params=params, timeout=30)
            r.raise_for_status()
            rows = r.json()
        except (requests.RequestException, ValueError) as e:
            try:
                cached = search_cve_cache(package, product, severity, advisory, after)
            except Exception:
                return json.dumps({"error": f"search failed: {e}"})
            if not cached:
                return json.dumps({"error": f"search failed: {e}",
                                   "note": "no local cve cache hit"})
            return json.dumps({"results": cached,
                               "note": "from local cve cache (API unreachable)"})
        if not rows:
            return json.dumps({"results": [], "note": "no matching CVEs"})
        slim = slim_rows(rows)
        try:
            upsert_cve_list_rows(slim)
        except Exception:
            pass  # ponytail: cache write is best-effort; never fail the search
        return json.dumps({"results": slim})


class RagInput(BaseModel):
    query: str = Field(description="what mitigation guidance to find")
    platform: str = Field(default="", description="rhel | openshift | other")


class RagSearchTool(BaseTool):
    name: str = "mitigation_rag_search"
    description: str = (
        "Search the local trusted knowledge base (Red Hat mitigation catalog + "
        "hardening docs) for grounded, non-disruptive mitigation options for a "
        "platform. Returns text snippets with source URLs. Only recommend options "
        "found here — never invent controls."
    )
    args_schema: Type[BaseModel] = RagInput

    def _run(self, query: str, platform: str = "") -> str:
        try:
            hits = rag_search_hybrid(query, platform or None, doc_types=("mitigation",))
        except Exception as e:
            # ponytail: Ollama/DB down → empty grounded list, don't kill the wave
            return f"Knowledge base unavailable ({type(e).__name__}: {e}). No grounded mitigations."
        if not hits:
            return "No grounded mitigations found in the knowledge base."
        return "\n\n".join(
            f"[source: {h['source_url']}] {h['text']}" for h in hits
        )
