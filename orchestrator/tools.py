"""CrewAI tools: Red Hat Security Data lookup + local RAG search."""
import json
from functools import lru_cache
from typing import Type

import requests
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from cve_parse import analyze_cve_json, search_params, slim_rows, valid_cve
from db import rag_search_hybrid

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
        cve = cve.strip()
        if not valid_cve(cve):  # trust boundary: don't fetch a garbage id
            return json.dumps({"error": f"not a valid CVE id: '{cve}'", "cve_id": cve})
        try:
            data = _fetch_cve_json(cve)
        except requests.RequestException as e:
            return json.dumps({"error": f"request failed: {e}", "cve_id": cve})
        if data is None:
            return json.dumps({"error": "CVE not found in Red Hat data", "cve_id": cve})
        return json.dumps(analyze_cve_json(data, product))


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
            return json.dumps({"error": f"search failed: {e}"})
        if not rows:
            return json.dumps({"results": [], "note": "no matching CVEs"})
        return json.dumps({"results": slim_rows(rows)})


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
        hits = rag_search_hybrid(query, platform or None)
        if not hits:
            return "No grounded mitigations found in the knowledge base."
        return "\n\n".join(
            f"[source: {h['source_url']}] {h['text']}" for h in hits
        )
