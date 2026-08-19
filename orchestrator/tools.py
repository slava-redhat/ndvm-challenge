"""CrewAI tools: Red Hat Security Data lookup + local RAG search."""
import json
from typing import Type

import requests
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from cve_parse import analyze_cve_json
from db import rag_search

SECDATA = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"


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
        try:
            r = requests.get(SECDATA.format(cve=cve.strip()),
                             params={"isCompressed": "false"}, timeout=30)
        except requests.RequestException as e:
            return json.dumps({"error": f"request failed: {e}", "cve_id": cve})
        if r.status_code == 404:
            return json.dumps({"error": "CVE not found in Red Hat data", "cve_id": cve})
        r.raise_for_status()
        return json.dumps(analyze_cve_json(r.json(), product))


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
        hits = rag_search(query, platform or None)
        if not hits:
            return "No grounded mitigations found in the knowledge base."
        return "\n\n".join(
            f"[source: {h['source_url']}] {h['text']}" for h in hits
        )
