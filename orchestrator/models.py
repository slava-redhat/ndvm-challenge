"""Shared pydantic schemas for the NDVM flow."""
import json
from typing import List, Literal, Optional
from pydantic import BaseModel, Field, model_validator

Persona = Literal["primary", "secondary"]
Platform = Literal["rhel", "openshift", "other"]
OTHER_OPTION = "Other (describe)"
NOT_SURE_OPTION = "Not sure"


class Intake(BaseModel):
    """What the Router extracts from the user's opening message."""
    on_topic: bool = Field(default=True, description="True only if the message concerns IT security, vulnerabilities, CVEs, patching or mitigation")
    persona: Persona = Field(description="'primary' = customer Platform Owner/IT Leader; 'secondary' = Red Hat Support/TAM")
    platform: Platform = "other"
    product: str = Field(default="", description="e.g. 'Red Hat Enterprise Linux 8'")
    version: str = ""
    cve: str = Field(default="", description="CVE id, e.g. CVE-2023-3390")
    constraint: str = Field(default="", description="the hard constraint, e.g. 'no reboot until quarter-end'")
    account: str = Field(default="", description="customer account/company name if a TAM named one")


class ClarifyQuestion(BaseModel):
    """One LLM-generated question the judge needs answered before advising.

    The gate uses closed choices. The UI reveals a short detail field only after the
    user explicitly selects ``Other (describe)``.
    """
    key: str = Field(description="short stable id, e.g. 'maintenance_window'")
    question: str
    options: List[str] = Field(
        default_factory=list,
        description="2-4 plain-language choices plus 'Other (describe)'",
    )
    multi: bool = False  # single-choice is safest by default; opt in for control lists


class Sufficiency(BaseModel):
    """The gatekeeper's verdict: is the case understood well enough to advise?"""
    sufficient: bool = Field(description="True only when advice would fit THIS environment, no wide guessing")
    missing: List[str] = Field(default=[], description="what is still unknown")
    questions: List[ClarifyQuestion] = []   # populated only when not sufficient


class CveChoice(BaseModel):
    """The Researcher's typed pick, so the Analyst can't drift to a different CVE."""
    cve: str = Field(description="the single CVE id to analyze next, e.g. CVE-2023-3390")
    why: str = ""
    alternatives: List[str] = Field(default=[], description="other notable CVE ids")


class VulnFinding(BaseModel):
    cve_id: str
    threat_severity: str = "unknown"
    cvss3: Optional[float] = None
    fix_state: str = "unknown"           # authoritative NDVM trigger
    ndvm_applies: bool = True            # False only when fix_state is 'Not affected' (Fixed still applies)
    rhsa: Optional[str] = None
    fixed_nvra: Optional[str] = None
    cwe: str = ""                        # Red Hat CWE id(s), e.g. 'CWE-416' — drives attack-class gating
    description: str = ""                # the vulnerability MECHANISM (bugzilla/details), not fix-state prose
    affected_packages: List[str] = []    # authoritative RH package names — drives component gating (kernel, openssh…)
    rationale: str = ""
    source_urls: List[str] = []


class ExploitSignal(BaseModel):
    """Prioritization facts, computed in Python from public feeds (never LLM-guessed)."""
    cve: str = ""
    in_kev: bool = False                       # CISA Known Exploited Vulnerabilities catalog
    epss: Optional[float] = None               # FIRST EPSS probability 0..1 (30-day exploit likelihood)
    epss_percentile: Optional[float] = None
    tier: Literal["act_now", "prioritize", "scheduled", "routine", "unknown"] = "routine"
    rationale: str = ""
    source_urls: List[str] = []
    compliance: Optional[dict] = None          # OpenSCAP posture modifier (priority.compliance_signal)
    # SSVC (SEI/CISA Table 9) — action decision, not a likelihood score
    ssvc_decision: Optional[Literal["track", "track_star", "attend", "act"]] = None
    ssvc_label: Optional[str] = None           # Track / Track* / Attend / Act
    ssvc_inputs: Optional[dict] = None
    ssvc_rationale: Optional[str] = None


class ControlAssessment(BaseModel):
    """Does a control the customer ALREADY runs mitigate this specific CVE?"""
    control: str
    status: Literal["mitigated", "partial", "not_mitigated", "unknown"]
    rationale: str = ""
    source_urls: List[str] = []


class ControlReport(BaseModel):
    """Typed wrapper so the validator's verdict can't drift on the way to the result."""
    controls: List[ControlAssessment] = []


class MitigationOption(BaseModel):
    catalog_id: str = ""                 # stable YAML id; empty = not from catalog (dropped)
    title: str
    action_type: str
    description: str
    disruption: Literal["none", "low", "medium", "high"]
    effectiveness: int = Field(ge=1, le=4)
    effort: int = Field(ge=1, le=4)
    steps: List[str] = []
    source_urls: List[str] = []
    score: Optional[float] = None   # deterministic fit score (scoring.py); set in Python


class AdviceResult(BaseModel):
    persona: Persona
    platform: Platform
    environment_summary: str
    vulnerability: VulnFinding
    priority: Optional[ExploitSignal] = None   # KEV/EPSS-driven urgency (set in Python)
    business_risk: str = ""            # plain-language risk for a non-technical decision-maker
    # Decision Package — residual labels + one-line summary (Python-owned; see priority.build_decision_package)
    residual_before: str = ""          # high|elevated|moderate|low|minimal|unknown
    residual_after: str = ""
    decision_summary: str = ""
    existing_controls: List[ControlAssessment] = []   # controls David already has
    options: List[MitigationOption]
    recommended_title: str
    explanation: str
    playbook: Optional[str] = None       # optional Ansible-style artifact

    # ponytail: CrewAI's LLM (Claude via LiteLLM) intermittently emits nested objects/
    # lists as JSON *strings* instead of objects. Left unhandled, pydantic rejects them
    # and CrewAI re-runs the slow synth agent up to 4x — the run then blows past the UI's
    # request timeout and the flow appears "stuck". Parsing them here makes structured
    # output validate on the first attempt (no retry storm). Upgrade path: if a stringified
    # field ever nests further strings, recurse — not needed for the flat fields below.
    @model_validator(mode="before")
    @classmethod
    def _coerce_json_strings(cls, data):
        if isinstance(data, dict):
            for key in ("vulnerability", "priority", "existing_controls", "options"):
                v = data.get(key)
                if isinstance(v, str):
                    try:
                        data[key] = json.loads(v)
                    except (ValueError, TypeError):
                        pass   # leave as-is; normal validation reports the real problem
        return data


if __name__ == "__main__":
    # Self-check: the exact failure from the logs — vulnerability + priority arrive as
    # JSON strings — must now validate instead of raising (which caused the retry storm).
    r = AdviceResult(
        persona="primary", platform="rhel", environment_summary="x",
        vulnerability='{"cve_id": "CVE-2021-44228", "threat_severity": "critical"}',
        priority='{"cve": "CVE-2021-44228", "tier": "act_now"}',
        options=[], recommended_title="t", explanation="e",
    )
    assert r.vulnerability.cve_id == "CVE-2021-44228"
    assert r.priority.tier == "act_now"
    # dict/object inputs still work unchanged
    r2 = AdviceResult(persona="primary", platform="rhel", environment_summary="x",
                      vulnerability={"cve_id": "CVE-1"}, options=[],
                      recommended_title="t", explanation="e")
    assert r2.vulnerability.cve_id == "CVE-1" and r2.priority is None
    print("ok")
