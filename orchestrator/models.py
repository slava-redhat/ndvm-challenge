"""Shared pydantic schemas for the NDVM flow."""
from typing import List, Literal, Optional
from pydantic import BaseModel, Field

Persona = Literal["primary", "secondary"]
Platform = Literal["rhel", "openshift", "other"]


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
    """One LLM-generated, tick-box question the judge needs answered before advising."""
    key: str = Field(description="short stable id, e.g. 'maintenance_window'")
    question: str
    options: List[str] = Field(description="2-5 concrete answer choices the user can tick")
    multi: bool = True   # checkboxes: more than one answer may apply


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
    ndvm_applies: bool = True            # False when fixed/not-affected
    rhsa: Optional[str] = None
    fixed_nvra: Optional[str] = None
    rationale: str = ""
    source_urls: List[str] = []


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
    title: str
    action_type: str
    description: str
    disruption: Literal["none", "low", "medium", "high"]
    effectiveness: int = Field(ge=1, le=4)
    effort: int = Field(ge=1, le=4)
    steps: List[str] = []
    source_urls: List[str] = []


class AdviceResult(BaseModel):
    persona: Persona
    platform: Platform
    environment_summary: str
    vulnerability: VulnFinding
    business_risk: str = ""            # plain-language risk for a non-technical decision-maker
    existing_controls: List[ControlAssessment] = []   # controls David already has
    options: List[MitigationOption]
    recommended_title: str
    explanation: str
    playbook: Optional[str] = None       # optional Ansible-style artifact
