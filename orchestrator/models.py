"""Shared pydantic schemas for the NDVM flow."""
from typing import List, Literal, Optional
from pydantic import BaseModel, Field

Persona = Literal["primary", "secondary"]
Platform = Literal["rhel", "openshift", "other"]


class Intake(BaseModel):
    """What the Router extracts from the user's opening message."""
    persona: Persona = Field(description="'primary' = customer Platform Owner/IT Leader; 'secondary' = Red Hat Support/TAM")
    platform: Platform = "other"
    product: str = Field(default="", description="e.g. 'Red Hat Enterprise Linux 8'")
    version: str = ""
    cve: str = Field(default="", description="CVE id, e.g. CVE-2023-3390")
    constraint: str = Field(default="", description="the hard constraint, e.g. 'no reboot until quarter-end'")


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
    options: List[MitigationOption]
    recommended_title: str
    explanation: str
    playbook: Optional[str] = None       # optional Ansible-style artifact
