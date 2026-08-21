"""SSVC (SEI/CISA) decision — what to *do*, not how likely exploitation is.

Pure Python decision table (CISA Stakeholder-Specific Vulnerability Categorization
Guide, Table 9 — coordinator tree). No network, no LLM. Inputs are derived from
facts NDVM already has (KEV/EPSS, severity, estate exposure, industry).

Outcomes: track | track_star | attend | act
  (UI label Track* uses track_star)

Cite: https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc
Guide: https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf

ponytail: Table 9 encoded verbatim; upgrade path = pull CISA Vulnrichment SSVC
from CVE records when you need coordinator-published decisions for USG/CI.
"""
from __future__ import annotations

SSVC_PAGE = "https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc"

# CISA Table 9: (exploitation, automatable, technical_impact, mission_wellbeing) → decision
_TABLE: dict[tuple[str, str, str, str], str] = {
    ("none", "no", "partial", "low"): "track",
    ("none", "no", "partial", "medium"): "track",
    ("none", "no", "partial", "high"): "track",
    ("none", "no", "total", "low"): "track",
    ("none", "no", "total", "medium"): "track",
    ("none", "no", "total", "high"): "track_star",
    ("none", "yes", "partial", "low"): "track",
    ("none", "yes", "partial", "medium"): "track",
    ("none", "yes", "partial", "high"): "attend",
    ("none", "yes", "total", "low"): "track",
    ("none", "yes", "total", "medium"): "track",
    ("none", "yes", "total", "high"): "attend",
    ("poc", "no", "partial", "low"): "track",
    ("poc", "no", "partial", "medium"): "track",
    ("poc", "no", "partial", "high"): "track_star",
    ("poc", "no", "total", "low"): "track",
    ("poc", "no", "total", "medium"): "track_star",
    ("poc", "no", "total", "high"): "attend",
    ("poc", "yes", "partial", "low"): "track",
    ("poc", "yes", "partial", "medium"): "track",
    ("poc", "yes", "partial", "high"): "attend",
    ("poc", "yes", "total", "low"): "track",
    ("poc", "yes", "total", "medium"): "track_star",
    ("poc", "yes", "total", "high"): "attend",
    ("active", "no", "partial", "low"): "track",
    ("active", "no", "partial", "medium"): "track",
    ("active", "no", "partial", "high"): "attend",
    ("active", "no", "total", "low"): "track",
    ("active", "no", "total", "medium"): "attend",
    ("active", "no", "total", "high"): "act",
    ("active", "yes", "partial", "low"): "attend",
    ("active", "yes", "partial", "medium"): "attend",
    ("active", "yes", "partial", "high"): "act",
    ("active", "yes", "total", "low"): "attend",
    ("active", "yes", "total", "medium"): "act",
    ("active", "yes", "total", "high"): "act",
}

_LABEL = {"track": "Track", "track_star": "Track*", "attend": "Attend", "act": "Act"}

# Industries where compromise hits mission-essential functions (critical infrastructure-ish).
_HIGH_MISSION = ("telecom", "telecommunication", "health", "healthcare", "hospital",
                 "bank", "financ", "energy", "utility", "carrier")


def exploitation_value(kev, epss) -> str:
    """CISA Exploitation: active | poc | none. EPSS≥0.1 stands in for Public PoC signal."""
    if kev is True:
        return "active"
    if epss is not None and epss >= 0.1:
        return "poc"
    return "none"


def technical_impact_value(severity: str = "") -> str:
    """CISA Technical Impact: total | partial from Red Hat severity."""
    sev = (severity or "").strip().lower()
    if sev in ("critical", "important"):
        return "total"
    return "partial"


def automatable_value(*, internet_facing: bool = False, answers: str = "") -> str:
    """CISA Automatable: yes if internet-reachable path is plausible (estate or answers)."""
    if internet_facing:
        return "yes"
    low = (answers or "").lower()
    if any(x in low for x in ("internet-facing", "internet facing", "publicly exposed",
                              "public exposure", "exposed to the internet")):
        return "yes"
    return "no"


def mission_wellbeing_value(industry: str = "", answers: str = "") -> str:
    """CISA Mission + Public Well-Being combined (Table 8 → low|medium|high).

    Demo default: CI-like industries → high; production/critical answers → medium;
    else low. Well-being stays Minimal unless answers mention safety/clinical harm.
    """
    blob = f"{industry} {answers}".lower()
    if any(k in blob for k in ("clinical", "patient", "safety", "life-critical",
                               "life critical", "fatalit")):
        return "high"
    if any(k in blob for k in _HIGH_MISSION):
        return "high"
    if any(k in blob for k in ("mission.?critical", "mission critical", "production",
                               "carrier.?sla", "99.999")):
        return "medium"
    return "low"


def ssvc_decide(exploitation: str, automatable: str, technical_impact: str,
                mission_wellbeing: str) -> str:
    """Look up CISA Table 9. Unknown combo → track (conservative defer)."""
    key = (exploitation, automatable, technical_impact, mission_wellbeing)
    return _TABLE.get(key, "track")


def ssvc_label(decision: str) -> str:
    return _LABEL.get(decision, decision)


def decide_for_context(*, kev, epss, severity: str = "", answers: str = "",
                       internet_facing: bool = False, industry: str = "",
                       freeze: bool = False) -> dict:
    """Full SSVC result for one CVE in one estate context."""
    exploitation = exploitation_value(kev, epss)
    automatable = automatable_value(internet_facing=internet_facing, answers=answers)
    technical = technical_impact_value(severity)
    mission = mission_wellbeing_value(industry, answers)
    decision = ssvc_decide(exploitation, automatable, technical, mission)
    inputs = {
        "exploitation": exploitation,
        "automatable": automatable,
        "technical_impact": technical,
        "mission_wellbeing": mission,
    }
    label = ssvc_label(decision)
    rationale = (
        f"SSVC (CISA Table 9) = {label} "
        f"(exploitation={exploitation}, automatable={automatable}, "
        f"technical={technical}, mission/well-being={mission})."
    )
    if decision == "act" and freeze:
        rationale += (" Change freeze in effect — Act means apply a non-disruptive "
                      "interim mitigation now (kpatch / config / network), not an "
                      "emergency reboot; schedule the reboot for the next window.")
    elif decision == "attend":
        rationale += " Remediate sooner than standard update timelines."
    elif decision == "track_star":
        rationale += " Monitor closely for changes; standard timelines still apply."
    elif decision == "track":
        rationale += " Continue tracking; remediate within standard update timelines."
    return {"ssvc_decision": decision, "ssvc_label": label, "ssvc_inputs": inputs,
            "ssvc_rationale": rationale, "source_url": SSVC_PAGE}


def attach_ssvc(sig: dict, *, severity: str = "", answers: str = "",
                internet_facing: bool = False, industry: str = "",
                freeze: bool = False) -> dict:
    """Mutate ExploitSignal-shaped dict with SSVC fields; return it."""
    out = decide_for_context(
        kev=sig.get("kev", sig.get("in_kev")), epss=sig.get("epss"),
        severity=severity or "", answers=answers, internet_facing=internet_facing,
        industry=industry, freeze=freeze)
    sig["ssvc_decision"] = out["ssvc_decision"]
    sig["ssvc_label"] = out["ssvc_label"]
    sig["ssvc_inputs"] = out["ssvc_inputs"]
    sig["ssvc_rationale"] = out["ssvc_rationale"]
    url = out["source_url"]
    srcs = list(sig.get("source_urls") or [])
    if url not in srcs:
        srcs.append(url)
    sig["source_urls"] = srcs
    return sig


if __name__ == "__main__":
    # Table 9 corners
    assert ssvc_decide("none", "no", "partial", "low") == "track"
    assert ssvc_decide("none", "no", "total", "high") == "track_star"
    assert ssvc_decide("active", "no", "total", "high") == "act"
    assert ssvc_decide("active", "yes", "total", "high") == "act"
    assert ssvc_decide("poc", "yes", "total", "high") == "attend"
    assert exploitation_value(True, 0.0) == "active"
    assert exploitation_value(False, 0.2) == "poc"
    assert exploitation_value(False, 0.01) == "none"
    assert technical_impact_value("Critical") == "total"
    assert technical_impact_value("Moderate") == "partial"
    assert automatable_value(internet_facing=True) == "yes"
    assert automatable_value(answers="hosts are internet-facing") == "yes"
    assert mission_wellbeing_value("Telecommunications") == "high"
    assert mission_wellbeing_value("Retail") == "low"
    r = decide_for_context(kev=True, epss=0.9, severity="Critical",
                           internet_facing=True, industry="Telecommunications",
                           freeze=True)
    assert r["ssvc_decision"] == "act"
    assert "non-disruptive" in r["ssvc_rationale"]
    assert ssvc_label("track_star") == "Track*"
    print("ok")
