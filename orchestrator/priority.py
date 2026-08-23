"""Prioritization: is this CVE exploited in the wild, and how likely is exploitation?

Two public feeds, both facts (not opinions), so we read them in Python and let the LLM
only explain — same trust rule as the CVE parser:
  - CISA KEV  : Known Exploited Vulnerabilities catalog (binary: listed => exploited).
  - FIRST EPSS: 30-day exploitation probability (0..1) + percentile.

SSVC (SEI/CISA Table 9) answers a different question — what to *do* (Act/Attend/Track*).
That decision is attached via ssvc.attach_ssvc after KEV/EPSS (see ssvc.py); no extra feed.

Network is best-effort: if a feed is unreachable we degrade to severity-only tiering
rather than fail the user's answer.
"""
import time

import requests

from ssvc import attach_ssvc

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
TIMEOUT = 8
_KEV_TTL = 6 * 3600  # ponytail: refresh KEV every 6h; upgrade to shared cache if multi-replica

_kev_cache: tuple[float, frozenset] | None = None  # (fetched_at, set)


def _kev_set() -> frozenset:
    """CISA KEV cveIDs. TTL-cached (not immortal) so catalog updates land without restart."""
    global _kev_cache
    now = time.time()
    if _kev_cache is not None and now - _kev_cache[0] < _KEV_TTL:
        return _kev_cache[1]
    r = requests.get(KEV_FEED, timeout=TIMEOUT)
    r.raise_for_status()
    s = frozenset(v.get("cveID", "") for v in r.json().get("vulnerabilities", []))
    _kev_cache = (now, s)
    return s


def in_kev(cve: str) -> bool | None:
    """True/False when the feed answered; None when unreachable (unknown, not 'not listed')."""
    try:
        return cve.strip().upper() in _kev_set()
    except Exception:
        return None


_epss_cache: dict[str, tuple[float, float, float]] = {}  # cve -> (fetched_at, epss, pct)
_EPSS_TTL = 6 * 3600


def fetch_epss(cve: str):
    """(epss, percentile) as floats, or (None, None) if unavailable."""
    key = (cve or "").strip().upper()
    if not key:
        return None, None
    now = time.time()
    hit = _epss_cache.get(key)
    if hit is not None and now - hit[0] < _EPSS_TTL:
        return hit[1], hit[2]
    try:
        r = requests.get(EPSS_API, params={"cve": key}, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json().get("data") or []
        if not data:
            return None, None
        epss, pct = float(data[0]["epss"]), float(data[0]["percentile"])
        _epss_cache[key] = (now, epss, pct)
        return epss, pct
    except Exception:
        return None, None


def classify(kev, epss, severity: str = "") -> tuple[str, str]:
    """Pure tiering — the auditable core. Returns (tier, rationale).

    kev: True / False / None (None = feed unreachable).
    """
    sev = (severity or "").strip().lower()
    pct = f"{epss:.1%}" if epss is not None else "unknown"
    # Nothing to go on — feeds unreachable AND no usable severity. Fail closed to
    # 'unknown' (not 'routine') so the UI never badges this as low risk.
    if kev is not True and epss is None and sev in ("", "unknown"):
        return "unknown", ("Risk could not be assessed — the CISA KEV / FIRST EPSS / Red Hat "
                           "feeds were unreachable or returned no signal during this run. "
                           "Re-run to get an exploitation rating; do NOT treat this as low risk.")
    if kev is True:
        return "act_now", (f"Listed in CISA KEV — actively exploited in the wild "
                           f"(EPSS {pct}). Treat as an emergency change even under a freeze.")
    if epss is not None and epss >= 0.5:
        return "act_now", (f"EPSS {pct}: high probability of exploitation in the next 30 days. "
                           f"Prioritise a non-disruptive mitigation now.")
    if (epss is not None and epss >= 0.1) or sev == "critical":
        return "prioritize", (f"Elevated exploitation risk (EPSS {pct}, severity "
                              f"{severity or 'n/a'}). Mitigate ahead of the routine backlog.")
    if (epss is not None and epss >= 0.01) or sev == "important":
        return "scheduled", (f"Moderate risk (EPSS {pct}, severity {severity or 'n/a'}). "
                             f"Schedule mitigation within the normal window.")
    return "routine", (f"Low current exploitation signal (EPSS {pct}, severity "
                       f"{severity or 'n/a'}). Handle in the routine cycle.")


_TIERS = ["routine", "scheduled", "prioritize", "act_now"]  # low -> high urgency


def compliance_signal(comp_rows: list) -> dict:
    """Turn Insights OpenSCAP posture for the affected hosts into a risk modifier.

    Compliance is estate posture, not a threat feed: a weak hardening score / a failing
    security rule means the compensating controls that would blunt this CVE are NOT in
    force here, so residual exposure is HIGHER (delta +1). A strong, clean posture means
    the estate is already hardened, so residual risk is LOWER (delta -1). Pure; no network.

    comp_rows: [{hostname, score, failed_rules, ...}] from accounts.compliance_view.
    """
    rows = [r for r in (comp_rows or []) if isinstance(r.get("score"), (int, float))]
    if not rows:
        return {"posture": "unknown", "min_score": None, "failed_rules": [], "delta": 0}
    min_score = min(r["score"] for r in rows)
    # Only score-bearing rows contribute failed rules (unscored hosts don't force weak).
    failed = sorted({f for r in rows for f in (r.get("failed_rules") or [])})
    if min_score < 70 or failed:
        posture, delta = "weak", 1
    elif min_score >= 90:
        posture, delta = "strong", -1
    else:
        posture, delta = "adequate", 0
    return {"posture": posture, "min_score": min_score, "failed_rules": failed, "delta": delta}


def adjust_tier(tier: str, delta: int, kev: bool = False) -> str:
    """Shift the urgency tier by posture. Escalation always allowed; de-escalation never
    for a KEV-listed CVE (actively exploited outranks good hygiene)."""
    if delta == 0 or (delta < 0 and kev):
        return tier
    if tier == "unknown":
        return "prioritize" if delta > 0 else "unknown"
    i = _TIERS.index(tier) if tier in _TIERS else 0
    return _TIERS[max(0, min(len(_TIERS) - 1, i + (1 if delta > 0 else -1)))]


def compliance_note(csig: dict) -> str:
    """Audit sentence explaining how compliance posture moved the tier."""
    if csig["delta"] > 0:
        rules = ", ".join(csig["failed_rules"]) or "hardening gaps"
        return (f"Compliance posture WEAK (OpenSCAP min {csig['min_score']}%, failing: {rules}) "
                f"— compensating controls not fully in force, so exposure is higher: urgency raised.")
    if csig["delta"] < 0:
        return (f"Compliance posture STRONG (OpenSCAP min {csig['min_score']}%, no failing rules) "
                f"— the estate is already hardened, so residual risk is lower: urgency eased.")
    return ""


def assess(cve: str, severity: str = "", kev_hint: bool = False) -> dict:
    """Build the ExploitSignal-shaped dict for a CVE. kev_hint lets an account's own
    known_exploited flag stand in when the live feed is unreachable."""
    cve = (cve or "").strip().upper()
    kev_live = in_kev(cve)
    # Hint True => listed. Else use live True/False/None (None = feed down).
    kev: bool | None = True if kev_hint else kev_live
    epss, pct = fetch_epss(cve)
    tier, rationale = classify(kev, epss, severity)
    sources = [KEV_PAGE] if kev is True else []
    if epss is not None:
        sources.append(f"{EPSS_API}?cve={cve}")
    return {"cve": cve, "in_kev": bool(kev), "kev": kev, "epss": epss, "epss_percentile": pct,
            "tier": tier, "rationale": rationale, "source_urls": sources}


def priority_note(sig: dict) -> str:
    """One-line summary for LLM prompts (business_risk + ranking)."""
    parts = [f"urgency tier: {sig['tier']}"]
    if sig.get("in_kev"):
        parts.append("KNOWN EXPLOITED (CISA KEV)")
    if sig.get("epss") is not None:
        parts.append(f"EPSS {sig['epss']:.1%} (percentile {sig.get('epss_percentile', 0):.0%})")
    if sig.get("ssvc_label"):
        parts.append(f"SSVC {sig['ssvc_label']}")
    return "; ".join(parts) + "."


def apply_ssvc_context(sig: dict, *, severity: str = "", answers: str = "",
                       internet_facing: bool = False, industry: str = "",
                       freeze: bool = False) -> dict:
    """Attach CISA SSVC decision using estate/answers context. Pure; no network."""
    return attach_ssvc(sig, severity=severity, answers=answers,
                       internet_facing=internet_facing, industry=industry, freeze=freeze)


# Residual labels for the Decision Package (CAB/TAM strip). Ordered high → low risk.
_RESIDUAL_ORDER = ("high", "elevated", "moderate", "low", "minimal")


def _base_residual(sig: dict) -> str:
    """Map current SSVC + urgency tier to a residual-risk label (before interim)."""
    if sig.get("tier") == "unknown" and not sig.get("ssvc_decision"):
        return "unknown"
    d, t = sig.get("ssvc_decision"), sig.get("tier")
    if d == "act" or t == "act_now":
        return "high"
    if d == "attend" or t == "prioritize":
        return "elevated"
    if d == "track_star" or t == "scheduled":
        return "moderate"
    return "low"


def _ease_residual(label: str, steps: int) -> str:
    if label == "unknown" or steps <= 0:
        return label
    try:
        i = _RESIDUAL_ORDER.index(label)
    except ValueError:
        return label
    return _RESIDUAL_ORDER[min(len(_RESIDUAL_ORDER) - 1, i + steps)]


def build_decision_package(sig: dict, *, controls: list | None = None,
                           recommended=None, freeze: bool = False,
                           fix_state: str = "") -> dict:
    """Python-owned Decision Package fields. LLM never invents these labels.

    Before = residual from current SSVC/urgency (+ already-mitigated controls).
    After  = same label eased by the recommended interim (or already low if protected).
    """
    controls = controls or []
    mitigated = any(getattr(c, "status", None) == "mitigated"
                    or (isinstance(c, dict) and c.get("status") == "mitigated")
                    for c in controls)
    before = "low" if mitigated else _base_residual(sig)
    if (fix_state or "") == "Not affected":
        before, after = "minimal", "minimal"
    elif mitigated:
        after = "low"
    elif recommended is not None:
        disruption = (getattr(recommended, "disruption", None)
                      or (recommended.get("disruption") if isinstance(recommended, dict)
                          else "") or "")
        eff = int(getattr(recommended, "effectiveness", None)
                  or (recommended.get("effectiveness") if isinstance(recommended, dict)
                      else 0) or 0)
        steps = 2 if disruption.lower() in ("none", "low") and eff >= 3 else 1
        after = _ease_residual(before, steps)
    else:
        after = before

    ssvc = sig.get("ssvc_label") or "—"
    tier = (sig.get("tier") or "unknown").replace("_", " ")
    rec_title = ""
    if recommended is not None:
        rec_title = (getattr(recommended, "title", None)
                     or (recommended.get("title") if isinstance(recommended, dict) else "")
                     or "")
    if (fix_state or "") == "Not affected":
        summary = (f"Not affected (VEX) — residual {after}. SSVC {ssvc}; urgency {tier}. "
                   f"No interim change required.")
    elif mitigated:
        summary = (f"Existing control already mitigates — residual {after}. "
                   f"SSVC {ssvc}; urgency {tier}. Confirm the control stays in force.")
    elif rec_title:
        freeze_bit = (" Under change freeze: apply a non-disruptive interim now — not a reboot."
                      if freeze and sig.get("ssvc_decision") == "act" else "")
        summary = (f"Residual before interim: {before}. Apply «{rec_title}» → residual {after}. "
                   f"SSVC {ssvc}; urgency {tier}.{freeze_bit}")
    else:
        summary = (f"Residual before interim: {before} (no ranked option yet). "
                   f"SSVC {ssvc}; urgency {tier}.")

    return {"residual_before": before, "residual_after": after,
            "decision_summary": summary}



if __name__ == "__main__":  # self-check for the pure classifier (no network needed)
    assert classify(True, 0.9, "Critical")[0] == "act_now"
    assert classify(False, 0.6)[0] == "act_now"
    assert classify(False, 0.2)[0] == "prioritize"
    assert classify(False, None, "Critical")[0] == "prioritize"
    assert classify(False, 0.02, "Moderate")[0] == "scheduled"
    assert classify(False, None, "Important")[0] == "scheduled"
    assert classify(False, None, " Important ")[0] == "scheduled"  # strip whitespace
    assert classify(False, 0.0, "Low")[0] == "routine"
    # total feed outage: honest unknown tier, never a confident low-risk badge
    assert classify(None, None, "")[0] == "unknown"
    assert classify(False, None, "unknown")[0] == "unknown"
    assert "could not be assessed" in classify(None, None, "")[1]
    # a known severity (or any EPSS/KEV) still rates normally, not the outage message
    assert "could not be assessed" not in classify(False, None, "Important")[1]
    assert "could not be assessed" not in classify(False, 0.0, "")[1]
    assert priority_note({"tier": "act_now", "in_kev": True, "epss": 0.94,
                          "epss_percentile": 0.99}).startswith("urgency tier: act_now")
    assert "SSVC Act" in priority_note({"tier": "act_now", "ssvc_label": "Act"})
    _s = {"kev": True, "in_kev": True, "epss": 0.9, "source_urls": []}
    apply_ssvc_context(_s, severity="Critical", internet_facing=True,
                       industry="Telecommunications", freeze=True)
    assert _s["ssvc_decision"] == "act" and "non-disruptive" in _s["ssvc_rationale"]
    # compliance risk modifier
    weak = compliance_signal([{"score": 55, "failed_rules": ["selinux_state_enforcing"]}])
    assert weak["delta"] == 1 and weak["posture"] == "weak"
    strong = compliance_signal([{"score": 95, "failed_rules": []},
                                {"score": 92, "failed_rules": []}])
    assert strong["delta"] == -1
    assert compliance_signal([])["delta"] == 0                 # no data -> no change
    # unscored rows with failed_rules must not force weak
    assert compliance_signal([{"failed_rules": ["x"]}])["delta"] == 0
    assert adjust_tier("scheduled", 1) == "prioritize"          # weak posture escalates
    assert adjust_tier("prioritize", -1) == "scheduled"         # strong posture eases
    assert adjust_tier("act_now", -1, kev=True) == "act_now"    # KEV never de-escalates
    assert adjust_tier("act_now", 1) == "act_now"               # can't exceed the top tier
    assert adjust_tier("unknown", 1) == "prioritize"
    assert compliance_note(weak).startswith("Compliance posture WEAK")
    # Decision Package: pure labels from SSVC/tier + recommended interim
    _pkg = build_decision_package(
        {"tier": "act_now", "ssvc_decision": "act", "ssvc_label": "Act"},
        recommended=type("O", (), {"title": "kpatch", "disruption": "none",
                                   "effectiveness": 4})(),
        freeze=True)
    assert _pkg["residual_before"] == "high" and _pkg["residual_after"] == "moderate"
    assert "kpatch" in _pkg["decision_summary"] and "non-disruptive" in _pkg["decision_summary"]
    assert build_decision_package(
        {"tier": "scheduled", "ssvc_label": "Track"},
        controls=[{"status": "mitigated"}])["residual_before"] == "low"
    assert build_decision_package(
        {"tier": "prioritize", "ssvc_label": "Attend"},
        fix_state="Not affected")["residual_after"] == "minimal"
    print("ok")
