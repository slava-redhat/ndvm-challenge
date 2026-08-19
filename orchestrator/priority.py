"""Prioritization: is this CVE exploited in the wild, and how likely is exploitation?

Two public feeds, both facts (not opinions), so we read them in Python and let the LLM
only explain — same trust rule as the CVE parser:
  - CISA KEV  : Known Exploited Vulnerabilities catalog (binary: listed => exploited).
  - FIRST EPSS: 30-day exploitation probability (0..1) + percentile.

Network is best-effort: if a feed is unreachable we degrade to severity-only tiering
rather than fail the user's answer.
"""
from functools import lru_cache

import requests

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
TIMEOUT = 8


@lru_cache(maxsize=1)
def _kev_set() -> frozenset:
    """CISA KEV cveIDs. Cached for the process lifetime (ponytail: refresh on restart)."""
    r = requests.get(KEV_FEED, timeout=TIMEOUT)
    r.raise_for_status()
    return frozenset(v.get("cveID", "") for v in r.json().get("vulnerabilities", []))


def in_kev(cve: str) -> bool:
    try:
        return cve.strip().upper() in _kev_set()
    except Exception:
        return False  # feed down: treat as not-listed rather than crash


@lru_cache(maxsize=4096)
def _epss_cached(cve: str) -> tuple:
    """Live EPSS lookup, cached per process. Raises on failure/no-data so lru_cache
    keeps only successful hits (a transient error or a not-yet-scored CVE stays retryable
    — lru_cache never caches exceptions)."""
    r = requests.get(EPSS_API, params={"cve": cve}, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json().get("data") or []
    if not data:
        raise LookupError("no EPSS data")
    return float(data[0]["epss"]), float(data[0]["percentile"])


def fetch_epss(cve: str):
    """(epss, percentile) as floats, or (None, None) if unavailable."""
    try:
        return _epss_cached(cve.strip().upper())
    except Exception:
        return None, None


def classify(kev: bool, epss, severity: str = "") -> tuple[str, str]:
    """Pure tiering — the auditable core. Returns (tier, rationale)."""
    sev = (severity or "").lower()
    pct = f"{epss:.0%}" if epss is not None else "unknown"
    if kev:
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


def assess(cve: str, severity: str = "", kev_hint: bool = False) -> dict:
    """Build the ExploitSignal-shaped dict for a CVE. kev_hint lets an account's own
    known_exploited flag stand in when the live feed is unreachable."""
    cve = (cve or "").strip().upper()
    kev = in_kev(cve) or bool(kev_hint)
    epss, pct = fetch_epss(cve)
    tier, rationale = classify(kev, epss, severity)
    sources = [KEV_PAGE] if kev else []
    if epss is not None:
        sources.append(f"{EPSS_API}?cve={cve}")
    return {"cve": cve, "in_kev": kev, "epss": epss, "epss_percentile": pct,
            "tier": tier, "rationale": rationale, "source_urls": sources}


def priority_note(sig: dict) -> str:
    """One-line summary for LLM prompts (business_risk + ranking)."""
    parts = [f"urgency tier: {sig['tier']}"]
    if sig.get("in_kev"):
        parts.append("KNOWN EXPLOITED (CISA KEV)")
    if sig.get("epss") is not None:
        parts.append(f"EPSS {sig['epss']:.0%} (percentile {sig.get('epss_percentile', 0):.0%})")
    return "; ".join(parts) + "."


if __name__ == "__main__":  # self-check for the pure classifier (no network needed)
    assert classify(True, 0.9, "Critical")[0] == "act_now"
    assert classify(False, 0.6)[0] == "act_now"
    assert classify(False, 0.2)[0] == "prioritize"
    assert classify(False, None, "Critical")[0] == "prioritize"
    assert classify(False, 0.02, "Moderate")[0] == "scheduled"
    assert classify(False, None, "Important")[0] == "scheduled"
    assert classify(False, 0.0, "Low")[0] == "routine"
    assert priority_note({"tier": "act_now", "in_kev": True, "epss": 0.94,
                          "epss_percentile": 0.99}).startswith("urgency tier: act_now")
    print("ok")
