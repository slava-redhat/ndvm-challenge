"""Pure Red Hat CVE JSON parser. No heavy deps so it stays unit-testable.

Trust rule: fix_state is read from Red Hat's data, never inferred by an LLM.
"""
import re

CVE_PAGE = "https://access.redhat.com/security/cve/{cve}"
SEARCH_PER_PAGE = 10  # ponytail: cap rows — enough for triage, keeps LLM tokens sane

# fix_state values that mean "no vendor fix is coming (soon)" -> NDVM is the point.
NO_FIX_STATES = {"Fix deferred", "Will not fix", "Out of support scope", "Affected"}

# Trust-boundary input guards: reject a malformed tool arg BEFORE the HTTP round-trip
# (an LLM occasionally passes "old openssh" or a URL as the CVE). Fail fast, cheaply.
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CVE_FIND_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
ADVISORY_RE = re.compile(r"^RH[SBE]A-\d{4}:\d+$", re.IGNORECASE)
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SEVERITIES = {"low", "moderate", "important", "critical"}


def valid_cve(cve: str) -> bool:
    return bool(CVE_RE.match((cve or "").strip()))


def filter_rag_hits_for_cve(hits: list, cve: str) -> list:
    """Keep only RAG chunks that do not cite a *different* CVE than the pinned one.

    Dense search happily returns other seed CVE blurbs as 'similar'. Trust rule: never
    treat another CVE's page as mitigation guidance for this case. Chunks that name no
    CVE (catalog/PDF hardening) stay eligible.
    """
    pinned = (cve or "").strip().upper()
    if not pinned:
        return list(hits or [])
    kept = []
    for hit in hits or []:
        blob = f"{hit.get('source_url') or ''} {hit.get('text') or ''}"
        found = {m.group(0).upper() for m in CVE_FIND_RE.finditer(blob)}
        if found and pinned not in found:
            continue
        kept.append(hit)
    return kept


def prefer_mitigation_hits(hits: list) -> list:
    """Allow-list options: keep only curated doc_type=mitigation chunks.

    PDFs alone must not drive NDVM options — thin PDF similarity is guessing.
    """
    return [h for h in (hits or [])
            if (h.get("metadata") or {}).get("doc_type") == "mitigation"]


def ndvm_applies_for(fix_state: str) -> bool:
    """NDVM applies unless Red Hat says the product isn't affected. A fix that shipped
    but can't be applied yet (reboot/change window blocked) STILL needs interim
    mitigation — so 'Fixed' is a first-class NDVM trigger, only 'Not affected' opts out."""
    return fix_state != "Not affected"


def search_params(package="", product="", severity="", advisory="", after="") -> dict:
    """Build the cve.json search query from non-empty filters. Raises ValueError on a
    malformed filter (validated here so the tool never fires a doomed request)."""
    params = {"per_page": SEARCH_PER_PAGE}
    for k, v in (("package", package), ("product", product), ("severity", severity),
                 ("advisory", advisory), ("after", after)):
        if v and v.strip():
            params[k] = v.strip()
    if len(params) == 1:
        raise ValueError("provide at least one filter (package/product/severity/advisory/after)")
    if "severity" in params:
        sev = params["severity"].lower()
        if sev not in SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(SEVERITIES)}")
        params["severity"] = sev  # RH API requires lowercase
    if "advisory" in params and not ADVISORY_RE.match(params["advisory"]):
        raise ValueError("advisory must look like RHSA-2024:2394 (RHSA/RHBA/RHEA-YYYY:NNNN)")
    if "after" in params and not DATE_RE.match(params["after"]):
        raise ValueError("after must be a date YYYY-MM-DD")
    return params


def slim_rows(rows: list) -> list:
    """Reduce cve.json search rows to the fields the agent needs; cap package lists."""
    return [{
        "cve": x.get("CVE"),
        "severity": x.get("severity"),
        "public_date": x.get("public_date"),
        "cvss3": x.get("cvss3_score"),
        "advisories": x.get("advisories") or [],
        "affected_packages": (x.get("affected_packages") or [])[:5],
        "summary": x.get("bugzilla_description"),
        "url": x.get("resource_url"),
    } for x in rows]


def cache_fields_from_slim(row: dict) -> dict | None:
    """Map a slim search hit to cve-table columns. Appends packages into summary so
    offline package/product ILIKE works without a schema change (ponytail ceiling)."""
    cve = (row.get("cve") or "").strip()
    if not cve:
        return None
    summary = (row.get("summary") or "").strip()
    pkgs = [p for p in (row.get("affected_packages") or []) if p]
    if pkgs:
        tag = "[" + ", ".join(pkgs) + "]"
        summary = f"{summary} {tag}".strip() if summary else tag
    cvss = None
    try:
        raw = row.get("cvss3")
        cvss = float(raw) if raw is not None and raw != "" else None
    except (TypeError, ValueError):
        cvss = None
    return {
        "cve_id": cve.upper(),
        "threat_severity": row.get("severity"),
        "cvss3": cvss,
        "summary": summary or None,
        "source_url": row.get("url") or CVE_PAGE.format(cve=cve.upper()),
    }


def cache_search_filters(package: str = "", product: str = "", severity: str = "",
                         advisory: str = "", after: str = ""):
    """Build WHERE clauses for offline cve-table search, or None if uncacheable.

    ponytail: no public_date/advisory columns — advisory or after-only need the API.
    """
    if (advisory or "").strip() or ((after or "").strip()
                                    and not any((package, product, severity))):
        return None
    clauses, params = [], []
    if (severity or "").strip():
        clauses.append("LOWER(COALESCE(threat_severity, '')) = LOWER(%s)")
        params.append(severity.strip())
    text = " ".join(x.strip() for x in (package, product) if x and x.strip())
    if text:
        like = f"%{text}%"
        clauses.append("(COALESCE(summary, '') ILIKE %s OR cve_id ILIKE %s)")
        params.extend([like, like])
    return (clauses, params) if clauses else None


def _match(product_name: str, hint: str) -> bool:
    """True when hint is a substring of product_name, rejecting minor-version false
    hits (hint '... Linux 8' must not match '... Linux 8.6')."""
    if not hint:
        return False
    pn, h = (product_name or "").lower(), hint.lower()
    idx = pn.find(h)
    if idx < 0:
        return False
    after = pn[idx + len(h):]
    # Hint ended on a version digit; a following ".N" means a longer minor matched.
    if h[-1:].isdigit() and after.startswith(".") and after[1:2].isdigit():
        return False
    return True


def _best_match(rows: list, product_hint: str):
    """Among rows whose product_name matches the hint, prefer the shortest name
    (exact major over a longer string that still contains the hint)."""
    hits = [r for r in rows if _match(r.get("product_name", ""), product_hint)]
    if not hits:
        return None
    return min(hits, key=lambda r: len(r.get("product_name") or ""))


def analyze_cve_json(data: dict, product_hint: str = "") -> dict:
    """Red Hat CVE JSON -> VulnFinding-shaped dict for a given product."""
    cve_id = data.get("name", "")
    cvss3 = None
    try:
        raw = (data.get("cvss3") or {}).get("cvss3_base_score")
        cvss3 = float(raw) if raw is not None else None
    except (TypeError, ValueError):
        cvss3 = None

    rhsa = fixed_nvra = None
    fix_state = "unknown"
    releases = data.get("affected_release") or []
    states = data.get("package_state") or []

    # 1) A shipped erratum for the product -> Fixed.
    rel = _best_match(releases, product_hint)
    if rel is not None:
        fix_state = "Fixed"
        rhsa = rel.get("advisory")
        fixed_nvra = rel.get("package")

    # 2) Otherwise the declared package_state for the product.
    if fix_state == "unknown":
        st = _best_match(states, product_hint)
        if st is not None:
            fix_state = st.get("fix_state") or "unknown"

    # 3) No product match: surface the most relevant state overall.
    if fix_state == "unknown":
        all_states = {st.get("fix_state") for st in states if st.get("fix_state")}
        if releases:
            fix_state = "Fixed"
            rhsa = releases[0].get("advisory")
            fixed_nvra = releases[0].get("package")
        elif all_states & NO_FIX_STATES:
            fix_state = next(s for s in ("Fix deferred", "Will not fix",
                                         "Out of support scope", "Affected")
                             if s in all_states)
        elif all_states == {"Not affected"}:
            fix_state = "Not affected"
        elif all_states:
            # Prefer a known NDVM-relevant label over hash-order of the set.
            for pref in ("Affected", "Fix deferred", "Will not fix",
                         "Out of support scope", "Fixed", "Not affected"):
                if pref in all_states:
                    fix_state = pref
                    break
            else:
                fix_state = sorted(all_states)[0]

    ndvm_applies = ndvm_applies_for(fix_state)
    if fix_state == "Not affected":
        rationale = "Red Hat marks this product not affected — the mitigation is to do nothing (evidence: VEX)."
    elif fix_state == "Fixed":
        rationale = f"A fix shipped ({rhsa}); until the maintenance window, use interim non-disruptive mitigations."
    elif fix_state in NO_FIX_STATES:
        rationale = f"Red Hat status '{fix_state}': immediate patching is not feasible — NDVM applies."
    else:
        rationale = "Fix status unclear from Red Hat data; treat as needing interim mitigation."

    return {
        "cve_id": cve_id,
        "threat_severity": data.get("threat_severity", "unknown"),
        "cvss3": cvss3,
        "fix_state": fix_state,
        "ndvm_applies": ndvm_applies,
        "rhsa": rhsa,
        "fixed_nvra": fixed_nvra,
        "rationale": rationale,
        "source_urls": [CVE_PAGE.format(cve=cve_id)] if cve_id else [],
    }
