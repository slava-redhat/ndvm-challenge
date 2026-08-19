"""Pure Red Hat CVE JSON parser. No heavy deps so it stays unit-testable.

Trust rule: fix_state is read from Red Hat's data, never inferred by an LLM.
"""
CVE_PAGE = "https://access.redhat.com/security/cve/{cve}"
SEARCH_PER_PAGE = 10  # ponytail: cap rows — enough for triage, keeps LLM tokens sane

# fix_state values that mean "no vendor fix is coming (soon)" -> NDVM is the point.
NO_FIX_STATES = {"Fix deferred", "Will not fix", "Out of support scope", "Affected"}


def search_params(package="", product="", severity="", advisory="", after="") -> dict:
    """Build the cve.json search query from non-empty filters (raises if none given)."""
    params = {"per_page": SEARCH_PER_PAGE}
    for k, v in (("package", package), ("product", product), ("severity", severity),
                 ("advisory", advisory), ("after", after)):
        if v and v.strip():
            params[k] = v.strip()
    if len(params) == 1:
        raise ValueError("provide at least one filter (package/product/severity/advisory/after)")
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


def _match(product_name: str, hint: str) -> bool:
    return bool(hint) and hint.lower() in (product_name or "").lower()


def analyze_cve_json(data: dict, product_hint: str = "") -> dict:
    """Red Hat CVE JSON -> VulnFinding-shaped dict for a given product."""
    cve_id = data.get("name", "")
    cvss3 = None
    try:
        cvss3 = float(data.get("cvss3", {}).get("cvss3_base_score"))
    except (TypeError, ValueError):
        pass

    rhsa = fixed_nvra = None
    fix_state = "unknown"
    releases = data.get("affected_release") or []
    states = data.get("package_state") or []

    # 1) A shipped erratum for the product -> Fixed.
    for rel in releases:
        if _match(rel.get("product_name", ""), product_hint):
            fix_state = "Fixed"
            rhsa = rel.get("advisory")
            fixed_nvra = rel.get("package")
            break

    # 2) Otherwise the declared package_state for the product.
    if fix_state == "unknown":
        for st in states:
            if _match(st.get("product_name", ""), product_hint):
                fix_state = st.get("fix_state", "unknown")
                break

    # 3) No product match: surface the most relevant state overall.
    if fix_state == "unknown":
        all_states = {st.get("fix_state") for st in states}
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
            fix_state = next(iter(all_states))

    ndvm_applies = fix_state != "Not affected"
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
