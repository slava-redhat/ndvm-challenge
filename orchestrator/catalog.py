"""Deterministic mitigation catalog: IDs, applicability, fail-closed pinning.

Options come only from curated YAML rows retrieved as doc_type=mitigation.
The LLM may rank/explain; Python owns the option records and citations.
"""
from __future__ import annotations

import re
from typing import Iterable

from models import MitigationOption, VulnFinding

# Heuristic package-class tokens for applicability (not a full CPE matcher).
_COMPONENT_PATTERNS: list[tuple[str, tuple[str, ...]]] = [
    ("kernel", ("kernel", "kpatch", "livepatch", "linux-firmware")),
    ("openssh", ("openssh", "sshd", "ssh-server", "regresshion")),
    ("openssl", ("openssl", "libssl", "crypto-policies")),
    ("httpd", ("httpd", "nginx", "http/2", "http2")),
    ("runc", ("runc", "crun", "container-runtime", "podman", "cri-o", "crio")),
    ("systemd", ("systemd",)),
    ("glibc", ("glibc",)),
]


def infer_components(pinned: VulnFinding, product: str = "",
                     platform: str = "") -> set[str]:
    """Best-effort component classes from Red Hat finding + product/platform."""
    blob = " ".join(
        x for x in (
            pinned.fixed_nvra or "",
            pinned.rationale or "",
            pinned.cve_id or "",
            product or "",
            platform or "",
        ) if x
    ).lower()
    found = {name for name, tokens in _COMPONENT_PATTERNS
             if any(t in blob for t in tokens)}
    if "openshift" in blob or (platform or "").lower() == "openshift":
        found.add("openshift")
    return found


def hit_catalog_id(hit: dict) -> str:
    return str(((hit.get("metadata") or {}).get("catalog_id") or "")).strip()


def option_from_hit(hit: dict) -> MitigationOption | None:
    """Build a MitigationOption from an ingested catalog chunk. None if no id."""
    meta = hit.get("metadata") or {}
    cid = str(meta.get("catalog_id") or "").strip()
    if not cid:
        return None
    disruption = meta.get("disruption") or "low"
    if disruption not in ("none", "low", "medium", "high"):
        disruption = "low"
    steps = meta.get("steps") or []
    if isinstance(steps, str):
        steps = [steps]
    url = (hit.get("source_url") or meta.get("source_url") or "").strip()
    return MitigationOption(
        catalog_id=cid,
        title=str(meta.get("title") or cid),
        action_type=str(meta.get("action_type") or "config"),
        description=str(meta.get("description") or (hit.get("text") or "")[:280]),
        disruption=disruption,
        effectiveness=int(meta.get("effectiveness") or 3),
        effort=int(meta.get("effort") or 2),
        steps=list(steps)[:5],
        source_urls=[url] if url else [],
    )


def _applies(meta: dict, components: set[str], fix_state: str) -> bool:
    allowed_states = [s for s in (meta.get("fix_states") or []) if s]
    if allowed_states and fix_state not in allowed_states:
        return False
    excl = {str(x).lower() for x in (meta.get("exclude_components") or [])}
    if excl & {c.lower() for c in components}:
        return False
    scope = str(meta.get("scope") or "").strip().lower()
    need = {str(x).lower() for x in (meta.get("components") or [])}
    # Must declare scope=generic (compensating) or non-empty components.
    if scope == "generic":
        pass
    elif need:
        if not (need & {c.lower() for c in components}):
            return False
    else:
        return False
    reqs = {str(x).lower() for x in (meta.get("requires") or [])}
    # ponytail: no live-patch inventory API — require kernel class only.
    if "livepatch" in reqs and "kernel" not in {c.lower() for c in components}:
        return False
    return True


def filter_applicable_hits(hits: Iterable[dict], pinned: VulnFinding,
                           product: str = "", platform: str = "") -> list[dict]:
    components = infer_components(pinned, product, platform)
    out = []
    for hit in hits or []:
        meta = hit.get("metadata") or {}
        if not hit_catalog_id(hit):
            continue
        if _applies(meta, components, pinned.fix_state or "unknown"):
            out.append(hit)
    return out


def materialize_options(hits: Iterable[dict]) -> list[MitigationOption]:
    opts, seen = [], set()
    for hit in hits or []:
        opt = option_from_hit(hit)
        if not opt or opt.catalog_id in seen:
            continue
        seen.add(opt.catalog_id)
        opts.append(opt)
    return opts


def pin_options_to_catalog(llm_options: list[MitigationOption] | None,
                           catalog_options: list[MitigationOption],
                           max_n: int = 3) -> list[MitigationOption]:
    """Keep only LLM picks that cite an exact catalog_id; replace with catalog records.

    Unmatched / invented options are dropped. LLM-supplied URLs and steps are never
    kept — the catalog owns execution instructions. If nothing matches, fall back to
    the first max_n catalog options (deterministic).
    """
    by_id = {o.catalog_id: o for o in catalog_options if o.catalog_id}
    pinned, seen = [], set()
    for o in llm_options or []:
        cid = (o.catalog_id or "").strip()
        if not cid or cid not in by_id or cid in seen:
            continue
        cat = by_id[cid]
        pinned.append(cat.model_copy(deep=True))
        seen.add(cid)
        if len(pinned) >= max_n:
            break
    if pinned:
        return pinned
    return [o.model_copy(deep=True) for o in catalog_options[:max_n]]


def catalog_context(options: list[MitigationOption]) -> str:
    """Compact allow-list for strategist/synth prompts."""
    lines = []
    for o in options:
        lines.append(
            f"- catalog_id={o.catalog_id} | {o.title} | action={o.action_type} | "
            f"disruption={o.disruption} eff={o.effectiveness} effort={o.effort} | "
            f"source={((o.source_urls or [''])[0])}"
        )
        if o.description:
            lines.append(f"  {o.description.strip()[:220]}")
    return "\n".join(lines) if lines else "(empty catalog)"


if __name__ == "__main__":
    pinned = VulnFinding(cve_id="CVE-2024-6387", fix_state="Affected",
                         fixed_nvra="openssh-8.0p1", rationale="openssh race")
    assert "openssh" in infer_components(pinned)
    kernel = VulnFinding(cve_id="CVE-2023-3390", fix_state="Affected",
                         rationale="kernel privilege escalation")
    assert "kernel" in infer_components(kernel)

    hit = {"source_url": "https://access.redhat.com/solutions/2206511",
           "text": "kpatch",
           "metadata": {"catalog_id": "rhel_kpatch", "title": "Apply kpatch",
                        "action_type": "livepatch", "disruption": "none",
                        "effectiveness": 3, "effort": 2, "components": ["kernel"],
                        "requires": ["livepatch"], "description": "live patch"}}
    assert filter_applicable_hits([hit], kernel)
    assert not filter_applicable_hits([hit], pinned)  # openssh CVE → no kpatch

    restart = {"source_url": "https://access.redhat.com/security/vulnerabilities/",
               "text": "restart",
               "metadata": {"catalog_id": "rhel_service_restart", "title": "Restart service",
                            "action_type": "config", "disruption": "low",
                            "effectiveness": 4, "effort": 2, "scope": "generic",
                            "exclude_components": ["kernel"], "description": "dnf + restart"}}
    assert not filter_applicable_hits([restart], kernel)
    assert filter_applicable_hits([restart], pinned)
    bare = {**restart, "metadata": {**restart["metadata"], "scope": "", "components": []}}
    assert not filter_applicable_hits([bare], pinned)
    assert "openshift" in infer_components(pinned, platform="openshift")

    cat = materialize_options(filter_applicable_hits([hit], kernel))
    invented = MitigationOption(
        catalog_id="invented", title="Invented", action_type="x", description="x",
        disruption="low", effectiveness=1, effort=1,
        source_urls=["https://evil.example/"])
    out = pin_options_to_catalog([invented], cat)
    assert all(o.catalog_id == "rhel_kpatch" for o in out)
    assert "evil" not in str(out[0].source_urls)
    # exact id match keeps catalog URL
    llm = MitigationOption(
        catalog_id="rhel_kpatch", title="wrong title", action_type="x", description="x",
        disruption="high", effectiveness=1, effort=1,
        source_urls=["https://invented.example/"], steps=["invented yum install"])
    pinned_opts = pin_options_to_catalog([llm], cat)
    assert pinned_opts[0].title == cat[0].title
    assert pinned_opts[0].source_urls == cat[0].source_urls
    assert pinned_opts[0].steps == cat[0].steps  # catalog owns steps
    print("ok")
