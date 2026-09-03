"""Deterministic mitigation catalog: IDs, applicability, fail-closed pinning.

Options come only from curated YAML rows retrieved as doc_type=mitigation.
The LLM may rank/explain; Python owns the option records and citations.
"""
from __future__ import annotations

import re
from typing import Iterable

from control_matrix import infer_attack_classes, lookup as _matrix_lookup
from models import MitigationOption, VulnFinding

# Map a catalog option to a control_matrix control family, so an option is checked
# against the CVE's ATTACK CLASS the same way the customer's existing controls are.
# This catches "control doesn't counter this mechanism" mismatches that the component
# gate cannot express (e.g. a NetworkPolicy top-ranked for a LOCAL privilege-escalation
# CVE). Options left unmapped defer to ranking — the matrix has no opinion on:
#   - vendor-fix delivery / version-blocking (ocp_roll_image, *_admission/image/acs,
#     rhel_service_restart, rhel_insights_remediation) — that is the component/plane
#     question, gated by components/exclude_components, not the attack class;
#   - removing the vulnerable code path (scale-to-zero, pause operator, disable/blacklist
#     module) — effective against any class it reaches.
_OPTION_CONTROL: dict[str, str] = {
    # network-surface controls: only help network-reachable attack classes
    "ocp_networkpolicy":  "network_segmentation",
    "ocp_egress_policy":  "network_segmentation",
    "ocp_cut_route":      "firewall",
    "ocp_default_deny":   "network_segmentation",
    "ocp_quarantine_nodes": "network_segmentation",
    "rhel_firewalld":     "firewall",
    "rhel_nftables":      "firewall",
    "rhel_openssl_isolate": "firewall",
    "rhel_quarantine":    "network_segmentation",
    "rhel_http_surface":  "firewall",
    # confinement controls: contain, don't fix; useless against classes SELinux can't touch
    "ocp_scc":            "selinux_enforcing",
    "ocp_restricted_v2":  "selinux_enforcing",
    "ocp_seccomp":        "selinux_enforcing",
    "rhel_selinux":       "selinux_enforcing",
    "rhel_systemd_harden": "selinux_enforcing",
    "rhel_container_runtime": "selinux_enforcing",
    # kernel live patch: the actual in-place kernel fix
    "rhel_kpatch":        "kernel_livepatch",
    # crypto policy: only weak-crypto classes
    "rhel_crypto_policy": "fips_mode",
}


def attack_class_applicable(catalog_id: str, attack_classes: list[str]) -> bool:
    """False only when the matrix says this option's control counters NONE of the CVE's
    attack classes. Unmapped option, no attack class, or no matrix opinion -> True (defer).

    Best-case across classes: an option is kept if it helps with even one relevant class
    (a firewall stays for a remote-DoS kernel CVE but is dropped for a local privesc one)."""
    control = _OPTION_CONTROL.get(catalog_id)
    if not control or not attack_classes:
        return True
    verdicts = [v for v in (_matrix_lookup(control, ac) for ac in attack_classes)
                if v is not None]
    if not verdicts:
        return True
    return any(v != "not_mitigated" for v in verdicts)

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
                     platform: str = "", message: str = "") -> set[str]:
    """Component classes from the AUTHORITATIVE Red Hat affected-package list, the
    finding, and what the user actually said (the message) — so e.g. a kernel CVE is
    recognised as 'kernel' (enabling kpatch) even when the product's fixed package name
    doesn't contain 'kernel'. The message is the user's own words, not a guess."""
    blob = " ".join(
        x for x in (
            " ".join(pinned.affected_packages or []),
            pinned.fixed_nvra or "",
            pinned.rationale or "",
            pinned.cve_id or "",
            product or "",
            platform or "",
            message or "",
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
    # A colon-space in an unquoted YAML step parses as a dict — coerce so one malformed
    # catalog row degrades gracefully instead of 500-ing the whole advise flow.
    steps = [s if isinstance(s, str) else " ".join(f"{k}: {v}" for k, v in s.items())
             if isinstance(s, dict) else str(s) for s in steps]
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
                           product: str = "", platform: str = "",
                           message: str = "") -> list[dict]:
    components = infer_components(pinned, product, platform, message)
    # Attack mechanism from Red Hat: CWE + description, NOT fix-state rationale prose.
    attack_classes = infer_attack_classes(
        f"{pinned.description or ''} {pinned.rationale or ''}", pinned.cwe or "")
    applicable, attack_ok = [], []
    for hit in hits or []:
        meta = hit.get("metadata") or {}
        cid = hit_catalog_id(hit)
        if not cid:
            continue
        if not _applies(meta, components, pinned.fix_state or "unknown"):
            continue
        applicable.append(hit)
        if attack_class_applicable(cid, attack_classes):
            attack_ok.append(hit)
    # Fail-safe: never let the attack-class gate empty a menu the component gate accepted.
    return attack_ok or applicable


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
    # Authoritative RH packages drive component gating even when fix-state prose is silent
    # and the product's fixed package name doesn't contain 'kernel' (the CBIS case).
    cbis = VulnFinding(cve_id="CVE-2026-31431", fix_state="Fixed",
                       fixed_nvra="cbis-kmod-6.1-1", affected_packages=["kernel"],
                       rationale="A fix shipped (RHSA-2026:14926)")
    assert "kernel" in infer_components(cbis, product="CBIS", platform="rhel")
    # The user's own words also count: 'kernel issue' in the message infers kernel.
    bare = VulnFinding(cve_id="CVE-2026-31431", fix_state="Fixed",
                       rationale="A fix shipped (RHSA-2026:14926)")
    assert "kernel" not in infer_components(bare, product="CBIS", platform="rhel")
    assert "kernel" in infer_components(bare, product="CBIS", platform="rhel",
                                        message="CVE-2026-31431 is a kernel issue")

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

    # Attack-class gate: a network control is useless against a LOCAL privesc kernel CVE
    # (dropped), but the kernel live patch that counters privesc is kept.
    fw = {"source_url": "https://access.redhat.com/solutions/962473", "text": "firewalld",
          "metadata": {"catalog_id": "rhel_firewalld", "title": "firewalld",
                       "action_type": "network", "disruption": "low", "effectiveness": 3,
                       "effort": 1, "scope": "generic", "description": "restrict"}}
    kept_ids = {hit_catalog_id(h) for h in filter_applicable_hits([hit, fw], kernel)}
    assert "rhel_kpatch" in kept_ids and "rhel_firewalld" not in kept_ids
    # Fail-safe: firewall alone (nothing else applies) is NOT dropped to an empty menu.
    assert filter_applicable_hits([fw], kernel)
    # A network control SURVIVES for a remotely-reachable kernel DoS (firewall helps DoS).
    kdos = VulnFinding(cve_id="CVE-2023-0001", fix_state="Affected",
                       rationale="kernel", description="remote denial of service, kernel crash")
    assert {hit_catalog_id(h) for h in filter_applicable_hits([hit, fw], kdos)} >= {"rhel_firewalld"}
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
