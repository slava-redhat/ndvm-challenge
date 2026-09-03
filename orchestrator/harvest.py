"""Harvest gate-shaped answers (no LLM).

Primary customers often state freeze windows, SELinux, exposure, etc. in the first
message. Turn those into the same ``[key] question: value`` lines the UI posts so
the sufficiency gate does not re-ask, and advice sees the facts.
"""
from __future__ import annotations

import re

from cve_parse import find_cves

# (key, human question label, list of (regex, answer value))
# First matching value wins per pattern; multiple control hits are joined.
_HARVEST_RULES: list[tuple[str, str, list[tuple[re.Pattern[str], str]]]] = [
    (
        "maintenance_window",
        "Maintenance / reboot window",
        [
            (re.compile(
                r"can(?:not|\s+not)\s+reboot|can't\s+reboot|no\s+reboot|change\s+freeze|"
                r"freeze\s+until|until\s+(?:quarter|q[1-4]|month|eoy|year[- ]?end)|"
                r"no\s+downtime|cannot\s+take\s+downtime|no\s+maintenance\s+window|"
                r"can(?:not|\s+not)\s+patch\s+yet|can't\s+patch\s+yet|"
                r"maintenance\s+freeze|change\s+window\s+(?:closed|blocked)|"
                r"no\s+outage|zero[- ]downtime\s+only|cannot\s+restart\s+(?:the\s+)?(?:host|node|server)",
                re.I),
             "No reboot / change freeze this period"),
            (re.compile(
                r"next\s+(?:maintenance|change)\s+window|reboot\s+ok\s+(?:next|after)|"
                r"can\s+reboot\s+(?:this|next)\s+(?:weekend|week|month)",
                re.I),
             "Reboot possible in next maintenance window"),
        ],
    ),
    (
        "existing_controls",
        "Controls already in place",
        [
            (re.compile(r"selinux(?:\s+(?:enforcing|enabled|is\s+on))?|"
                        r"have\s+selinux|selinux\s+enforcing", re.I),
             "SELinux enforcing"),
            (re.compile(r"\bfirewalld\b|\biptables\b|\bnftables\b|host\s+firewall", re.I),
             "Host firewall active"),
            (re.compile(r"\bfips\b", re.I), "FIPS mode"),
            (re.compile(r"\bidm\b|identity\s+management|\bsssd\b", re.I), "IdM enrolled"),
            (re.compile(r"network\s+segmentation|microsegmentation|vlan\s+isolat", re.I),
             "Network segmentation"),
            (re.compile(r"\bkpatch\b|kernel\s+live\s*patch|live\s*patch(?:ing)?|"
                        r"\bkernelcare\b", re.I),
             "Kernel live patching (kpatch)"),
            (re.compile(r"\bnetworkpolicy\b|network\s+policies|default[- ]deny|"
                        r"egress\s*(?:network)?\s*policy", re.I),
             "NetworkPolicy / default-deny"),
            (re.compile(r"\brhacs\b|\bacs\b|advanced\s+cluster\s+security|"
                        r"admission\s+controller|gatekeeper|kyverno|oph\b", re.I),
             "Admission / ACS policy"),
            (re.compile(r"restricted(?:-v2)?\s+scc|\bscc\b.*restrict|"
                        r"pod\s+security\s+(?:admission|standard)|psa\s+restricted",
                        re.I),
             "Restricted SCC / PSA"),
            (re.compile(r"red\s+hat\s+insights|\binsights\b|advisor\s+remediation", re.I),
             "Red Hat Insights"),
            (re.compile(r"\bsatellite\b|disconnected\s+(?:env|network|registry)|"
                        r"air[- ]gapped\s+(?:content|repo)", re.I),
             "Satellite / disconnected content"),
            (re.compile(r"\bwaf\b|web\s+application\s+firewall|mod_security", re.I),
             "WAF in front"),
            (re.compile(r"\bmfa\b|multi[- ]factor|2fa|sso\b|single\s+sign[- ]on", re.I),
             "MFA / SSO"),
            (re.compile(r"\bluks\b|disk\s+encryption|encrypted\s+(?:volumes?|disks?)", re.I),
             "Disk encryption"),
            (re.compile(r"private\s+registry|image\s+sign(?:ing|ed)|"
                        r"clusterimagepolicy|signed\s+images?\s+only", re.I),
             "Signed / private images only"),
            (re.compile(r"\bauditd\b|audit\s+logging|central(?:ized)?\s+logging|"
                        r"\bsplunk\b|\belastic\b.*log", re.I),
             "Audit / centralized logging"),
            (re.compile(r"crypto[- ]policies|system[- ]wide\s+crypto|"
                        r"tls\s*1\.[23]\s+only", re.I),
             "Crypto-policy / TLS hardened"),
            (re.compile(r"egress\s+proxy|forward\s+proxy|no\s+direct\s+egress|"
                        r"restricted\s+egress", re.I),
             "Restricted egress / proxy"),
        ],
    ),
    (
        "exposure",
        "Network exposure",
        [
            (re.compile(r"internet[- ]facing|public[- ]facing|\bdmz\b|"
                        r"exposed\s+to\s+(?:the\s+)?internet|public\s+(?:ip|elb|load\s*balancer)|"
                        r"public\s+route",
                        re.I),
             "Internet-facing"),
            (re.compile(r"air[- ]gapped|internal\s+only|not\s+(?:internet|public)[- ]facing|"
                        r"private\s+subnet|no\s+public\s+ip|vpn[- ]only|"
                        r"management\s+network\s+only|corp(?:orate)?\s+network\s+only|"
                        r"private\s+route|no\s+public\s+route",
                        re.I),
             "Internal / VPN / private only"),
            (re.compile(r"bastion|jump\s*host|via\s+vpn", re.I),
             "Reachable only via bastion/VPN"),
        ],
    ),
    (
        "backup_dr",
        "Backup / DR readiness",
        [
            (re.compile(r"tested\s+dr|dr\s+tested|standby\s+ready|failover\s+tested|"
                        r"warm\s+standby|hot\s+standby|dr\s+drill", re.I),
             "Tested DR/standby ready"),
            (re.compile(r"no\s+(?:dr|disaster\s+recovery)|without\s+(?:dr|backups?)\b|"
                        r"no\s+tested\s+restore|backups?\s+untested", re.I),
             "No safe alternate capacity"),
            (re.compile(r"daily\s+backups?|velero|odf\s+backup|etcd\s+backup|"
                        r"snapshot(?:s|ting)\s+(?:enabled|in\s+place)", re.I),
             "Backups/snapshots in place"),
        ],
    ),
]


# Strong, unambiguous OpenShift/Kubernetes signals the user wrote themselves.
# Deliberately NOT 'cluster', 'node', 'pod' or 'operator' — those appear in RHEL HA
# and general prose, so treating them as a signal would be guessing, not reading.
_OCP_SIGNALS = ("openshift", "ocp", "kubernetes", "k8s", "rhcos", "kubelet",
                "machineconfig", "container platform", "cri-o", "crio", "oc adm",
                "oc apply", "oc get")
# Unambiguous RHEL host-plane signals.
_RHEL_SIGNALS = ("rhel", "red hat enterprise", "enterprise linux",
                 " el7", " el8", " el9", ".el7", ".el8", ".el9")


def _platform_from_answer(answers: str) -> str | None:
    """Deterministically read an explicit platform CHOICE the user made in the gate.

    None when unanswered/blank. An explicit 'Other' choice maps to 'other' (search
    both menus) — that is the user's own selection, not a guess."""
    for line in (answers or "").splitlines():
        m = re.match(r"^\[platform\]\s*[^:]*:\s*(.+)$", line.strip(), re.I)
        if not m:
            continue
        val = m.group(1).strip().lower()
        if not val or val in ("(no answer)", "not sure"):
            return None
        if any(t in val for t in _OCP_SIGNALS):
            return "openshift"
        if "rhel" in val or "enterprise linux" in val:
            return "rhel"
        return "other"
    return None


def detect_platform(message: str, answers: str = "") -> str | None:
    """100% deterministic platform — NEVER the LLM router's guess.

    The platform selects the ENTIRE mitigation menu (RHEL host plane vs OpenShift
    workload plane); a wrong pick silently hides the right answer (e.g. kpatch for a
    kernel CVE). So it is read only from what the user actually stated:
      - an explicit gate CHOICE, else
      - an unambiguous signal in the message (OpenShift XOR RHEL).
    Returns None when the message is unclear (neither signal, or both) so the caller
    ASKS the user instead of guessing.
    """
    chosen = _platform_from_answer(answers)
    if chosen:
        return chosen
    low = (message or "").lower()
    ocp = any(t in low for t in _OCP_SIGNALS)
    rhel = any(t in low for t in _RHEL_SIGNALS)
    if ocp and not rhel:
        return "openshift"
    if rhel and not ocp:
        return "rhel"
    return None


def _answered_keys(answers: str) -> set[str]:
    return {
        m.group(1).strip().lower()
        for m in re.finditer(r"^\[([a-z0-9_-]+)\]", answers or "", re.MULTILINE | re.I)
    }


def harvest_answers(message: str) -> str:
    """Return ``[key] question: value`` lines for facts confidently present in message."""
    text = message or ""
    if not text.strip():
        return ""
    lines: list[str] = []
    for key, label, patterns in _HARVEST_RULES:
        hits: list[str] = []
        for rx, value in patterns:
            if rx.search(text) and value not in hits:
                hits.append(value)
        if hits:
            lines.append(f"[{key}] {label}: {', '.join(hits)}")
    return "\n".join(lines)


def merge_answers(*parts: str) -> str:
    """Merge answer blobs; keep the first line for each ``[key]`` (UI/estate wins over harvest if listed first — callers put harvest first so prose fills gaps only)."""
    seen: set[str] = set()
    out: list[str] = []
    for part in parts:
        for line in (part or "").splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.match(r"^\[([a-z0-9_-]+)\]", line, re.I)
            if m:
                key = m.group(1).lower()
                if key in seen:
                    continue
                seen.add(key)
            out.append(line)
    return "\n".join(out)


def remaining_cves(message: str, chosen: str = "") -> list[str]:
    """CVE ids named in message except the one already analyzed (order preserved)."""
    chosen_u = (chosen or "").strip().upper()
    return [c for c in find_cves(message) if c != chosen_u]


def which_cve_answer_line(cve: str) -> str:
    """Pre-answer the multi-CVE radio so the next advise run skips which_cve."""
    return (f"[which_cve] You named more than one CVE — which should we analyze first?: "
            f"{(cve or '').strip().upper()}")


def _answer_values(answers: str) -> str:
    """Join values after the first ':' on each answer line (not question prose)."""
    return " ".join(
        line.split(":", 1)[-1]
        for line in (answers or "").splitlines() if ":" in line
    ).upper()


def select_cve(message: str, answers: str = "", named: list[str] | None = None) -> str | None:
    """Pick the CVE to analyze from the customer message (+ gate answers).

    Returns:
      - the sole CVE named in the message, or the multi-CVE radio pick
      - None if 2+ CVEs are named and none has been picked yet (ask which_cve)
      - "" if the message names no CVE (caller may research)

    Pass ``named`` to use a pre-filtered list (e.g. after dropping RH-unknown ids).
    """
    named = list(named) if named is not None else find_cves(message)
    if not named:
        return ""
    if len(named) == 1:
        return named[0]
    picked = next((c for c in named if c in _answer_values(answers)), "")
    return picked or None


if __name__ == "__main__":
    # Platform is deterministic and NEVER guessed: unclear -> None (caller asks).
    # The router LLM's opinion is irrelevant — detect_platform never takes it.
    assert detect_platform("CVE-2026-31431 kernel issue, can't reboot") is None
    assert detect_platform("our OpenShift cluster is on CVE-2026-31431") == "openshift"
    assert detect_platform("kubernetes workload hit by CVE-x") == "openshift"
    assert detect_platform("RHEL 9 host, kernel CVE") == "rhel"
    assert detect_platform("plain question") is None
    # 'cluster'/'node'/'pod' alone are too weak to be a signal -> ask, don't guess.
    assert detect_platform("my cluster node has a kernel bug") is None
    # Both signals present is ambiguous -> ask.
    assert detect_platform("openshift on rhel worker") is None
    # An explicit gate choice is deterministic and wins over the (unclear) message.
    q = "[platform] Which platform is this on?: Red Hat OpenShift"
    assert detect_platform("kernel issue", q) == "openshift"
    q2 = "[platform] Which platform is this on?: Red Hat Enterprise Linux (RHEL) host"
    assert detect_platform("kernel issue", q2) == "rhel"
    assert detect_platform("kernel issue", "[platform] x: (no answer)") is None
    assert harvest_answers("we run SELinux enforcing and can't reboot until quarter-end")
    print("ok")
