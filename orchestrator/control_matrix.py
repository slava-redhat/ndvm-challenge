"""Deterministic control-vs-CVE-type validation matrix.

Python-owned truth table: does a security control mitigate a given CVE attack
class? The validator LLM still reasons about context, but this matrix provides
a ground-truth floor — if the matrix says "no", the LLM cannot upgrade to
"mitigated". If the matrix says "yes", the LLM may still downgrade to
"partial" with rationale (e.g., misconfigured SELinux).

ponytail: start with the controls and attack classes that appear in our YAML
catalog and Red Hat CVE data. Extend rows/columns as new controls or CWE
families appear — the lookup returns None (defer to LLM) for unknown pairs.
"""
from __future__ import annotations

import re
from typing import Literal

Verdict = Literal["mitigated", "partial", "not_mitigated"]

# Rows: normalized control names (lowercased, as customers state them)
# Columns: attack class tags inferred from CWE / CVSS / description
# Values: worst-case verdict assuming the control is properly configured
_MATRIX: dict[str, dict[str, Verdict]] = {
    "selinux_enforcing": {
        "privilege_escalation":  "partial",     # confines but doesn't fix root cause
        "container_escape":     "partial",      # MCS labels limit blast radius
        "arbitrary_code_exec":  "partial",      # confined execution, not prevention
        "local_file_access":    "partial",      # type enforcement limits file access
        "remote_code_exec":     "not_mitigated",
        "denial_of_service":    "not_mitigated",
        "info_disclosure":      "not_mitigated",
        "buffer_overflow":      "not_mitigated",
    },
    "firewall": {
        "remote_code_exec":     "partial",      # blocks inbound vectors
        "lateral_movement":     "partial",
        "data_exfiltration":    "partial",
        "privilege_escalation": "not_mitigated",
        "local_file_access":    "not_mitigated",
        "buffer_overflow":      "not_mitigated",
        "denial_of_service":    "partial",
    },
    "network_segmentation": {
        "remote_code_exec":     "partial",
        "lateral_movement":     "mitigated",
        "data_exfiltration":    "partial",
        "privilege_escalation": "not_mitigated",
        "denial_of_service":    "partial",
    },
    "fips_mode": {
        "crypto_weakness":      "mitigated",
        "info_disclosure":      "partial",
        "privilege_escalation": "not_mitigated",
        "remote_code_exec":     "not_mitigated",
    },
    "kernel_livepatch": {
        "privilege_escalation": "mitigated",
        "buffer_overflow":      "mitigated",
        "arbitrary_code_exec":  "mitigated",
        "use_after_free":       "mitigated",
    },
}

# Normalize customer-stated control strings to matrix keys
_CONTROL_ALIASES: list[tuple[str, tuple[str, ...]]] = [
    ("selinux_enforcing", ("selinux", "se-linux", "selinux enforcing")),
    ("firewall",          ("firewall", "nftables", "iptables", "firewalld", "dmz")),
    ("network_segmentation", ("network segmentation", "network isolation",
                              "vlan", "microsegmentation", "dmz")),
    ("fips_mode",         ("fips", "fips mode", "fips 140")),
    ("kernel_livepatch",  ("kpatch", "livepatch", "kernel live patch", "ksplice")),
]

# Infer attack class from CWE numbers or description keywords
_ATTACK_CLASS_PATTERNS: list[tuple[str, tuple[str, ...]]] = [
    ("privilege_escalation", ("privilege escalation", "priv esc", "local privilege",
                              "cwe-269", "cwe-250")),
    ("remote_code_exec",     ("remote code execution", "rce", "cwe-94")),
    ("arbitrary_code_exec",  ("arbitrary code", "code execution", "cwe-78", "cwe-77")),
    ("buffer_overflow",      ("buffer overflow", "heap overflow", "stack overflow",
                              "out-of-bounds write", "cwe-120", "cwe-787", "cwe-122")),
    ("use_after_free",       ("use-after-free", "use after free", "cwe-416")),
    ("container_escape",     ("container escape", "container breakout", "runc",
                              "cwe-269")),
    ("denial_of_service",    ("denial of service", "dos", "crash", "cwe-400",
                              "cwe-770")),
    ("info_disclosure",      ("information disclosure", "info leak", "memory leak",
                              "cwe-200", "cwe-532")),
    ("local_file_access",    ("local file", "path traversal", "directory traversal",
                              "cwe-22")),
    ("lateral_movement",     ("lateral movement", "pivot")),
    ("data_exfiltration",    ("data exfiltration", "exfil")),
    ("crypto_weakness",      ("cryptographic", "weak cipher", "ssl", "tls",
                              "cwe-327", "cwe-326")),
]


def normalize_control(raw: str) -> str | None:
    low = (raw or "").strip().lower()
    for key, aliases in _CONTROL_ALIASES:
        if any(a in low for a in aliases):
            return key
    return None


def infer_attack_classes(description: str, cwe: str = "") -> list[str]:
    blob = f"{description} {cwe}".lower()
    return [cls for cls, tokens in _ATTACK_CLASS_PATTERNS
            if any(t in blob for t in tokens)]


def lookup(control: str, attack_class: str) -> Verdict | None:
    """Deterministic lookup. None = matrix has no opinion (defer to LLM)."""
    return _MATRIX.get(control, {}).get(attack_class)


def validate_control(raw_control: str, cve_description: str,
                     cwe: str = "") -> dict:
    """Validate a customer-stated control against a CVE's attack profile.

    Returns {control, normalized, attack_classes, verdict, rationale}.
    verdict is the strictest (most conservative) matrix opinion across all
    attack classes. None verdicts (unknown pairs) are skipped.
    """
    norm = normalize_control(raw_control)
    classes = infer_attack_classes(cve_description, cwe)
    if not norm or not classes:
        return {"control": raw_control, "normalized": norm,
                "attack_classes": classes, "verdict": None,
                "rationale": "no matrix coverage — deferred to LLM reasoning"}

    verdicts = []
    details = []
    for cls in classes:
        v = lookup(norm, cls)
        if v is not None:
            verdicts.append(v)
            details.append(f"{cls}={v}")

    if not verdicts:
        return {"control": raw_control, "normalized": norm,
                "attack_classes": classes, "verdict": None,
                "rationale": "no matrix coverage — deferred to LLM reasoning"}

    # Conservative: worst verdict wins
    priority = {"not_mitigated": 0, "partial": 1, "mitigated": 2}
    worst = min(verdicts, key=lambda v: priority[v])
    return {"control": raw_control, "normalized": norm,
            "attack_classes": classes, "verdict": worst,
            "rationale": f"matrix: {', '.join(details)}"}


if __name__ == "__main__":
    assert normalize_control("SELinux in enforcing mode") == "selinux_enforcing"
    assert normalize_control("nftables firewall") == "firewall"
    assert normalize_control("unknown thing") is None

    classes = infer_attack_classes("kernel privilege escalation via netfilter")
    assert "privilege_escalation" in classes

    r = validate_control("SELinux enforcing",
                         "kernel privilege escalation via netfilter")
    assert r["verdict"] == "partial"
    assert r["normalized"] == "selinux_enforcing"

    r2 = validate_control("nftables firewall", "remote code execution in httpd")
    assert r2["verdict"] == "partial"

    r3 = validate_control("kpatch", "use-after-free in kernel netfilter")
    assert r3["verdict"] == "mitigated"

    r4 = validate_control("FIPS mode", "weak TLS cipher negotiation")
    assert r4["verdict"] == "mitigated"

    r5 = validate_control("unknown control", "whatever")
    assert r5["verdict"] is None

    print("ok")
