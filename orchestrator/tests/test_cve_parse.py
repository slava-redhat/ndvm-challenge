"""Self-check for the trust-critical CVE parser. Run: python -m pytest (or this file)."""
from cve_parse import analyze_cve_json

# Fix deferred for the customer's product -> NDVM applies (the David scenario).
DEFERRED = {
    "name": "CVE-2023-0001",
    "threat_severity": "Moderate",
    "cvss3": {"cvss3_base_score": "6.5"},
    "package_state": [
        {"product_name": "Red Hat Enterprise Linux 8", "fix_state": "Fix deferred"},
        {"product_name": "Red Hat Enterprise Linux 9", "fix_state": "Affected"},
    ],
}

# Shipped erratum for the product -> Fixed, with RHSA/NVRA.
FIXED = {
    "name": "CVE-2023-3390",
    "threat_severity": "Important",
    "cvss3": {"cvss3_base_score": "7.8"},
    "affected_release": [
        {"product_name": "Red Hat Enterprise Linux 8", "advisory": "RHSA-2023:5255",
         "package": "kernel-0:4.18.0-477.27.1.el8_8"},
    ],
}

# xz backdoor: never shipped -> every state Not affected -> do nothing.
NOT_AFFECTED = {
    "name": "CVE-2024-3094",
    "threat_severity": "Important",
    "package_state": [
        {"product_name": "Red Hat Enterprise Linux 8", "fix_state": "Not affected"},
        {"product_name": "Red Hat Enterprise Linux 9", "fix_state": "Not affected"},
    ],
}


def test_fix_deferred_triggers_ndvm():
    f = analyze_cve_json(DEFERRED, "Red Hat Enterprise Linux 8")
    assert f["fix_state"] == "Fix deferred"
    assert f["ndvm_applies"] is True
    assert f["cvss3"] == 6.5
    assert f["source_urls"]


def test_fixed_reports_rhsa_and_nvra():
    f = analyze_cve_json(FIXED, "Red Hat Enterprise Linux 8")
    assert f["fix_state"] == "Fixed"
    assert f["rhsa"] == "RHSA-2023:5255"
    assert "kernel" in f["fixed_nvra"]
    assert f["ndvm_applies"] is True  # can't patch now -> interim mitigation still wanted


def test_not_affected_means_do_nothing():
    f = analyze_cve_json(NOT_AFFECTED, "Red Hat Enterprise Linux 9")
    assert f["fix_state"] == "Not affected"
    assert f["ndvm_applies"] is False


def test_unknown_product_falls_back_to_worst_state():
    f = analyze_cve_json(DEFERRED, "Some Product We Do Not Run")
    assert f["fix_state"] in ("Fix deferred", "Affected")  # surfaces a no-fix state


if __name__ == "__main__":
    test_fix_deferred_triggers_ndvm()
    test_fixed_reports_rhsa_and_nvra()
    test_not_affected_means_do_nothing()
    test_unknown_product_falls_back_to_worst_state()
    print("ok")
