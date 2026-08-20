"""Self-check for the trust-critical CVE parser. Run: python -m pytest (or this file)."""
from cve_parse import analyze_cve_json, ndvm_applies_for, search_params, valid_cve

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


def test_ndvm_trigger_rule():
    # reboot-blocked "Fixed" is a first-class trigger; only "Not affected" opts out.
    assert ndvm_applies_for("Fixed") is True
    assert ndvm_applies_for("Fix deferred") is True
    assert ndvm_applies_for("unknown") is True
    assert ndvm_applies_for("Not affected") is False


def test_input_guardrails():
    # CVE id validation (trust boundary before any HTTP fetch)
    assert valid_cve("CVE-2023-3390") and valid_cve("cve-2024-12345")
    assert not valid_cve("old openssh") and not valid_cve("") and not valid_cve("CVE-23-1")
    # search filters: good inputs pass, malformed ones raise instead of firing a request
    assert search_params(package="kernel", severity="Important")["severity"] == "important"
    # cvss3: null must not crash
    null_cvss = analyze_cve_json({"name": "CVE-2024-1", "cvss3": None, "package_state": []})
    assert null_cvss["cvss3"] is None and null_cvss["fix_state"] in ("unknown", "Fixed")
    # major version hint must not latch onto a longer minor
    multi = {
        "name": "CVE-2024-2",
        "package_state": [
            {"product_name": "Red Hat Enterprise Linux 8.6", "fix_state": "Affected"},
            {"product_name": "Red Hat Enterprise Linux 8", "fix_state": "Fix deferred"},
        ],
    }
    assert analyze_cve_json(multi, "Enterprise Linux 8")["fix_state"] == "Fix deferred"
    assert search_params(advisory="RHSA-2024:2394")["advisory"] == "RHSA-2024:2394"
    for bad in (dict(severity="scary"), dict(advisory="RHSA-bogus"), dict(after="2024/01/01")):
        try:
            search_params(**bad)
            assert False, f"expected ValueError for {bad}"
        except ValueError:
            pass
    try:
        search_params()  # no filters
        assert False, "expected ValueError for no filters"
    except ValueError:
        pass


if __name__ == "__main__":
    test_fix_deferred_triggers_ndvm()
    test_fixed_reports_rhsa_and_nvra()
    test_not_affected_means_do_nothing()
    test_unknown_product_falls_back_to_worst_state()
    test_ndvm_trigger_rule()
    test_input_guardrails()
    print("ok")
