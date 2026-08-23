"""Offline checks for the CVE search helpers (no network, no crewai)."""
from cve_parse import (cache_fields_from_slim, cache_search_filters, search_params,
                       slim_rows)


def test_params_drops_empties_and_requires_one():
    p = search_params(package="openssl", product="", severity="important")
    assert p == {"per_page": 10, "package": "openssl", "severity": "important"}, p
    try:
        search_params()  # no filters -> must raise
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError when no filter given")


def test_slim_maps_fields_and_caps_packages():
    row = {"CVE": "CVE-2023-3390", "severity": "important",
           "public_date": "2023-01-01T00:00:00Z", "cvss3_score": "7.8",
           "advisories": ["RHSA-2023:1"], "bugzilla_description": "kernel: ...",
           "affected_packages": [f"pkg{i}" for i in range(9)],
           "resource_url": "https://example/cve.json"}
    slim = slim_rows([row])[0]
    assert slim["cve"] == "CVE-2023-3390"
    assert slim["cvss3"] == "7.8"
    assert len(slim["affected_packages"]) == 5  # capped
    assert slim["url"].endswith("cve.json")


def test_cache_fields_folds_packages_into_summary():
    fields = cache_fields_from_slim({
        "cve": "cve-2023-3390", "severity": "Important", "cvss3": "7.8",
        "summary": "nftables bypass", "affected_packages": ["kernel", "kernel-rt"],
        "url": "https://access.redhat.com/security/cve/CVE-2023-3390",
    })
    assert fields["cve_id"] == "CVE-2023-3390"
    assert fields["cvss3"] == 7.8
    assert "kernel" in fields["summary"] and "nftables" in fields["summary"]
    assert cache_fields_from_slim({"cve": "", "summary": "x"}) is None


def test_cache_search_filters_offline_rules():
    assert cache_search_filters(advisory="RHSA-2024:2394") is None
    assert cache_search_filters(after="2024-01-01") is None  # after-only
    clauses, params = cache_search_filters(package="kernel", severity="important")
    assert "threat_severity" in clauses[0]
    assert params[0] == "important"
    assert "kernel" in params[1]


if __name__ == "__main__":
    test_params_drops_empties_and_requires_one()
    test_slim_maps_fields_and_caps_packages()
    test_cache_fields_folds_packages_into_summary()
    test_cache_search_filters_offline_rules()
    print("ok")
