"""Offline checks for the CVE search helpers (no network, no crewai)."""
from cve_parse import search_params, slim_rows


def test_params_drops_empties_and_requires_one():
    p = search_params(package="openssl", product="", severity="important")
    assert p == {"per_page": 10, "package": "openssl", "severity": "important"}, p
    try:
        search_params()  # no filters -> must raise
        raise AssertionError("expected ValueError when no filter given")
    except ValueError:
        pass


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


if __name__ == "__main__":
    test_params_drops_empties_and_requires_one()
    test_slim_maps_fields_and_caps_packages()
    print("ok")
