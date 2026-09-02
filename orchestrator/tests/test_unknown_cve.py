"""Unknown CVE drop (Red Hat 404)."""
from harvest import select_cve
from tools import partition_redhat_cves, redhat_cve_exists, unknown_cve_message


def test_partition_drops_404_keeps_known():
    import tools
    real = tools.redhat_cve_exists
    tools.redhat_cve_exists = (
        lambda c: True if (c or "").upper() == "CVE-2023-3390" else False)
    try:
        keep, unknown = partition_redhat_cves(["CVE-2026-84715", "CVE-2023-3390"])
        assert keep == ["CVE-2023-3390"]
        assert unknown == ["CVE-2026-84715"]
    finally:
        tools.redhat_cve_exists = real


def test_select_cve_uses_filtered_named():
    msg = "CVE-2026-84715 and CVE-2023-3390 on RHEL 8"
    # After drop, only the known id remains → pin without which_cve.
    assert select_cve(msg, "", named=["CVE-2023-3390"]) == "CVE-2023-3390"
    assert select_cve(msg, "") is None  # unfiltered still multi


def test_unknown_message_names_cve():
    assert "CVE-2026-84715" in unknown_cve_message(["CVE-2026-84715"])
    assert "dropped" in unknown_cve_message(["CVE-A", "CVE-B"]).lower()


def test_exists_false_on_bad_id():
    assert redhat_cve_exists("not-a-cve") is False


if __name__ == "__main__":
    test_partition_drops_404_keeps_known()
    test_select_cve_uses_filtered_named()
    test_unknown_message_names_cve()
    test_exists_false_on_bad_id()
    print("ok")
