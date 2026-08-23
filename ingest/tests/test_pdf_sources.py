from fetch_pdfs import GUIDES, build
from ingest import PDF_SOURCES


def test_curated_pdf_filenames_map_to_canonical_red_hat_urls():
    for guide in GUIDES:
        url, filename = build(*guide)
        assert PDF_SOURCES[filename][0] == url
        assert url.startswith("https://docs.redhat.com/")


def test_pdf_platform_is_preserved_for_rhel_and_openshift_guides():
    assert PDF_SOURCES["Red_Hat_Enterprise_Linux-9-Security_hardening-en-US.pdf"][1] == "rhel"
    assert PDF_SOURCES["OpenShift_Container_Platform-4.18-Security_and_compliance-en-US.pdf"][1] == "openshift"
    assert PDF_SOURCES["Red_Hat_Ansible_Automation_Platform-2.5-Hardening_and_compliance-en-US.pdf"][1] == "other"
