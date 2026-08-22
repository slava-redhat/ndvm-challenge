#!/usr/bin/env python3
"""Download the Red Hat security PDFs most relevant to NDVM into data/pdfs/.

Data-driven: add a row to GUIDES and re-run. The docs.redhat.com PDF URL is fully
predictable, so we build it from (product, version, guide) and just verify each is a
real application/pdf before saving. Idempotent: existing files are skipped.

    python3 ingest/fetch_pdfs.py            # download the curated set
    python3 ingest/fetch_pdfs.py --dry-run  # print the URLs it would fetch
    python3 ingest/fetch_pdfs.py --selfcheck

Then:  make ingest
"""
import sys
from pathlib import Path

import requests

BASE = "https://docs.redhat.com/en/documentation/{product}/{version}/pdf/{guide}/{fname}"
DATA = Path(__file__).resolve().parent.parent / "data" / "pdfs"

# Curated for the challenge: how to mitigate WITHOUT patching/reboot.
# title = the product/guide title with spaces -> underscores (that's the filename casing).
# Only rows that return application/pdf today — probe before adding.
GUIDES = [
    # RHEL 9 — core non-disruptive levers
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9", "security_hardening", "Security_hardening"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9", "using_selinux", "Using_SELinux"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9",
     "configuring_firewalls_and_packet_filters", "Configuring_firewalls_and_packet_filters"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9",
     "managing_and_monitoring_security_updates", "Managing_and_monitoring_security_updates"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9",
     "managing_monitoring_and_updating_the_kernel", "Managing_monitoring_and_updating_the_kernel"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9", "securing_networks", "Securing_networks"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9",
     "configuring_authentication_and_authorization_in_rhel",
     "Configuring_authentication_and_authorization_in_RHEL"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9",
     "managing_software_with_the_dnf_tool", "Managing_software_with_the_DNF_tool"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9",
     "configuring_and_managing_networking", "Configuring_and_managing_networking"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9",
     "automating_system_administration_by_using_rhel_system_roles",
     "Automating_system_administration_by_using_RHEL_system_roles"),
    # IdM — access control as a compensating control
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9",
     "managing_idm_users_groups_hosts_and_access_control_rules",
     "Managing_IdM_users_groups_hosts_and_access_control_rules"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9",
     "using_ansible_to_install_and_manage_identity_management",
     "Using_Ansible_to_install_and_manage_Identity_Management"),
    # RHEL 8 — still the majority of customer estates in the demo accounts
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "8", "security_hardening", "Security_hardening"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "8", "using_selinux", "Using_SELinux"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "8",
     "configuring_and_managing_networking", "Configuring_and_managing_networking"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "8",
     "managing_monitoring_and_updating_the_kernel", "Managing_monitoring_and_updating_the_kernel"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "8",
     "managing_and_monitoring_security_updates", "Managing_and_monitoring_security_updates"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "8", "securing_networks", "Securing_networks"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "8",
     "configuring_authentication_and_authorization_in_rhel",
     "Configuring_authentication_and_authorization_in_RHEL"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "8",
     "automating_system_administration_by_using_rhel_system_roles",
     "Automating_system_administration_by_using_RHEL_system_roles"),
    # Insights — vulnerability service (detection → remediation path)
    ("red_hat_insights", "Red_Hat_Insights", "1-latest",
     "assessing_and_monitoring_security_vulnerabilities_on_rhel_systems",
     "Assessing_and_monitoring_security_vulnerabilities_on_RHEL_systems"),
    ("red_hat_insights", "Red_Hat_Insights", "1-latest",
     "generating_vulnerability_service_reports",
     "Generating_vulnerability_service_reports"),
    # Satellite — compliance / host hardening at estate scale
    ("red_hat_satellite", "Red_Hat_Satellite", "6.16",
     "managing_security_compliance", "Managing_Security_Compliance"),
    ("red_hat_satellite", "Red_Hat_Satellite", "6.16", "managing_hosts", "Managing_Hosts"),
    # OpenShift — NetworkPolicy / SCC / nodes / auth
    ("openshift_container_platform", "OpenShift_Container_Platform", "4.18",
     "security_and_compliance", "Security_and_compliance"),
    ("openshift_container_platform", "OpenShift_Container_Platform", "4.18",
     "authentication_and_authorization", "Authentication_and_authorization"),
    ("openshift_container_platform", "OpenShift_Container_Platform", "4.18", "nodes", "Nodes"),
    ("openshift_container_platform", "OpenShift_Container_Platform", "4.18",
     "backup_and_restore", "Backup_and_restore"),
    ("openshift_container_platform", "OpenShift_Container_Platform", "4.18",
     "networking_operators", "Networking_operators"),
    ("openshift_container_platform", "OpenShift_Container_Platform", "4.16",
     "security_and_compliance", "Security_and_compliance"),
    ("openshift_container_platform", "OpenShift_Container_Platform", "4.16",
     "networking", "Networking"),
    ("openshift_container_platform", "OpenShift_Container_Platform", "4.15",
     "networking", "Networking"),  # 4.18 networking guide is HTML-only; 4.15/4.16 have PDFs
    # ACS — runtime policy / admission-style compensating controls
    ("red_hat_advanced_cluster_security_for_kubernetes",
     "Red_Hat_Advanced_Cluster_Security_for_Kubernetes", "4.6", "operating", "Operating"),
    ("red_hat_advanced_cluster_security_for_kubernetes",
     "Red_Hat_Advanced_Cluster_Security_for_Kubernetes", "4.6", "configuring", "Configuring"),
    ("red_hat_advanced_cluster_security_for_kubernetes",
     "Red_Hat_Advanced_Cluster_Security_for_Kubernetes", "4.6", "integrating", "Integrating"),
    ("red_hat_advanced_cluster_security_for_kubernetes",
     "Red_Hat_Advanced_Cluster_Security_for_Kubernetes", "4.6", "roxctl_cli", "roxctl_CLI"),
    # Ansible Automation Platform — hardening & compliance
    ("red_hat_ansible_automation_platform", "Red_Hat_Ansible_Automation_Platform", "2.5",
     "hardening_and_compliance", "Hardening_and_compliance"),
    # OpenStack Platform — security & hardening (17.1 renamed the guide; 16.2 has the PDF)
    ("red_hat_openstack_platform", "Red_Hat_OpenStack_Platform", "16.2",
     "security_and_hardening_guide", "Security_and_Hardening_Guide"),
    # Ceph Storage — data security & hardening
    ("red_hat_ceph_storage", "Red_Hat_Ceph_Storage", "7",
     "data_security_and_hardening_guide", "Data_Security_and_Hardening_Guide"),
]


def build(product, ptitle, version, guide, gtitle):
    fname = f"{ptitle}-{version}-{gtitle}-en-US.pdf"
    return BASE.format(product=product, version=version, guide=guide, fname=fname), fname


def fetch(url, fname) -> str:
    dest = DATA / fname
    if dest.exists() and dest.stat().st_size > 0:
        return f"skip (exists)   {fname}"
    try:
        r = requests.get(url, timeout=120, stream=True)
    except requests.RequestException as e:
        return f"ERROR {e}   {fname}"
    ct = r.headers.get("content-type", "")
    if r.status_code != 200 or "application/pdf" not in ct:
        return f"MISS  HTTP {r.status_code} {ct or '?'}   {url}"
    tmp = dest.with_suffix(".part")
    size = 0
    with open(tmp, "wb") as f:
        for chunk in r.iter_content(1 << 16):
            f.write(chunk); size += len(chunk)
    tmp.rename(dest)  # atomic: no half-written .pdf ever seen by ingest
    return f"OK  {size/1e6:5.1f} MB   {fname}"


def main(argv):
    rows = [build(*g) for g in GUIDES]
    if "--dry-run" in argv:
        for url, _ in rows:
            print(url)
        return
    DATA.mkdir(parents=True, exist_ok=True)
    print(f"-> {DATA}")
    ok = 0
    for url, fname in rows:
        line = fetch(url, fname)
        print("  " + line)
        ok += line.startswith(("OK", "skip"))
    print(f"{ok}/{len(rows)} available. Next: make ingest")


def _selfcheck():
    url, fname = build(*GUIDES[0])
    expect = ("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/pdf/"
              "security_hardening/Red_Hat_Enterprise_Linux-9-Security_hardening-en-US.pdf")
    assert url == expect, url
    assert fname.endswith("-en-US.pdf")
    print("ok")


if __name__ == "__main__":
    _selfcheck() if "--selfcheck" in sys.argv else main(sys.argv[1:])
