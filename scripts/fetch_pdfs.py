#!/usr/bin/env python3
"""Download the Red Hat security PDFs most relevant to NDVM into data/pdfs/.

Data-driven: add a row to GUIDES and re-run. The docs.redhat.com PDF URL is fully
predictable, so we build it from (product, version, guide) and just verify each is a
real application/pdf before saving. Idempotent: existing files are skipped.

    python3 scripts/fetch_pdfs.py            # download the curated set
    python3 scripts/fetch_pdfs.py --dry-run  # print the URLs it would fetch
    python3 scripts/fetch_pdfs.py --selfcheck

Then:  make ingest
"""
import sys
from pathlib import Path

import requests

BASE = "https://docs.redhat.com/en/documentation/{product}/{version}/pdf/{guide}/{fname}"
DATA = Path(__file__).resolve().parent.parent / "data" / "pdfs"

# Curated for the challenge: how to mitigate WITHOUT patching/reboot.
# title = the product/guide title with spaces -> underscores (that's the filename casing).
GUIDES = [
    # RHEL — the core non-disruptive levers (live patch, SELinux, firewall, update mgmt)
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9", "security_hardening", "Security_hardening"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9", "using_selinux", "Using_SELinux"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9",
     "configuring_firewalls_and_packet_filters", "Configuring_firewalls_and_packet_filters"),
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9",
     "managing_and_monitoring_security_updates", "Managing_and_monitoring_security_updates"),
    # RHEL kernel: kpatch / live patching = reboot-free kernel CVE mitigation
    ("red_hat_enterprise_linux", "Red_Hat_Enterprise_Linux", "9",
     "managing_monitoring_and_updating_the_kernel", "Managing_monitoring_and_updating_the_kernel"),
    # OpenShift — compensating controls (NetworkPolicy, SCC, admission, node hardening)
    ("openshift_container_platform", "OpenShift_Container_Platform", "4.18",
     "security_and_compliance", "Security_and_compliance"),
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
