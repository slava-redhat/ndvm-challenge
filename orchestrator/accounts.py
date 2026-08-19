"""Synthetic Red Hat Insights-style account store — the TAM's view of a customer.

A Red Hat TAM does not ask the customer to describe their estate; they look it up
in Red Hat Insights (Inventory + Vulnerability + Compliance). The JSON files under
data/accounts/ are the synthetic stand-in. This module loads them, matches a company
by name/org, and renders the estate as the SAME 'answers' text the questionnaire
produces — so the rest of the flow grounds on real account facts with no new wiring.
"""
import glob
import json
import os

DATA_DIR = os.environ.get("NDVM_DATA_DIR", "/app/data")
ACCOUNTS_DIR = os.path.join(DATA_DIR, "accounts")


def _load_all() -> list[dict]:
    out = []
    for path in sorted(glob.glob(os.path.join(ACCOUNTS_DIR, "*.json"))):
        try:
            with open(path) as f:
                out.append(json.load(f))
        except (OSError, ValueError):
            continue  # ponytail: skip a malformed account file rather than 500 the app
    return out


def list_accounts() -> list[dict]:
    """[{org_id, account_name, industry}] for the UI dropdown and the router."""
    return [{"org_id": a["account"]["org_id"],
             "account_name": a["account"]["account_name"],
             "industry": a["account"].get("industry", "")}
            for a in _load_all()]


def load_account(name_or_org: str) -> dict | None:
    """Match by exact org_id, else case-insensitive substring of the account name."""
    key = (name_or_org or "").strip().lower()
    if not key:
        return None
    accounts = _load_all()
    for a in accounts:
        if key == str(a["account"].get("org_id", "")).lower():
            return a
    for a in accounts:
        if key in a["account"]["account_name"].lower():
            return a
    return None


def detect_account(message: str) -> dict | None:
    """Return the account whose company name appears in the message, else None.
    Auto-detect uses this: naming a known customer account is a TAM signal."""
    low = (message or "").lower()
    for a in _load_all():
        name = a["account"]["account_name"]
        first = name.split()[0].lower()  # natural phrasing: 'Meridian is affected...'
        if name.lower() in low or (len(first) > 4 and first in low):
            return a
    return None


def cve_view(account: dict, cve: str) -> dict | None:
    """What the Insights Vulnerability service shows for this CVE on this account."""
    vuln = (account.get("insights_vulnerability") or {}).get((cve or "").strip().upper())
    if not vuln:
        return None
    return {
        "cve": (cve or "").strip().upper(),
        "severity": vuln.get("severity"),
        "red_hat_fix_state": vuln.get("red_hat_fix_state"),
        "known_exploited": vuln.get("known_exploited", False),
        "affected": vuln.get("affected_systems", []),
        "not_affected": vuln.get("systems_not_affected", []),
        "remediation_playbook": vuln.get("remediation_playbook"),
    }


def default_cve(account: dict) -> str:
    """When the TAM names an account but no CVE: prefer a known-exploited affected CVE."""
    best = ""
    for cve, v in (account.get("insights_vulnerability") or {}).items():
        if not v.get("affected_systems"):
            continue
        if v.get("known_exploited"):
            return cve
        best = best or cve
    return best


def account_view(account: dict, cve: str) -> dict:
    """Compact block the UI renders above the advice."""
    acc = account["account"]
    return {
        "org_id": acc["org_id"],
        "account_name": acc["account_name"],
        "industry": acc.get("industry", ""),
        "assigned_tam": acc.get("assigned_tam", ""),
        "estate_size": len(account.get("systems", [])),
        "maintenance": account.get("maintenance_policy", {}),
        "cve": cve_view(account, cve),
    }


def estate_as_answers(account: dict, cve: str) -> str:
    """Render the account estate as the questionnaire's 'answers' text, so the gate is
    satisfied and the profiler/validator ground on real facts instead of guessing."""
    acc = account["account"]
    lines = [f"Customer account: {acc['account_name']} (org {acc['org_id']}), "
             f"{acc.get('industry', '')}."]
    mp = account.get("maintenance_policy", {})
    if mp:
        lines.append(f"Maintenance window: {mp.get('next_reboot_window', '?')} "
                     f"(~{mp.get('weeks_until_window', '?')} weeks); "
                     f"{mp.get('change_freeze', '')}.")
    cv = cve_view(account, cve)
    aff_names = set()
    if cv:
        lines.append(f"Detection: Red Hat Insights Vulnerability. {cv['cve']} "
                     f"({cv.get('severity')}, fix_state {cv.get('red_hat_fix_state')}, "
                     f"known_exploited={cv.get('known_exploited')}).")
        if cv["affected"]:
            aff_names = {h["hostname"] for h in cv["affected"]}
            lines.append("Affected systems: " + "; ".join(
                f"{h['hostname']} [{h.get('status')}, "
                f"{'internet-facing' if h.get('public_exposure') else 'internal'}]"
                for h in cv["affected"]))
        if cv["not_affected"]:
            lines.append("Not affected: " + "; ".join(h["hostname"] for h in cv["not_affected"]))
        if cv.get("remediation_playbook"):
            lines.append(f"Insights remediation available: {cv['remediation_playbook']}.")
    # Aggregate controls/exposure/backups from the affected hosts (or all, if none pinned).
    controls, exposure, backups = set(), set(), set()
    for s in account.get("systems", []):
        if aff_names and s["hostname"] not in aff_names:
            continue
        c = s.get("controls", {})
        if c.get("selinux"):
            controls.add(f"SELinux {c['selinux']}")
        if c.get("firewalld"):
            controls.add("firewalld active")
        if c.get("fips_mode"):
            controls.add("FIPS mode")
        if c.get("idm_enrolled"):
            controls.add("IdM enrolled")
        exposure.add("internet-facing" if s.get("public_exposure") else "internal")
        b = s.get("backup", {})
        if b:
            backups.add(f"{b.get('type', '?')} ({b.get('frequency', '?')})"
                        + (", DR-replicated" if b.get("dr_replicated") else ""))
    if controls:
        lines.append("Controls in place: " + ", ".join(sorted(controls)) + ".")
    if exposure:
        lines.append("Exposure: " + ", ".join(sorted(exposure)) + ".")
    if backups:
        lines.append("Backups/DR: " + "; ".join(sorted(backups)) + ".")
    return "\n".join(lines)


if __name__ == "__main__":  # self-check against the shipped demo accounts
    accs = list_accounts()
    assert accs, "no account files found"
    a = load_account("meridian")
    assert a and "Meridian" in a["account"]["account_name"]
    assert detect_account("Is Meridian affected by CVE-2023-3390?") is not None
    assert detect_account("just a random question") is None
    cv = cve_view(a, "CVE-2023-3390")
    assert cv and cv["affected"], "expected affected hosts"
    ans = estate_as_answers(a, "CVE-2023-3390")
    assert "Meridian" in ans and "internet-facing" in ans
    print("ok:", [x["account_name"] for x in accs])
