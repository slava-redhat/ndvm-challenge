"""Harvest + gate sanitize + CVE queue (no LLM)."""
from harvest import (harvest_answers, merge_answers, remaining_cves,
                     which_cve_answer_line)
from models import ClarifyQuestion, Sufficiency
from crew import _sanitize_gate_questions


def test_harvest_freeze_and_selinux():
    msg = ("CVE-2023-3390 and CVE-2024-6387 on RHEL 8 — can't reboot this quarter. "
           "We have SELinux enforcing. What can I do now?")
    harvested = harvest_answers(msg)
    assert "[maintenance_window]" in harvested
    assert "No reboot" in harvested
    assert "[existing_controls]" in harvested
    assert "SELinux" in harvested


def test_merge_keeps_first_key():
    a = "[exposure] Network exposure: Internet-facing"
    b = "[exposure] Network exposure: Internal only\n[backup_dr] Backup / DR readiness: No safe alternate capacity"
    merged = merge_answers(a, b)
    assert "Internet-facing" in merged
    assert "Internal only" not in merged
    assert "[backup_dr]" in merged


def test_remaining_cves_drops_chosen():
    msg = "see CVE-2023-3390 and CVE-2024-6387 please"
    assert remaining_cves(msg, "CVE-2023-3390") == ["CVE-2024-6387"]
    assert remaining_cves(msg, "") == ["CVE-2023-3390", "CVE-2024-6387"]


def test_sanitize_drops_harvested_keys():
    gate = Sufficiency(
        sufficient=False,
        questions=[
            ClarifyQuestion(key="maintenance_window",
                            question="When can you reboot?",
                            options=["This week", "Not this quarter", "Other (describe)"]),
            ClarifyQuestion(key="existing_controls",
                            question="Which controls are in place?",
                            options=["SELinux enforcing", "Other (describe)"], multi=True),
            ClarifyQuestion(key="backup_dr",
                            question="Is DR ready?",
                            options=["Yes", "No", "Other (describe)"]),
        ],
    )
    answers = harvest_answers(
        "can't reboot this quarter; SELinux enforcing on the fleet")
    sanitized = _sanitize_gate_questions(gate, "CVE-2023-3390", answers)
    keys = [q.key for q in sanitized.questions]
    assert "maintenance_window" not in keys
    assert "existing_controls" not in keys
    assert keys == ["backup_dr"]


def test_which_cve_answer_line_pins_pick():
    line = which_cve_answer_line("cve-2024-6387")
    assert line.startswith("[which_cve]")
    assert "CVE-2024-6387" in line
    # Same matching rule as run_gate: CVE must appear in answer values after ':'
    answer_vals = " ".join(
        ln.split(":", 1)[-1] for ln in line.splitlines() if ":" in ln
    ).upper()
    assert "CVE-2024-6387" in answer_vals


def test_harvest_common_controls():
    msg = ("OpenShift app is VPN-only; we run NetworkPolicy default-deny, RHACS admission, "
           "and kpatch on the workers. Insights is connected. Daily Velero backups.")
    h = harvest_answers(msg)
    assert "NetworkPolicy" in h
    assert "ACS" in h or "Admission" in h
    assert "kpatch" in h.lower() or "live patch" in h.lower()
    assert "Insights" in h
    assert "[exposure]" in h and ("VPN" in h or "Internal" in h or "private" in h.lower()
                                   or "bastion" in h.lower())
    assert "[backup_dr]" in h
    h2 = harvest_answers("auditd, crypto-policies, egress proxy, private subnet")
    assert "Audit" in h2 and "Crypto" in h2 and "egress" in h2.lower()
    assert "[exposure]" in h2


if __name__ == "__main__":
    test_harvest_freeze_and_selinux()
    test_merge_keeps_first_key()
    test_remaining_cves_drops_chosen()
    test_sanitize_drops_harvested_keys()
    test_which_cve_answer_line_pins_pick()
    test_harvest_common_controls()
    print("ok")
