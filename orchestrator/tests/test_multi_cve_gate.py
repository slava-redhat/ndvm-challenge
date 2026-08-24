"""Multi-CVE gate disambiguation (no LLM)."""
from models import Intake
from crew import run_gate


def test_two_cves_force_which_pick():
    intake = Intake(persona="primary", platform="rhel", cve="CVE-2023-3390")
    gate = run_gate(
        "CVE-2023-3390 and CVE-2024-6387 on my RHEL 9 fleet, cannot reboot",
        intake, answers="")
    assert gate.sufficient is False
    assert gate.questions[0].key == "which_cve"
    assert gate.questions[0].options == ["CVE-2023-3390", "CVE-2024-6387"]
    assert gate.questions[0].multi is False


def test_two_cves_answer_pins_intake():
    from cve_parse import find_cves
    msg = "CVE-2023-3390 and CVE-2024-6387"
    named = find_cves(msg)
    answers = (
        "You named more than one CVE — which should we analyze first?: CVE-2024-6387"
    )
    answer_vals = " ".join(
        line.split(":", 1)[-1] for line in answers.splitlines() if ":" in line
    ).upper()
    picked = next((c for c in named if c in answer_vals), "")
    assert picked == "CVE-2024-6387"


if __name__ == "__main__":
    test_two_cves_force_which_pick()
    test_two_cves_answer_pins_intake()
    print("ok")
