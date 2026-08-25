"""Multi-CVE gate disambiguation (no LLM)."""
from models import ClarifyQuestion, Intake, NOT_SURE_OPTION, OTHER_OPTION, Sufficiency
from crew import _esc, _normalize_gate_questions, _sanitize_gate_questions, run_gate


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


def test_gate_questions_use_other_instead_of_a_free_text_question():
    gate = Sufficiency(
        sufficient=False,
        questions=[
            ClarifyQuestion(key="controls", question="Which controls are in place?",
                            options=["SELinux enforcing", "Network segmentation"], multi=True),
            ClarifyQuestion(key="restore", question="Can you restore elsewhere?",
                            options=[], multi=False),
        ],
    )
    normalized = _normalize_gate_questions(gate)

    assert normalized.questions[0].options[-1] == OTHER_OPTION
    assert normalized.questions[1].options == [NOT_SURE_OPTION, OTHER_OPTION]
    assert all(question.options for question in normalized.questions)


def test_gate_filters_detection_questions_and_already_answered_keys():
    gate = Sufficiency(
        sufficient=False,
        questions=[
            ClarifyQuestion(key="detection", question="Which scanner detected this CVE?",
                            options=["Insights", "Other (describe)"]),
            ClarifyQuestion(key="controls", question="Which controls are already in place?",
                            options=["SELinux enforcing", "Other (describe)"], multi=True),
            ClarifyQuestion(key="dr_ready", question="Is a tested DR site ready?",
                            options=["Yes", "No", "Other (describe)"]),
        ],
    )
    sanitized = _sanitize_gate_questions(
        gate, "CVE-2024-6387",
        "[controls] Which controls are already in place?: Not sure",
    )

    assert [question.key for question in sanitized.questions] == ["dr_ready"]
    assert sanitized.questions[0].multi is False


def test_gate_caps_questions_and_preserves_braces_for_the_llm():
    gate = Sufficiency(
        sufficient=False,
        questions=[
            ClarifyQuestion(key=f"q{i}", question=f"Question {i}", options=["Yes", "No"])
            for i in range(6)
        ],
    )
    normalized = _normalize_gate_questions(gate)

    assert [question.key for question in normalized.questions] == ["q0", "q1", "q2", "q3"]
    assert all(question.options[-1] == OTHER_OPTION for question in normalized.questions)
    assert _esc("kernel-{debug}") == r"kernel-\u007bdebug\u007d"


if __name__ == "__main__":
    test_two_cves_force_which_pick()
    test_two_cves_answer_pins_intake()
    test_gate_questions_use_other_instead_of_a_free_text_question()
    test_gate_filters_detection_questions_and_already_answered_keys()
    test_gate_caps_questions_and_preserves_braces_for_the_llm()
    print("ok")
