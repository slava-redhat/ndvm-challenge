"""Guard against sufficiency-gate '2026 is a future year' questions."""


def test_drop_cve_year_doubt_questions():
    import crew
    from models import ClarifyQuestion, Sufficiency

    bad = ClarifyQuestion(
        key="cve_verify",
        question="The CVE number shows 2026 (future year). Can you verify the correct CVE identifier?",
        options=["CVE-2024-31431", "CVE-2025-31431", "Keep CVE-2026-31431"],
    )
    ok = ClarifyQuestion(
        key="exposure",
        question="How is the affected host exposed?",
        options=["internet-facing", "internal", "air-gapped"],
    )
    gate = Sufficiency(sufficient=False, missing=["exposure"], questions=[bad, ok])
    out = crew._drop_cve_year_doubt_questions(gate, "CVE-2026-31431")
    assert len(out.questions) == 1 and out.questions[0].key == "exposure"

    only_bad = Sufficiency(sufficient=False, questions=[bad])
    cleared = crew._drop_cve_year_doubt_questions(only_bad, "CVE-2026-31431")
    assert cleared.sufficient and not cleared.questions


def test_cve_year_context_uses_today():
    import crew
    from datetime import date
    ctx = crew._cve_year_context()
    assert str(date.today().year) in ctx
    assert "not 'future'" in ctx


if __name__ == "__main__":
    test_cve_year_context_uses_today()
    test_drop_cve_year_doubt_questions()
    print("ok")
