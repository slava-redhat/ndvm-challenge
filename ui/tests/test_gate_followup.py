"""Keep the conditional Other detail field interactive before submission."""
from pathlib import Path


def test_other_detail_is_not_inside_a_streamlit_form() -> None:
    source = Path(__file__).resolve().parents[1].joinpath("app.py").read_text()
    start = source.index("if pending:")
    end = source.index("# Phase 1 — fresh submission.", start)
    followup = source[start:end]

    assert 'with st.form("clarify"):' not in followup
    assert 'with st.container(border=True):' in followup
    assert 'st.button("Submit answers →", type="primary", key="clarify_submit")' in followup


def test_pending_gate_pins_and_displays_its_cve() -> None:
    source = Path(__file__).resolve().parents[1].joinpath("app.py").read_text()

    assert 'pending_cve = pending.get("cve") or "this CVE"' in source
    assert 'Answering follow-up questions for **{pending_cve}**' in source
    assert 'st.button("Start a new question", key="cancel_pending"' in source
    assert 'disabled=bool(pending)' in source
    assert '"cve": (data.get("intake") or {}).get("cve", "")' in source


if __name__ == "__main__":
    test_other_detail_is_not_inside_a_streamlit_form()
    test_pending_gate_pins_and_displays_its_cve()
    print("ok")
