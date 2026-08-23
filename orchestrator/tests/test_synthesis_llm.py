"""Regression coverage for structured briefing completion length."""
from crew import _synth_agent


def test_synthesizer_has_a_completion_budget():
    """The final AdviceResult is large enough to exceed provider defaults."""
    assert (_synth_agent("secondary").llm.max_tokens or 0) >= 8192


if __name__ == "__main__":
    test_synthesizer_has_a_completion_budget()
    print("ok")
