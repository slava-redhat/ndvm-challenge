"""Relevance guard: a discovered CVE must concern the software the user named.

Reproduces the real bug — asking about 'openssh' surfaced CVE-2026-4631, which is a
*cockpit* RCE ('SSH command-line argument injection') matched only on the word 'SSH'.
Tests the pure token logic (no network); package sets are what Red Hat data returns.
"""


def test_mismatch_is_rejected():
    import crew
    # openssh question, cockpit CVE packages -> not relevant
    assert crew._pkg_relevant(
        {"cockpit"}, "I have issues with my openssh on centos 9") is False


def test_match_is_accepted():
    import crew
    assert crew._pkg_relevant(
        {"openssh", "openssh-server"}, "old OpenSSH on our RHEL 8 web tier") is True


def test_open_ended_is_allowed():
    import crew
    # No specific software named -> discovery is legitimately open, don't block.
    assert crew._pkg_relevant({"cockpit"}, "what should I worry about on RHEL 9") is True


def test_unverifiable_is_allowed():
    import crew
    # CVE packages unknown (empty) -> never block on missing Red Hat data.
    assert crew._pkg_relevant(set(), "issues with my openssh") is True


def test_named_software_strips_platform_and_generic_words():
    import crew
    named = crew._named_software("I have issues with my openssh on centos 9")
    assert named == {"openssh"}


if __name__ == "__main__":
    test_mismatch_is_rejected()
    test_match_is_accepted()
    test_open_ended_is_allowed()
    test_unverifiable_is_allowed()
    test_named_software_strips_platform_and_generic_words()
    print("ok")
