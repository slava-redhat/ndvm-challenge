"""Regression coverage for fail-closed mitigation retrieval."""

import crew
from models import Intake, MitigationOption, VulnFinding


def test_empty_rag_does_not_invoke_llms_or_emit_options(monkeypatch):
    intake = Intake(
        persona="secondary",
        platform="rhel",
        product="Red Hat Enterprise Linux 9",
        cve="CVE-2024-6387",
        constraint="cannot reboot during business hours",
    )
    monkeypatch.setattr(
        crew,
        "assess",
        lambda *_args, **_kwargs: {"tier": "prioritize", "in_kev": False, "epss": 0.1},
    )
    monkeypatch.setattr(crew, "apply_ssvc_context", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(crew, "rag_search_hybrid", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        crew,
        "lookup_vuln_finding",
        lambda *_args, **_kwargs: VulnFinding(cve_id="CVE-2024-6387"),
    )
    monkeypatch.setattr(
        crew,
        "_analysis_agents",
        lambda: (_ for _ in ()).throw(AssertionError("LLMs must not run without RAG")),
    )

    result = crew.run_advice(intake, "secondary")

    assert result["knowledge_base_unavailable"] is True
    assert "No verified mitigation guidance" in result["message"]


def test_model_citations_are_replaced_with_retrieved_sources():
    option = MitigationOption(
        title="Restrict SSH",
        action_type="network",
        description="Block untrusted access.",
        disruption="low",
        effectiveness=3,
        effort=1,
        source_urls=["https://invented.example/guide"],
    )

    crew._bind_retrieved_sources([option], {"https://docs.redhat.com/guide"})

    assert option.source_urls == ["https://docs.redhat.com/guide"]


def test_filter_rag_hits_rejects_other_cve_pages():
    from cve_parse import filter_rag_hits_for_cve

    hits = [
        {"text": "CVE-2023-44487 (Important). HTTP/2 Rapid Reset",
         "source_url": "https://access.redhat.com/security/cve/CVE-2023-44487"},
        {"text": "Apply kpatch for kernel live patching without reboot",
         "source_url": "https://docs.redhat.com/kpatch"},
        {"text": "CVE-2026-31431 livepatch guidance",
         "source_url": "https://access.redhat.com/security/cve/CVE-2026-31431"},
    ]
    kept = filter_rag_hits_for_cve(hits, "CVE-2026-31431")
    assert [h["source_url"] for h in kept] == [
        "https://docs.redhat.com/kpatch",
        "https://access.redhat.com/security/cve/CVE-2026-31431",
    ]


if __name__ == "__main__":
    test_filter_rag_hits_rejects_other_cve_pages()
    test_model_citations_are_replaced_with_retrieved_sources()
    print("ok")
