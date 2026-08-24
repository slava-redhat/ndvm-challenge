"""Correctness tests for deterministic catalog options (not just retrieval recall)."""

import catalog
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
        crew, "assess",
        lambda *_a, **_k: {"tier": "prioritize", "in_kev": False, "epss": 0.1},
    )
    monkeypatch.setattr(crew, "apply_ssvc_context", lambda *_a, **_k: None)
    monkeypatch.setattr(crew, "rag_search_hybrid", lambda *_a, **_k: [])
    monkeypatch.setattr(
        crew, "lookup_vuln_finding",
        lambda *_a, **_k: VulnFinding(cve_id="CVE-2024-6387", fix_state="Affected",
                                      rationale="openssh"),
    )
    monkeypatch.setattr(
        crew, "_analysis_agents",
        lambda: (_ for _ in ()).throw(AssertionError("LLMs must not run without catalog")),
    )
    result = crew.run_advice(intake, "secondary")
    assert result["knowledge_base_unavailable"] is True


def test_pdf_only_hits_fail_closed(monkeypatch):
    intake = Intake(
        persona="secondary", platform="rhel", product="RHEL 9",
        cve="CVE-2026-31431", constraint="cannot reboot",
    )
    monkeypatch.setattr(
        crew, "assess",
        lambda *_a, **_k: {"tier": "prioritize", "in_kev": False, "epss": 0.1},
    )
    monkeypatch.setattr(crew, "apply_ssvc_context", lambda *_a, **_k: None)

    def fake_rag(query, platform=None, k=6, pool=20, doc_types=None):
        if doc_types == ("pdf",):
            return [{
                "text": "Generic hardening prose from a PDF.",
                "source_url": "https://docs.redhat.com/pdf/hardening.pdf",
                "metadata": {"doc_type": "pdf", "platform": "rhel"},
            }]
        return []  # no mitigation catalog hits

    monkeypatch.setattr(crew, "rag_search_hybrid", fake_rag)
    monkeypatch.setattr(
        crew, "lookup_vuln_finding",
        lambda *_a, **_k: VulnFinding(cve_id="CVE-2026-31431", fix_state="Affected"),
    )
    monkeypatch.setattr(
        crew, "_analysis_agents",
        lambda: (_ for _ in ()).throw(AssertionError("LLMs must not run without catalog")),
    )
    result = crew.run_advice(intake, "secondary")
    assert result["knowledge_base_unavailable"] is True


def test_prefer_mitigation_hits_drops_pdfs():
    from cve_parse import prefer_mitigation_hits
    hits = [
        {"text": "pdf", "metadata": {"doc_type": "pdf"}},
        {"text": "kpatch", "metadata": {"doc_type": "mitigation", "catalog_id": "rhel_kpatch"},
         "source_url": "https://access.redhat.com/solutions/2206511"},
    ]
    kept = prefer_mitigation_hits(hits)
    assert len(kept) == 1 and kept[0]["metadata"]["catalog_id"] == "rhel_kpatch"


def test_invented_option_dropped_and_catalog_url_wins():
    cat = [
        MitigationOption(
            catalog_id="rhel_kpatch", title="Apply a kernel live patch (kpatch)",
            action_type="livepatch", description="kpatch", disruption="none",
            effectiveness=3, effort=2,
            source_urls=["https://access.redhat.com/solutions/2206511"],
            steps=["dnf install kpatch kpatch-dnf"],
        )
    ]
    llm = [
        MitigationOption(
            catalog_id="invented_opt", title="Magic fix", action_type="config",
            description="invented", disruption="none", effectiveness=4, effort=1,
            source_urls=["https://evil.example/fix"],
        ),
        MitigationOption(
            catalog_id="rhel_kpatch", title="Wrong title from LLM", action_type="x",
            description="wrong", disruption="high", effectiveness=1, effort=1,
            source_urls=["https://invented.example/yum"],
            steps=["kpatch list"],
        ),
    ]
    out = catalog.pin_options_to_catalog(llm, cat)
    assert len(out) == 1
    assert out[0].catalog_id == "rhel_kpatch"
    assert out[0].title == "Apply a kernel live patch (kpatch)"
    assert out[0].source_urls == ["https://access.redhat.com/solutions/2206511"]
    assert "evil" not in str(out[0].source_urls)
    assert out[0].steps == ["dnf install kpatch kpatch-dnf"]  # catalog owns steps


def test_unmatched_citation_never_preserved():
    cat = [
        MitigationOption(
            catalog_id="rhel_firewalld", title="Restrict exposure with firewalld",
            action_type="network", description="fw", disruption="low",
            effectiveness=3, effort=1,
            source_urls=["https://access.redhat.com/solutions/962473"],
        )
    ]
    llm = [
        MitigationOption(
            catalog_id="", title="Restrict exposure with firewalld",
            action_type="network", description="fw", disruption="low",
            effectiveness=3, effort=1,
            source_urls=["https://access.redhat.com/solutions/962473"],
        )
    ]
    out = catalog.pin_options_to_catalog(llm, cat)
    # no catalog_id → dropped; fallback to catalog records
    assert out[0].catalog_id == "rhel_firewalld"
    assert out[0].source_urls == ["https://access.redhat.com/solutions/962473"]


def test_wrong_component_kpatch_excluded_for_openssh():
    hit = {
        "source_url": "https://access.redhat.com/solutions/2206511",
        "text": "kpatch",
        "metadata": {
            "catalog_id": "rhel_kpatch", "title": "Apply kpatch",
            "action_type": "livepatch", "disruption": "none",
            "effectiveness": 3, "effort": 2, "components": ["kernel"],
            "requires": ["livepatch"], "description": "live patch",
        },
    }
    openssh = VulnFinding(cve_id="CVE-2024-6387", fix_state="Affected",
                          fixed_nvra="openssh-8.0p1", rationale="OpenSSH server")
    assert catalog.filter_applicable_hits([hit], openssh) == []
    kernel = VulnFinding(cve_id="CVE-2023-3390", fix_state="Affected",
                         rationale="kernel privilege escalation")
    assert len(catalog.filter_applicable_hits([hit], kernel)) == 1


def test_service_restart_excludes_kernel_cve():
    hit = {
        "source_url": "https://access.redhat.com/security/vulnerabilities/",
        "text": "restart",
        "metadata": {
            "catalog_id": "rhel_service_restart", "title": "Restart service",
            "action_type": "config", "disruption": "low",
            "effectiveness": 4, "effort": 2, "scope": "generic",
            "exclude_components": ["kernel"], "fix_states": ["Fixed", "Affected"],
            "description": "dnf + restart",
        },
    }
    kernel = VulnFinding(cve_id="CVE-2023-3390", fix_state="Affected",
                         rationale="kernel flaw")
    assert catalog.filter_applicable_hits([hit], kernel) == []
    openssh = VulnFinding(cve_id="CVE-2024-6387", fix_state="Affected",
                          fixed_nvra="openssh-8.0p1", rationale="OpenSSH")
    assert len(catalog.filter_applicable_hits([hit], openssh)) == 1


def test_empty_components_without_scope_rejected():
    hit = {
        "source_url": "https://access.redhat.com/solutions/962473",
        "text": "firewall",
        "metadata": {
            "catalog_id": "rhel_firewalld", "title": "firewalld",
            "action_type": "network", "disruption": "low",
            "effectiveness": 3, "effort": 1, "components": [],
            "description": "fw",
        },
    }
    pinned = VulnFinding(cve_id="CVE-1", fix_state="Affected", rationale="openssh")
    assert catalog.filter_applicable_hits([hit], pinned) == []
    hit["metadata"]["scope"] = "generic"
    assert len(catalog.filter_applicable_hits([hit], pinned)) == 1


def test_openshift_component_inferred_from_platform():
    hit = {
        "source_url": "https://access.redhat.com/solutions/5243301",
        "text": "scc",
        "metadata": {
            "catalog_id": "ocp_scc", "title": "Tighten SCC",
            "action_type": "config", "disruption": "low",
            "effectiveness": 3, "effort": 2, "components": ["openshift"],
            "description": "restrict SCC",
        },
    }
    pinned = VulnFinding(cve_id="CVE-1", fix_state="Affected", rationale="container")
    assert catalog.filter_applicable_hits([hit], pinned, platform="rhel") == []
    assert len(catalog.filter_applicable_hits(
        [hit], pinned, platform="openshift")) == 1
    # Catalog rows use scope=generic for platform compensating controls.
    hit["metadata"].pop("components")
    hit["metadata"]["scope"] = "generic"
    assert len(catalog.filter_applicable_hits([hit], pinned, platform="rhel")) == 1


def test_catalog_versus_pdf_retrieval_roles():
    """Catalog hits become options; PDF hits never materialize as catalog options."""
    mit = {
        "source_url": "https://access.redhat.com/solutions/2206511",
        "text": "kpatch",
        "metadata": {
            "doc_type": "mitigation", "catalog_id": "rhel_kpatch",
            "title": "Apply kpatch", "action_type": "livepatch",
            "disruption": "none", "effectiveness": 3, "effort": 2,
            "components": ["kernel"], "requires": ["livepatch"],
            "description": "live patch",
        },
    }
    pdf = {
        "source_url": "https://docs.redhat.com/en/documentation/x.pdf",
        "text": "SELinux hardening chapter",
        "metadata": {"doc_type": "pdf", "platform": "rhel"},
    }
    from cve_parse import prefer_mitigation_hits
    only_mit = prefer_mitigation_hits([mit, pdf])
    assert len(only_mit) == 1
    kernel = VulnFinding(cve_id="CVE-1", fix_state="Affected", rationale="kernel")
    opts = catalog.materialize_options(
        catalog.filter_applicable_hits(only_mit, kernel))
    assert [o.catalog_id for o in opts] == ["rhel_kpatch"]
    assert catalog.materialize_options([pdf]) == []


if __name__ == "__main__":
    test_prefer_mitigation_hits_drops_pdfs()
    test_invented_option_dropped_and_catalog_url_wins()
    test_unmatched_citation_never_preserved()
    test_wrong_component_kpatch_excluded_for_openssh()
    test_service_restart_excludes_kernel_cve()
    test_empty_components_without_scope_rejected()
    test_openshift_component_inferred_from_platform()
    test_catalog_versus_pdf_retrieval_roles()
    import runpy
    runpy.run_path("catalog.py", run_name="__main__")
    print("ok")
