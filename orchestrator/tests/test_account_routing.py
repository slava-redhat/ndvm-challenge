"""Regression coverage for implicit account selection in the TAM flow."""
from pathlib import Path

import crew
from models import Intake


HELIOS_REQUEST = (
    "Helios Health is asking about CVE-2024-6387 (regreSSHion) on their RHEL 9 "
    "fleet and can't reboot the clinical systems during business hours."
)


def test_tam_without_selected_account_autodetects_named_customer(monkeypatch):
    """The TAM's explicit persona must not disable matching a named account."""
    monkeypatch.setenv("NDVM_DATA_DIR", str(Path(__file__).parents[2] / "data"))
    monkeypatch.setattr(
        crew,
        "run_router",
        lambda *_: Intake(
            persona="secondary",
            platform="rhel",
            product="Red Hat Enterprise Linux 9",
            cve="CVE-2024-6387",
            constraint="cannot reboot during business hours",
        ),
    )
    monkeypatch.setattr(
        crew,
        "run_gate",
        lambda *_: (_ for _ in ()).throw(
            AssertionError("recognized account must bypass the sufficiency gate")
        ),
    )

    flow = crew.NDVMFlow()
    flow.state.message = HELIOS_REQUEST
    flow.state.forced_persona = "secondary"
    flow.triage()

    assert flow.state.intake.account == "Helios Health Systems"
    assert flow.state.gate.sufficient is True
    assert "Helios Health Systems" in flow.state.answers


def test_account_affected_systems_override_incorrect_router_platform(monkeypatch):
    monkeypatch.setenv("NDVM_DATA_DIR", str(Path(__file__).parents[2] / "data"))
    monkeypatch.setattr(
        crew,
        "run_router",
        lambda *_: Intake(
            persona="secondary",
            platform="openshift",
            cve="CVE-2023-3390",
            constraint="maintenance freeze",
        ),
    )

    flow = crew.NDVMFlow()
    flow.state.message = "Meridian has CVE-2023-3390 during a freeze"
    flow.state.account = "Meridian"
    flow.triage()

    assert flow.state.intake.platform == "rhel"
