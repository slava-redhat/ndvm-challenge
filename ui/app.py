"""NDVM Streamlit UI: chat intake -> ranked, cited mitigation options."""
import os
import requests
import streamlit as st

ORCH = os.environ.get("ORCHESTRATOR_URL", "http://localhost:8000")
DISRUPTION_COLOR = {"none": "🟢", "low": "🟢", "medium": "🟠", "high": "🔴"}


def dots(n: int) -> str:
    n = max(0, min(4, int(n or 0)))
    return "●" * n + "○" * (4 - n)


st.set_page_config(page_title="NDVM — Non-Disruptive Vulnerability Mitigation", page_icon="🛡️")
st.title("🛡️ Non-Disruptive Vulnerability Mitigation")
st.caption("Can't patch right now? Describe your environment and the CVE — get trusted, "
           "personalized options grounded in Red Hat security data.")

persona_label = st.radio(
    "Who are you? (or let the router decide)",
    ["Auto-detect", "Customer / Platform Owner", "Red Hat Support / TAM"],
    horizontal=True,
)
persona = {"Customer / Platform Owner": "primary",
           "Red Hat Support / TAM": "secondary"}.get(persona_label)

msg = st.text_area(
    "Your situation",
    placeholder="e.g. CVE-2023-3390 is flagged on my RHEL 8 fleet. I can't reboot for "
                "patching until the quarter-end maintenance window. What can I do now?",
    height=110,
)

if st.button("Get mitigation options", type="primary") and msg.strip():
    with st.spinner("Routing → analysing Red Hat data → retrieving mitigations → ranking…"):
        try:
            resp = requests.post(f"{ORCH}/advise",
                                 json={"message": msg, "persona": persona}, timeout=300)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            st.error(f"Orchestrator error: {e}")
            st.stop()

    intake = data.get("intake", {})
    advice = data.get("advice") or {}
    if not advice:
        st.warning("No advice produced. Check the CVE id and try again.")
        st.stop()

    flow = "Customer flow" if advice.get("persona") == "primary" else "TAM flow"
    st.success(f"Router chose: **{flow}**  ·  platform: `{intake.get('platform','?')}`  ·  "
               f"CVE: `{intake.get('cve','?')}`")

    vuln = advice.get("vulnerability", {})
    with st.container(border=True):
        st.subheader(f"{vuln.get('cve_id','CVE')} — {vuln.get('threat_severity','?')}")
        cols = st.columns(3)
        cols[0].metric("Fix state", vuln.get("fix_state", "?"))
        cols[1].metric("CVSS", vuln.get("cvss3") or "—")
        cols[2].metric("NDVM applies", "Yes" if vuln.get("ndvm_applies") else "No")
        st.write(vuln.get("rationale", ""))
        if vuln.get("rhsa"):
            st.write(f"Fixing erratum: `{vuln['rhsa']}` → `{vuln.get('fixed_nvra','')}`")

    st.markdown("### Mitigation options")
    recommended = advice.get("recommended_title")
    for opt in advice.get("options", []):
        is_rec = opt.get("title") == recommended
        with st.container(border=True):
            head = f"{'⭐ **RECOMMENDED** — ' if is_rec else ''}**{opt['title']}**"
            st.markdown(head)
            c = st.columns(3)
            c[0].markdown(f"{DISRUPTION_COLOR.get(opt.get('disruption','low'),'⚪')} "
                          f"disruption: **{opt.get('disruption','?')}**")
            c[1].markdown(f"effectiveness: {dots(opt.get('effectiveness'))}")
            c[2].markdown(f"effort: {dots(opt.get('effort'))}")
            st.write(opt.get("description", ""))
            if opt.get("steps"):
                st.markdown("\n".join(f"- {s}" for s in opt["steps"]))
            for src in opt.get("source_urls", []):
                st.caption(f"source: {src}")

    st.markdown("### Recommended approach")
    st.info(advice.get("explanation", ""))

    if advice.get("playbook"):
        with st.expander("Ansible-style playbook for the recommended option"):
            st.code(advice["playbook"], language="yaml")

    st.download_button("📤 Share this analysis with my TAM",
                       data=str(advice), file_name="ndvm-advice.txt")
