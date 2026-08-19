"""NDVM Streamlit UI: chat intake -> ranked, cited mitigation options."""
import os
import requests
import streamlit as st

ORCH = os.environ.get("ORCHESTRATOR_URL", "http://localhost:8000")
DISRUPTION_COLOR = {"none": "🟢", "low": "🟢", "medium": "🟠", "high": "🔴"}


def dots(n: int) -> str:
    n = max(0, min(4, int(n or 0)))
    return "●" * n + "○" * (4 - n)


def report_md(intake: dict, advice: dict) -> str:
    """Full analysis as Markdown — the single source for both the .md and the TAM share."""
    v = advice.get("vulnerability", {})
    rec = advice.get("recommended_title")
    flow = "Customer" if advice.get("persona") == "primary" else "Red Hat TAM"
    out = [f"# NDVM Analysis — {v.get('cve_id','CVE')} ({v.get('threat_severity','?')})",
           f"_Audience: {flow} · Platform: {intake.get('platform','?')} · "
           f"Constraint: {intake.get('constraint','—') or '—'}_\n",
           "## Environment", advice.get("environment_summary", "") + "\n",
           "## Vulnerability",
           f"- **Fix state:** {v.get('fix_state','?')}",
           f"- **CVSS v3:** {v.get('cvss3') or '—'}",
           f"- **NDVM applies:** {'Yes' if v.get('ndvm_applies') else 'No'}"]
    if v.get("rhsa"):
        out.append(f"- **Fixing erratum:** {v['rhsa']} → {v.get('fixed_nvra','')}")
    if v.get("rationale"):
        out.append("\n" + v["rationale"])
    out += [f"- source: {s}" for s in v.get("source_urls", [])]
    out.append("\n## Mitigation options (ranked)")
    for o in advice.get("options", []):
        star = " ⭐ **RECOMMENDED**" if o.get("title") == rec else ""
        out.append(f"\n### {o.get('title','')}{star}")
        out.append(f"- disruption: **{o.get('disruption','?')}** · "
                   f"effectiveness: {o.get('effectiveness','?')}/4 · effort: {o.get('effort','?')}/4")
        if o.get("description"):
            out.append(o["description"])
        out += [f"  - {s}" for s in o.get("steps", [])]
        out += [f"  - source: {s}" for s in o.get("source_urls", [])]
    out += ["\n## Recommended approach", advice.get("explanation", "")]
    if advice.get("playbook"):
        out += ["\n## Playbook", "```yaml", advice["playbook"], "```"]
    return "\n".join(out)


def report_pdf(intake: dict, advice: dict) -> bytes:
    """Same content as a simple PDF. Core fonts are latin-1, so strip non-latin glyphs."""
    from fpdf import FPDF
    def a(s):  # ponytail: drop emoji/bullets rather than ship a TTF; content stays intact
        return (str(s) if s is not None else "").encode("latin-1", "ignore").decode("latin-1")
    v = advice.get("vulnerability", {})
    rec = advice.get("recommended_title")
    pdf = FPDF()
    pdf.set_auto_page_break(True, 15)
    pdf.add_page()

    def h(txt, size=13):
        pdf.set_font("Helvetica", "B", size); pdf.multi_cell(0, 7, a(txt)); pdf.ln(1)

    def p(txt):
        pdf.set_font("Helvetica", "", 10); pdf.multi_cell(0, 5, a(txt))

    h(f"NDVM Analysis - {v.get('cve_id','CVE')} ({v.get('threat_severity','?')})", 16)
    flow = "Customer" if advice.get("persona") == "primary" else "Red Hat TAM"
    p(f"Audience: {flow}  |  Platform: {intake.get('platform','?')}  |  "
      f"Constraint: {intake.get('constraint','-') or '-'}")
    pdf.ln(2)
    h("Environment"); p(advice.get("environment_summary", ""))
    pdf.ln(1); h("Vulnerability")
    p(f"Fix state: {v.get('fix_state','?')}")
    p(f"CVSS v3: {v.get('cvss3') or '-'}    NDVM applies: {'Yes' if v.get('ndvm_applies') else 'No'}")
    if v.get("rhsa"):
        p(f"Fixing erratum: {v['rhsa']} -> {v.get('fixed_nvra','')}")
    if v.get("rationale"):
        p(v["rationale"])
    for s in v.get("source_urls", []):
        p(f"source: {s}")
    pdf.ln(1); h("Mitigation options (ranked)")
    for o in advice.get("options", []):
        star = "  [RECOMMENDED]" if o.get("title") == rec else ""
        h(f"{o.get('title','')}{star}", 11)
        p(f"disruption: {o.get('disruption','?')}  |  effectiveness: "
          f"{o.get('effectiveness','?')}/4  |  effort: {o.get('effort','?')}/4")
        if o.get("description"):
            p(o["description"])
        for s in o.get("steps", []):
            p(f"  - {s}")
        for s in o.get("source_urls", []):
            p(f"  source: {s}")
    pdf.ln(1); h("Recommended approach"); p(advice.get("explanation", ""))
    if advice.get("playbook"):
        h("Playbook"); pdf.set_font("Courier", "", 8); pdf.multi_cell(0, 4, a(advice["playbook"]))
    return bytes(pdf.output())


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

MAX_ROUNDS = 2  # ponytail: stop questioning after 2 rounds and advise anyway (force)


def post_advise(message, persona, answers="", force=False):
    resp = requests.post(f"{ORCH}/advise",
                         json={"message": message, "persona": persona,
                               "answers": answers, "force": force}, timeout=300)
    resp.raise_for_status()
    return resp.json()


def render_advice(intake, advice):
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

    md = report_md(intake, advice)
    share, _, dl_md, dl_pdf = st.columns([3, 2, 1, 1])
    share.download_button("📤 Share this analysis with my TAM",
                          data=md, file_name="ndvm-advice.md", mime="text/markdown")
    dl_md.download_button("⬇️ .md", data=md, file_name="ndvm-analysis.md",
                          mime="text/markdown")
    try:
        dl_pdf.download_button("⬇️ .pdf", data=report_pdf(intake, advice),
                               file_name="ndvm-analysis.pdf", mime="application/pdf")
    except Exception as e:  # PDF is a nice-to-have; never block the page on it
        dl_pdf.caption(f"pdf n/a: {e}")


ss = st.session_state
pending = ss.get("pending")  # {questions, orig_msg, persona, answers, round}

# Phase 2 — the sufficiency judge asked for more; collect tick-box answers.
if pending:
    st.info("A few quick questions so the advice fits **your** environment — I won't guess. "
            "Tick what applies, then submit.")
    if pending.get("missing"):
        st.caption("Still unclear: " + " · ".join(pending["missing"]))
    with st.form("clarify"):
        picks = {}
        for i, q in enumerate(pending["questions"]):
            label = q["question"]
            opts = q.get("options", []) or []
            key = f"q_{i}_{q.get('key','')}"
            if q.get("multi", True):
                picks[label] = st.multiselect(label, opts, key=key)
            else:
                picks[label] = [v] if (v := st.radio(label, opts, key=key)) else []
        submitted = st.form_submit_button("Submit answers →", type="primary")
    if submitted:
        new = "\n".join(f"{lbl}: {', '.join(v) if v else '(no answer)'}"
                        for lbl, v in picks.items())
        merged = (pending["answers"] + "\n" + new).strip()
        rnd = pending["round"] + 1
        force = rnd > MAX_ROUNDS  # ran out of rounds: advise with what we have
        with st.spinner("Re-checking your case…" if not force else "Analysing…"):
            data = post_advise(pending["orig_msg"], pending["persona"], merged, force)
        if data.get("status") == "need_info" and not force:
            ss["pending"] = {"questions": data["questions"], "missing": data.get("missing", []),
                             "orig_msg": pending["orig_msg"], "persona": pending["persona"],
                             "answers": merged, "round": rnd}
            ss.pop("result", None)
        else:
            ss.pop("pending", None)
            ss["result"] = data
        st.rerun()

# Phase 1 — fresh submission.
elif st.button("Get mitigation options", type="primary") and msg.strip():
    with st.spinner("Routing → checking your case fits → analysing → ranking…"):
        try:
            data = post_advise(msg, persona)
        except Exception as e:
            st.error(f"Orchestrator error: {e}")
            st.stop()
    if data.get("status") == "need_info":
        ss["pending"] = {"questions": data["questions"], "missing": data.get("missing", []),
                         "orig_msg": msg, "persona": persona, "answers": "", "round": 1}
        ss.pop("result", None)
    else:
        ss["result"] = data
    st.rerun()

# Render the last produced advice (survives download-button reruns).
if ss.get("result"):
    data = ss["result"]
    if data.get("status") == "off_topic":
        st.warning(data.get("message", "I can only help with security vulnerability mitigation."))
    else:
        intake = data.get("intake", {})
        advice = data.get("advice") or {}
        if advice:
            render_advice(intake, advice)
        else:
            st.warning("No advice produced. Check the CVE id and try again.")
