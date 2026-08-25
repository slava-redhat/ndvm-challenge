"""NDVM Streamlit UI: chat intake -> ranked, cited mitigation options."""
import json
import os
import requests
import streamlit as st

ORCH = os.environ.get("ORCHESTRATOR_URL", "http://localhost:8000")
DISRUPTION_COLOR = {"none": "🟢", "low": "🟢", "medium": "🟠", "high": "🔴"}
CONTROL_ICON = {"mitigated": "✅", "partial": "🟡", "not_mitigated": "❌", "unknown": "⚪"}
TIER_BADGE = {"act_now": ("🔴", "Act now"), "prioritize": ("🟠", "Prioritize"),
              "unknown": ("⚫", "Unknown"), "scheduled": ("🟡", "Scheduled"),
              "routine": ("⚪", "Routine")}
SSVC_BADGE = {"act": ("🔴", "Act"), "attend": ("🟠", "Attend"),
              "track_star": ("🟡", "Track*"), "track": ("⚪", "Track")}


# P4 — provenance: label each source by trust tier so David sees WHY to trust a fact.
# Pure domain match (no model), highest-trust first wins.
SOURCE_TIERS = [
    (("access.redhat.com", "bugzilla.redhat.com", "docs.redhat.com", "docs.openshift.com"),
     "🛡️", "Red Hat official"),
    (("cisa.gov",), "🚨", "CISA (US gov)"),
    (("first.org",), "📊", "FIRST EPSS"),
    (("nvd.nist.gov", "cve.org", "cve.mitre.org", "mitre.org"), "🏛️", "NVD / MITRE"),
]


def source_tier(url: str) -> tuple[str, str]:
    low = (url or "").lower()
    for domains, icon, label in SOURCE_TIERS:
        if any(d in low for d in domains):
            return icon, label
    return "🔗", "Other source"


def src_label(url: str) -> str:
    icon, label = source_tier(url)
    return f"{icon} {label} — {url}"


def src_tag(url: str) -> str:
    """Plain '[tier] url' for exports (no emoji; survives latin-1 PDF)."""
    _, label = source_tier(url)
    return f"[{label}] {url}"


def priority_line(pr: dict) -> str:
    """One human line from an ExploitSignal dict, or '' if absent."""
    if not pr:
        return ""
    icon, label = TIER_BADGE.get(pr.get("tier", "routine"), ("⚪", "Routine"))
    bits = [f"{icon} **{label}**"]
    if pr.get("in_kev"):
        bits.append("known-exploited (CISA KEV)")
    if pr.get("epss") is not None:
        bits.append(f"EPSS {pr['epss']:.0%}")
    if pr.get("ssvc_label") or pr.get("ssvc_decision"):
        sicon, slabel = SSVC_BADGE.get(pr.get("ssvc_decision") or "",
                                       ("", pr.get("ssvc_label") or "SSVC"))
        bits.append(f"SSVC {sicon} {slabel}".strip())
    return " · ".join(bits)


def dots(n: int) -> str:
    n = max(0, min(4, int(n or 0)))
    return "●" * n + "○" * (4 - n)


def render_audit(audit: list) -> None:
    """The visible trust story: how this answer was produced, step by step. Each step
    shows its BASIS (what it rests on) so 'trusted' is inspectable, not asserted."""
    if not audit:
        return
    total = sum(s.get("ms") or 0 for s in audit)
    with st.expander(f"🧾 How this answer was produced — audit trail"
                     + (f" ({total/1000:.0f}s)" if total else ""), expanded=False):
        st.caption("Green-badged steps are computed in Python from authoritative feeds "
                   "(never model-guessed). Every fact traces to a source below.")
        for i, s in enumerate(audit, 1):
            ms = f"  ·  {s['ms']/1000:.1f}s" if s.get("ms") else ""
            st.markdown(f"**{i}. {s.get('step','')}**  `{s.get('basis','')}`{ms}")
            if s.get("detail"):
                st.caption(s["detail"])
            for src in s.get("sources", []):
                st.caption(src_label(src))


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
    pr = advice.get("priority") or {}
    if pr:
        icon, label = TIER_BADGE.get(pr.get("tier", "routine"), ("", "Routine"))
        out.append(f"- **Exploitation urgency:** {icon} {label}"
                   + (" · known-exploited (CISA KEV)" if pr.get("in_kev") else "")
                   + (f" · EPSS {pr['epss']:.0%}" if pr.get("epss") is not None else ""))
        if pr.get("ssvc_label") or pr.get("ssvc_decision"):
            sicon, slabel = SSVC_BADGE.get(pr.get("ssvc_decision") or "",
                                          ("", pr.get("ssvc_label") or "SSVC"))
            out.append(f"- **SSVC decision:** {sicon} {slabel} (CISA/SEI Table 9 — action priority)")
            if pr.get("ssvc_rationale"):
                out.append(f"  - {pr['ssvc_rationale']}")
        if pr.get("rationale"):
            out.append(f"  - {pr['rationale']}")
        out += [f"  - source: {src_tag(s)}" for s in pr.get("source_urls", [])]
    if v.get("rhsa"):
        out.append(f"- **Fixing erratum:** {v['rhsa']} → {v.get('fixed_nvra','')}")
    if v.get("rationale"):
        out.append("\n" + v["rationale"])
    out += [f"- source: {src_tag(s)}" for s in v.get("source_urls", [])]
    controls = advice.get("existing_controls", [])
    if controls:
        out.append("\n## Controls you already have")
        for c in controls:
            out.append(f"- **{c.get('control','')}** — {c.get('status','?').replace('_',' ')}"
                       + (f": {c['rationale']}" if c.get("rationale") else ""))
            out += [f"  - source: {src_tag(s)}" for s in c.get("source_urls", [])]
    if advice.get("decision_summary") or advice.get("residual_before"):
        out += ["\n## Decision package",
                f"- **Residual before interim:** {(advice.get('residual_before') or '—').replace('_', ' ')}",
                f"- **Residual after recommended:** {(advice.get('residual_after') or '—').replace('_', ' ')}"]
        if advice.get("decision_summary"):
            out.append(f"- {advice['decision_summary']}")
    if advice.get("business_risk"):
        out += ["\n## What this means for your business", advice["business_risk"]]
    out.append("\n## Mitigation options (ranked)")
    for o in advice.get("options", []):
        star = " ⭐ **RECOMMENDED**" if o.get("title") == rec else ""
        out.append(f"\n### {o.get('title','')}{star}")
        out.append(f"- disruption: **{o.get('disruption','?')}** · "
                   f"effectiveness: {o.get('effectiveness','?')}/4 · effort: {o.get('effort','?')}/4"
                   + (f" · fit score: {o['score']}" if o.get("score") is not None else ""))
        if o.get("description"):
            out.append(o["description"])
        out += [f"  - {s}" for s in o.get("steps", [])]
        out += [f"  - source: {src_tag(s)}" for s in o.get("source_urls", [])]
    out += ["\n## Recommended approach", advice.get("explanation", "")]
    if advice.get("playbook"):
        out += ["\n## Playbook", "```yaml", advice["playbook"], "```"]
    audit = advice.get("audit", [])
    if audit:
        out.append("\n## How this answer was produced (audit trail)")
        for i, s in enumerate(audit, 1):
            out.append(f"{i}. **{s.get('step','')}** [{s.get('basis','')}]"
                       + (f" — {s['detail']}" if s.get("detail") else ""))
            out += [f"   - source: {src_tag(x)}" for x in s.get("sources", [])]
    return "\n".join(out)


def report_pdf(intake: dict, advice: dict, account: dict | None = None) -> bytes:
    """PDF with the same section order and labels as render_advice / render_account."""
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos

    def a(s):  # ponytail: core fonts are latin-1; drop emoji rather than ship a TTF
        return (str(s) if s is not None else "").encode("latin-1", "ignore").decode("latin-1")

    v = advice.get("vulnerability", {})
    rec = advice.get("recommended_title")
    pdf = FPDF()
    pdf.set_margins(15, 15, 15)
    pdf.set_auto_page_break(True, 15)
    pdf.add_page()

    def h(txt, size=13):
        pdf.set_font("Helvetica", "B", size)
        pdf.multi_cell(0, 7, a(txt), new_x=XPos.LMARGIN, new_y=YPos.NEXT, wrapmode="CHAR")
        pdf.ln(1)

    def p(txt, size=10, style=""):
        pdf.set_font("Helvetica", style, size)
        pdf.multi_cell(0, 5, a(txt), new_x=XPos.LMARGIN, new_y=YPos.NEXT, wrapmode="CHAR")

    def adots(n):
        n = max(0, min(4, int(n or 0)))
        return "*" * n + "-" * (4 - n)

    def rule():
        pdf.ln(1)
        y = pdf.get_y()
        pdf.set_draw_color(180, 180, 180)
        pdf.line(15, y, 195, y)
        pdf.ln(3)

    # --- Router banner (same as st.success in render_advice) ---
    flow = "Customer flow" if advice.get("persona") == "primary" else "TAM flow"
    h("NDVM — Non-Disruptive Vulnerability Mitigation", 16)
    p(f"Router chose: {flow}  ·  platform: {intake.get('platform', '?')}  ·  "
      f"CVE: {intake.get('cve') or v.get('cve_id', '?')}")
    rule()

    # --- Account estate (same blocks as render_account) ---
    if account:
        h(f"Customer: {account.get('account_name', '')}", 14)
        p(f"Registered systems: {account.get('estate_size', '?')}    "
          f"Affected by this CVE: {len((account.get('cve') or {}).get('affected') or [])}    "
          f"Reboot window: {(account.get('maintenance') or {}).get('next_reboot_window', '-')}")
        if account.get("assigned_tam"):
            p(f"Industry: {account.get('industry', '')}  ·  TAM: {account['assigned_tam']}  ·  "
              f"org {account.get('org_id', '')}", size=9)
        mw = account.get("maintenance") or {}
        if mw.get("change_freeze"):
            p(f"Change policy: {mw['change_freeze']}", size=9)
        cv = account.get("cve") or {}
        if cv.get("affected"):
            h(f"Hosts affected by {cv.get('cve', '')} "
              f"(severity {cv.get('severity', '?')}, fix_state {cv.get('red_hat_fix_state', '?')}"
              + (", known-exploited" if cv.get("known_exploited") else "") + ")", 11)
            for host in cv["affected"]:
                p(f"  {host.get('hostname', '')}  |  {host.get('status', '')}  |  "
                  f"{'internet-facing' if host.get('public_exposure') else 'internal'}  |  "
                  f"{host.get('reason', '')}", size=9)
        if cv.get("not_affected"):
            p("Not affected: " + ", ".join(
                host.get("hostname", "") for host in cv["not_affected"]), size=9)
        if cv.get("remediation_playbook"):
            p(f"Insights remediation available: {cv['remediation_playbook']}", size=9)
        comp = account.get("compliance") or []
        if comp:
            h("Compliance (Insights OpenSCAP) — affected hosts", 11)
            for r in comp:
                p(f"  {r.get('hostname', '')}  |  {r.get('profile', '')}  |  "
                  f"{r.get('score', '?')}%  |  "
                  f"{', '.join(r.get('failed_rules', [])) or '-'}", size=9)
        rule()

    # --- Vulnerability block (subheader + 3 metrics + priority + rationale + sources) ---
    h(f"{v.get('cve_id', 'CVE')} — {v.get('threat_severity', '?')}", 14)
    p(f"Fix state: {v.get('fix_state', '?')}      "
      f"CVSS: {v.get('cvss3') or '-'}      "
      f"NDVM applies: {'Yes' if v.get('ndvm_applies') else 'No'}")
    pr = advice.get("priority") or {}
    if pr:
        _, label = TIER_BADGE.get(pr.get("tier", "routine"), ("", "Routine"))
        bits = [f"Exploitation urgency: {label}"]
        if pr.get("in_kev"):
            bits.append("known-exploited (CISA KEV)")
        if pr.get("epss") is not None:
            bits.append(f"EPSS {pr['epss']:.0%}")
        if pr.get("ssvc_label"):
            bits.append(f"SSVC {pr['ssvc_label']}")
        p(" · ".join(bits), style="B")
        if pr.get("rationale"):
            p(pr["rationale"])
        if pr.get("ssvc_rationale"):
            p(pr["ssvc_rationale"])
    if v.get("rationale"):
        p(v["rationale"])
    if v.get("rhsa"):
        p(f"Fixing erratum: {v['rhsa']} -> {v.get('fixed_nvra', '')}")
    for src in list(v.get("source_urls", [])) + (pr.get("source_urls", []) if pr else []):
        p(src_tag(src), size=8)

    # --- Controls you already have ---
    controls = advice.get("existing_controls", [])
    if controls:
        rule()
        if any(c.get("status") == "mitigated" for c in controls):
            p("You may already be protected — a control you run mitigates this. See below.",
              style="B")
        h("Controls you already have")
        for c in controls:
            status = (c.get("status") or "?").replace("_", " ")
            p(f"[{status}]  {c.get('control', '')}", style="B")
            if c.get("rationale"):
                p(c["rationale"])
            for src in c.get("source_urls", []):
                p(src_tag(src), size=8)
            pdf.ln(1)

    # --- Decision package (after controls; same order as Streamlit / Markdown) ---
    if advice.get("decision_summary") or advice.get("residual_before"):
        rule()
        h("Decision package", 14)
        p(f"Residual before interim: {(advice.get('residual_before') or '—').replace('_', ' ')}      "
          f"Residual after recommended: {(advice.get('residual_after') or '—').replace('_', ' ')}",
          style="B")
        if advice.get("decision_summary"):
            p(advice["decision_summary"])

    # --- Business risk ---
    risk = advice.get("business_risk")
    if risk:
        rule()
        h("What this means for your business")
        p(risk)

    # --- Mitigation options (ranked cards) ---
    rule()
    h("Mitigation options")
    for opt in advice.get("options", []):
        is_rec = opt.get("title") == rec
        title = opt.get("title", "")
        h(("RECOMMENDED — " if is_rec else "") + title, 11)
        p(f"disruption: {opt.get('disruption', '?')}      "
          f"effectiveness: {adots(opt.get('effectiveness'))} ({opt.get('effectiveness', '?')}/4)      "
          f"effort: {adots(opt.get('effort'))} ({opt.get('effort', '?')}/4)")
        if opt.get("score") is not None:
            p(f"fit score {opt['score']} · ranked by disruption/effectiveness/effort "
              f"for your constraint (higher = better)", size=9)
        if opt.get("description"):
            p(opt["description"])
        if opt.get("steps"):
            for s in opt["steps"]:
                p(f"  - {s}")
        for src in opt.get("source_urls", []):
            p(src_tag(src), size=8)
        pdf.ln(2)

    # --- Recommended approach ---
    rule()
    h("Recommended approach")
    p(advice.get("explanation", ""))

    # --- Playbook ---
    if advice.get("playbook"):
        rule()
        h("Ansible-style playbook for the recommended option")
        pdf.set_font("Courier", "", 8)
        pdf.multi_cell(0, 4, a(advice["playbook"]),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT, wrapmode="CHAR")

    # --- Audit trail (same content as render_audit) ---
    audit = advice.get("audit") or []
    if audit:
        rule()
        total = sum(s.get("ms") or 0 for s in audit)
        h("How this answer was produced — audit trail"
          + (f" ({total / 1000:.0f}s)" if total else ""))
        p("Steps tagged with Python / Red Hat / CISA / FIRST are computed from "
          "authoritative feeds (never model-guessed).", size=9)
        for i, s in enumerate(audit, 1):
            ms = f"  ·  {s['ms'] / 1000:.1f}s" if s.get("ms") else ""
            p(f"{i}. {s.get('step', '')}  [{s.get('basis', '')}]{ms}", style="B")
            if s.get("detail"):
                p(s["detail"], size=9)
            for src in s.get("sources", []):
                p(src_tag(src), size=8)

    return bytes(pdf.output())


st.set_page_config(page_title="NDVM — Non-Disruptive Vulnerability Mitigation", page_icon="🛡️")
st.title("🛡️ Non-Disruptive Vulnerability Mitigation")
st.caption("Can't patch right now? Describe your environment and the CVE — get trusted, "
           "personalized options grounded in Red Hat security data.")

@st.cache_data(ttl=300)
def fetch_accounts():
    """Synthetic customer accounts a TAM can look up (Insights-style estate)."""
    try:
        r = requests.get(f"{ORCH}/accounts", timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception:
        return []


@st.cache_data(ttl=300)
def fetch_triage(account):
    """Whole-estate CVE triage (KEV+EPSS ranked) for one customer."""
    try:
        r = requests.get(f"{ORCH}/triage", params={"account": account}, timeout=60)
        r.raise_for_status()
        return r.json()
    except Exception:
        return {}


def render_triage(tri):
    """Respond-at-scale board: all of a customer's tracked CVEs, most urgent first."""
    if not tri.get("cves"):
        return
    with st.expander(f"📊 Full exposure for {tri.get('account','')} — all tracked CVEs, "
                     f"triaged by KEV + EPSS + SSVC", expanded=True):
        st.caption("Start at the top. Name a CVE below to deep-dive it into options.")
        st.table([{"CVE": r["cve"],
                   "urgency": f"{TIER_BADGE.get(r['tier'],('⚪',''))[0]} "
                              f"{r['tier'].replace('_',' ')}",
                   "SSVC": f"{SSVC_BADGE.get(r.get('ssvc_decision') or '', ('',''))[0]} "
                           f"{r.get('ssvc_label') or '—'}",
                   "known-exploited": "⚠️ yes" if r.get("in_kev") else "—",
                   "EPSS": f"{r['epss']:.0%}" if r.get("epss") is not None else "—",
                   "affected": r.get("affected_count", 0),
                   "internet-facing": r.get("internet_facing", 0),
                   "fix_state": r.get("fix_state", "")} for r in tri["cves"]])


ss = st.session_state
pending = ss.get("pending")  # {questions, orig_msg, cve, persona, answers, round}

PERSONA_OPTIONS = {
    "auto": ":material/auto_awesome: Let NDVM decide",
    "primary": ":material/business_center: Platform owner",
    "secondary": ":material/support_agent: Red Hat TAM",
}
with st.container(border=True):
    st.markdown("#### Start your mitigation briefing")
    st.caption("Choose the view that fits your role, or let NDVM tailor it from your question.")
    persona_choice = st.segmented_control(
        "Who are you?",
        options=list(PERSONA_OPTIONS),
        format_func=PERSONA_OPTIONS.get,
        default="auto",
        required=True,
        key="persona_choice",
        width="stretch",
        disabled=bool(pending),
    )
persona_label = {
    "auto": "Auto-detect",
    "primary": "Customer / Platform Owner",
    "secondary": "Red Hat Support / TAM",
}[persona_choice]
persona = {"primary": "primary", "secondary": "secondary"}.get(persona_choice)

# Three tailored inputs — one per persona.
account = ""  # only the TAM flow selects a customer account to look up
if persona == "secondary":
    st.caption("**Red Hat Support / TAM** — look up the customer's estate in Insights, "
               "then get an evidence-first brief you can relay.")
    accounts = fetch_accounts()
    labels = ["(no account — I'll describe it)"] + [
        f"{a['account_name']} · {a.get('industry','')}" for a in accounts]
    pick = st.selectbox("Customer account", labels, index=1 if accounts else 0,
                        disabled=bool(pending))
    if pick != labels[0]:
        account = accounts[labels.index(pick) - 1]["account_name"]
        render_triage(fetch_triage(account))
    msg = st.text_area(
        "What are you looking into for this customer?",
        placeholder="e.g. CVE-2024-1086 — which of their hosts are affected and what can "
                    "they do without a reboot?",
        height=90,
        disabled=bool(pending),
    )
elif persona == "primary":
    st.caption("**Customer / Platform Owner** — describe your situation; I'll ask a few "
               "quick questions so the advice fits your environment, then give you options.")
    msg = st.text_area(
        "Your situation",
        placeholder="e.g. CVE-2023-3390 is flagged on my RHEL 8 fleet. I can't reboot for "
                    "patching until the quarter-end maintenance window. What can I do now?",
        height=110,
        disabled=bool(pending),
    )
else:
    st.caption("**Auto-detect** — just describe it. Name a known customer (e.g. *Meridian*) "
               "and I'll pull their estate and switch to the TAM view automatically.")
    msg = st.text_area(
        "Your situation",
        placeholder="e.g. Is Meridian Telecom affected by CVE-2023-3390, and what can they "
                    "do without rebooting?",
        height=110,
        disabled=bool(pending),
    )

MAX_ROUNDS = 2  # ponytail: stop questioning after 2 rounds and advise anyway (force)


def run_with_progress(message, persona, answers="", force=False, account="", round=0):
    """Stream the flow's real steps into a live status box (replaces the opaque spinner),
    and return the final result dict. Calls st.stop() on error."""
    payload = {"message": message, "persona": persona, "answers": answers,
               "force": force, "account": account, "round": round}
    data = None
    with st.status("Working on it…", expanded=True) as status:
        try:
            # (connect, read) — heartbeats keep the read timeout from firing mid-wave
            with requests.post(f"{ORCH}/advise_stream", json=payload,
                               stream=True, timeout=(10, 120)) as r:
                r.raise_for_status()
                for line in r.iter_lines():
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    et = evt.get("type")
                    if et == "ping":
                        continue
                    if et == "step":
                        status.update(label=evt["step"])
                        st.write(f"• {evt['step']}")
                    elif et == "error":
                        raise RuntimeError(evt.get("message", "unknown error"))
                    elif et == "result":
                        data = evt.get("data")
            status.update(label="Done", state="complete")
        except Exception as e:
            status.update(label="Failed", state="error")
            st.error(f"Orchestrator error: {e}")
            st.stop()
    if data is None:
        st.error("Stream ended without a result")
        st.stop()
    return data


def render_account(acc):
    """Insights-style estate panel shown above the advice for the TAM flow."""
    st.markdown(f"### 🏢 {acc.get('account_name','')}")
    meta = st.columns(3)
    meta[0].metric("Registered systems", acc.get("estate_size", "?"))
    cv = acc.get("cve") or {}
    meta[1].metric("Affected by this CVE", len(cv.get("affected", [])))
    mw = acc.get("maintenance", {})
    meta[2].metric("Reboot window", mw.get("next_reboot_window", "—"))
    if acc.get("assigned_tam"):
        st.caption(f"Industry: {acc.get('industry','')}  ·  TAM: {acc['assigned_tam']}  ·  "
                   f"org {acc.get('org_id','')}")
    if mw.get("change_freeze"):
        st.caption(f"Change policy: {mw['change_freeze']}")
    if cv.get("affected"):
        st.markdown(f"**Hosts affected by `{cv.get('cve','')}`** "
                    f"(severity {cv.get('severity','?')}, fix_state {cv.get('red_hat_fix_state','?')}"
                    + (", ⚠️ known-exploited" if cv.get("known_exploited") else "") + ")")
        st.table([{"host": h.get("hostname", ""), "status": h.get("status", ""),
                   "exposure": "internet-facing" if h.get("public_exposure") else "internal",
                   "why": h.get("reason", "")} for h in cv["affected"]])
    if cv.get("not_affected"):
        st.caption("Not affected: " + ", ".join(h.get("hostname", "") for h in cv["not_affected"]))
    if cv.get("remediation_playbook"):
        st.caption(f"Insights remediation available: `{cv['remediation_playbook']}`")
    comp = acc.get("compliance") or []
    if comp:
        st.markdown("**Compliance (Insights OpenSCAP)** — affected hosts")
        st.table([{"host": r.get("hostname", ""), "profile": r.get("profile", ""),
                   "score": f"{r.get('score','?')}%",
                   "failing rules": ", ".join(r.get("failed_rules", [])) or "—"} for r in comp])


def render_advice(intake, advice, account=None):
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
        pr = advice.get("priority") or {}
        pline = priority_line(pr)
        if pline:
            (st.error if pr.get("tier") == "act_now" or pr.get("ssvc_decision") == "act" else
             st.warning if pr.get("tier") != "routine" or pr.get("ssvc_decision") in
             ("attend", "track_star") else st.info)(
                f"{pline}\n\n{pr.get('rationale','')}"
                + (f"\n\n{pr['ssvc_rationale']}" if pr.get("ssvc_rationale") else ""))
        st.write(vuln.get("rationale", ""))
        if vuln.get("rhsa"):
            st.write(f"Fixing erratum: `{vuln['rhsa']}` → `{vuln.get('fixed_nvra','')}`")
        for src in list(vuln.get("source_urls", [])) + (pr.get("source_urls", []) if pline else []):
            st.caption(src_label(src))

    controls = advice.get("existing_controls", [])
    if controls:
        if any(c.get("status") == "mitigated" for c in controls):
            st.success("You may already be protected — a control you run mitigates this. See below.")
        st.markdown("### Controls you already have")
        for c in controls:
            with st.container(border=True):
                st.markdown(f"{CONTROL_ICON.get(c.get('status'), '⚪')} **{c.get('control','')}** "
                            f"— {c.get('status','?').replace('_',' ')}")
                st.write(c.get("rationale", ""))
                for src in c.get("source_urls", []):
                    st.caption(src_label(src))

    before = advice.get("residual_before") or ""
    after = advice.get("residual_after") or ""
    summary = advice.get("decision_summary") or ""
    if before or after or summary:
        with st.container(border=True):
            st.markdown("### Decision package")
            c1, c2 = st.columns(2)
            c1.metric("Residual before interim", before.replace("_", " ").title() or "—")
            c2.metric("Residual after recommended", after.replace("_", " ").title() or "—")
            if summary:
                st.info(summary)

    risk = advice.get("business_risk")
    if risk:
        st.markdown("### 💼 What this means for your business")
        st.warning(risk)

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
            if opt.get("score") is not None:
                st.caption(f"fit score **{opt['score']}** · ranked by disruption/"
                           "effectiveness/effort for your constraint (higher = better)")
            st.write(opt.get("description", ""))
            if opt.get("steps"):
                st.markdown("\n".join(f"- {s}" for s in opt["steps"]))
            for src in opt.get("source_urls", []):
                st.caption(src_label(src))

    st.markdown("### Recommended approach")
    st.info(advice.get("explanation", ""))

    if advice.get("playbook"):
        with st.expander("Ansible-style playbook for the recommended option"):
            st.code(advice["playbook"], language="yaml")

    md = report_md(intake, advice)
    cve = (advice.get("vulnerability", {}).get("cve_id") or intake.get("cve") or "analysis")
    base = f"NDVM-{cve}-mitigation".replace(" ", "")  # e.g. NDVM-CVE-2023-3390-mitigation
    st.markdown("#### Export this analysis")
    share, dl_md, dl_pdf = st.columns(3)
    share.download_button("📤 Share with my TAM", data=md, file_name=f"{base}.md",
                          mime="text/markdown", use_container_width=True)
    dl_md.download_button("⬇️ Download Markdown", data=md, file_name=f"{base}.md",
                          mime="text/markdown", use_container_width=True)
    try:
        dl_pdf.download_button("⬇️ Download PDF", data=report_pdf(intake, advice, account),
                               file_name=f"{base}.pdf", mime="application/pdf",
                               use_container_width=True)
    except Exception as e:  # PDF is a nice-to-have; never block the page on it
        dl_pdf.caption(f"pdf n/a: {e}")

    st.markdown("### Audit trail")
    render_audit(advice.get("audit", []))


# Phase 2 — the sufficiency judge asked for more; collect answers.
if pending:
    pending_cve = pending.get("cve") or "this CVE"
    st.info(f"Answering follow-up questions for **{pending_cve}**. I won't guess.")
    if st.button("Start a new question", key="cancel_pending",
                 icon=":material/restart_alt:"):
        ss.pop("pending", None)
        ss.pop("result", None)
        st.rerun()
    if pending.get("missing"):
        st.caption("Still unclear: " + " · ".join(pending["missing"]))
    with st.container(border=True):
        picks = []
        for i, q in enumerate(pending["questions"]):
            label = q["question"]
            opts = [o for o in (q.get("options") or []) if str(o).strip()]
            if not opts:
                opts = ["Not sure", "Other (describe)"]
            key = f"q_{i}_{q.get('key','')}"
            if q.get("multi", False):
                values = st.multiselect(label, opts, key=key)
            else:
                values = [st.radio(label, opts, key=key)]
            other = next((value for value in values
                          if str(value).lower().startswith("other")), "")
            values = [value for value in values if value != other]
            if other:
                detail = st.text_input(
                    "Add a short detail",
                    key=f"{key}_other",
                    placeholder="Only if a listed choice does not fit",
                ).strip()
                values.append(f"Other: {detail}" if detail else "Other")
            picks.append((q.get("key", ""), label, values))
        submitted = st.button("Submit answers →", type="primary", key="clarify_submit")
    if submitted:
        new = "\n".join(
            f"[{key}] {label}: {', '.join(values) if values else '(no answer)'}"
            for key, label, values in picks
        )
        merged = (pending["answers"] + "\n" + new).strip()
        # CVE disambiguation is not a sufficiency round — keep budget for real gate Qs.
        only_cve_pick = (
            len(pending["questions"]) == 1
            and (pending["questions"][0].get("key") or "") == "which_cve"
        )
        rnd = pending["round"] if only_cve_pick else pending["round"] + 1
        force = rnd > MAX_ROUNDS  # ran out of rounds: advise with what we have
        data = run_with_progress(pending["orig_msg"], pending["persona"], merged, force,
                                 pending.get("account", ""), round=rnd)
        if data.get("status") == "need_info" and not force:
            ss["pending"] = {"questions": data["questions"], "missing": data.get("missing", []),
                             "orig_msg": pending["orig_msg"], "persona": pending["persona"],
                             "answers": merged, "round": rnd,
                             "account": pending.get("account", ""),
                             "cve": (data.get("intake") or {}).get("cve") or pending.get("cve", "")}
            ss.pop("result", None)
        else:
            ss.pop("pending", None)
            ss["result"] = data
        st.rerun()

# Phase 1 — fresh submission.
elif st.button("Get mitigation options", type="primary") and msg.strip():
    data = run_with_progress(msg, persona, account=account)
    if data.get("status") == "need_info":
        ss["pending"] = {"questions": data["questions"], "missing": data.get("missing", []),
                         "orig_msg": msg, "persona": persona, "answers": "", "round": 1,
                         "account": account,
                         "cve": (data.get("intake") or {}).get("cve", "")}
        ss.pop("result", None)
    else:
        ss["result"] = data
    st.rerun()

# Render the last produced advice (survives download-button reruns).
if ss.get("result"):
    data = ss["result"]
    if data.get("status") in ("off_topic", "need_cve", "knowledge_base_unavailable"):
        st.warning(data.get("message", "No verified mitigation guidance is available."))
    else:
        intake = data.get("intake", {})
        advice = data.get("advice") or {}
        if data.get("account"):
            render_account(data["account"])
        if advice:
            render_advice(intake, advice, data.get("account"))
        else:
            st.warning("No advice produced. Check the CVE id and try again.")
