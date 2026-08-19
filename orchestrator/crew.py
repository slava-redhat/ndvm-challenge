"""CrewAI agents + tasks + the router Flow.

Flow: triage(Router) -> @router(persona) -> primary|secondary crew.
Both personas share the analysis agents (profiler, analyst, retriever, strategist)
and differ only in the final synthesizer (Customer Advisor vs TAM Briefer).
"""
from crewai import Agent, Crew, Process, Task
from crewai.flow.flow import Flow, listen, router, start
from pydantic import BaseModel

from llm import get_llm
from models import AdviceResult, Intake, Sufficiency
from tools import RagSearchTool, RedHatCveSearchTool, RedHatSecurityDataTool

LLM = get_llm()
SEC_TOOL = RedHatSecurityDataTool()
SEARCH_TOOL = RedHatCveSearchTool()
RAG_TOOL = RagSearchTool()


# ---- Agents (each with a backstory) -----------------------------------------

def _router_agent() -> Agent:
    return Agent(
        role="Intake & Persona Router",
        goal="In as few questions as possible, figure out who the user is and scope their situation.",
        backstory=(
            "You are a calm Red Hat triage specialist. In moments you tell a stressed "
            "external customer (a Platform Owner or IT Leader) apart from an internal "
            "Red Hat Support engineer or TAM, and you extract the essentials: platform, "
            "version, the CVE, and the hard constraint that blocks patching."
        ),
        llm=LLM,
        verbose=False,
    )


def _analysis_agents() -> dict[str, Agent]:
    profiler = Agent(
        role="Environment Profiler",
        goal="Turn messy human descriptions into a precise environment profile.",
        backstory=(
            "You capture exactly what a customer runs — platform, product, version, "
            "exposure — and the real-world constraint (e.g. 'no reboot until quarter-end') "
            "that rules out immediate patching."
        ),
        llm=LLM, verbose=False,
    )
    researcher = Agent(
        role="Red Hat CVE Researcher",
        goal="Discover which CVEs actually affect the customer's software and surface the ones that matter.",
        backstory=(
            "You comb Red Hat's CVE catalog the way a security analyst does — by package, "
            "product, severity and date. When a customer names software but not a CVE, or "
            "asks 'what should I worry about', you find the relevant CVEs and their "
            "advisories from Red Hat's own public data, never from memory."
        ),
        tools=[SEARCH_TOOL], llm=LLM, verbose=False,
    )
    analyst = Agent(
        role="Red Hat Vulnerability Analyst",
        goal="State the authoritative truth about a CVE for this product, with citations.",
        backstory=(
            "You live in Red Hat's security data. Given a CVE and a product you report "
            "severity, whether a fix shipped, and the Fix State (Fix deferred / Will not "
            "fix / Not affected...). You never guess — you read the data and cite it."
        ),
        tools=[SEC_TOOL], llm=LLM, verbose=False,
    )
    retriever = Agent(
        role="Mitigation Knowledge Retriever",
        goal="Retrieve only grounded, sourced, non-disruptive mitigation options.",
        backstory=(
            "You know where the trusted mitigation guidance lives and you retrieve only "
            "options that fit the platform. You never invent a control that isn't in the "
            "knowledge base."
        ),
        tools=[RAG_TOOL], llm=LLM, verbose=False,
    )
    strategist = Agent(
        role="Risk & Trade-off Strategist",
        goal="Rank mitigations for THIS customer's constraint and pick the best.",
        backstory=(
            "You weigh each option by disruption, effectiveness and effort against the "
            "customer's hard constraint, then choose the one you'd stake your name on and "
            "explain why the others rank lower."
        ),
        llm=LLM, verbose=False,
    )
    return {"profiler": profiler, "researcher": researcher, "analyst": analyst,
            "retriever": retriever, "strategist": strategist}


def _synth_agent(persona: str) -> Agent:
    if persona == "secondary":
        return Agent(
            role="TAM Technical Briefing Writer",
            goal="Write a dense, evidence-first brief a Red Hat TAM can relay and adapt.",
            backstory=(
                "You write for a Red Hat TAM advising a customer: every claim cited, the "
                "raw fix_state / RHSA / VEX references included, ready to reuse across "
                "similar cases."
            ),
            llm=LLM, verbose=False,
        )
    return Agent(
        role="Customer Mitigation Advisor",
        goal="Give a stressed Platform Owner options, trade-offs, and a clear recommendation.",
        backstory=(
            "You speak plainly and confidently to someone who can't take downtime. You give "
            "viable options, the trade-offs, a clear recommended approach, and the proof "
            "behind it — so they can act today without fear."
        ),
        llm=LLM, verbose=False,
    )


# ---- Router crew -------------------------------------------------------------

def run_router(message: str, forced_persona: str = "") -> Intake:
    agent = _router_agent()
    task = Task(
        description=(
            "Read the user's message:\n---\n{message}\n---\n"
            "Classify the persona: 'primary' = an external customer (Platform Owner or "
            "IT Leader); 'secondary' = Red Hat Support or a TAM. Extract platform "
            "(rhel|openshift|other), product (e.g. 'Red Hat Enterprise Linux 8'), version, "
            "cve (e.g. CVE-2023-3390), and the hard constraint that blocks patching. "
            "If a forced persona is provided ('{forced_persona}'), use it as the persona."
        ),
        expected_output="An Intake object.",
        agent=agent,
        output_pydantic=Intake,
    )
    crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=False)
    out = crew.kickoff(inputs={"message": message, "forced_persona": forced_persona or "none"})
    intake: Intake = out.pydantic
    if forced_persona in ("primary", "secondary"):
        intake.persona = forced_persona  # UI override wins
    return intake


# ---- Sufficiency gate (runs before any advice) -------------------------------

def _gate_agent() -> Agent:
    return Agent(
        role="Environment Sufficiency Judge",
        goal=("Refuse to advise until this customer's specific environment is understood; "
              "otherwise ask a few precise tick-box questions."),
        backstory=(
            "You are a meticulous Red Hat TAM lead who has watched bad advice come from "
            "guessing. Before anyone proposes a mitigation you insist on knowing the REAL "
            "case: how the CVE surfaced (which scanner / Insights / audit), the exact "
            "affected component and version, how the system is exposed (internet-facing, "
            "internal, air-gapped), whether backups / snapshots / DR exist, and the true "
            "maintenance-window timing. You never pad with generic questions — every "
            "question you ask would actually change the recommendation. You do NOT suggest "
            "upgrading or mitigating a CVE until the picture fits."
        ),
        llm=LLM, verbose=False,
    )


def run_gate(message: str, intake: Intake, answers: str = "") -> Sufficiency:
    agent = _gate_agent()
    task = Task(
        description=(
            "You are the guardrail BEFORE any mitigation advice. Decide whether you "
            "understand THIS customer's situation well enough to give environment-fit, "
            "non-disruptive advice WITHOUT wide guessing.\n"
            "Customer message:\n---\n{message}\n---\n"
            "Structured so far: platform={platform}, product='{product}', version='{version}', "
            "cve='{cve}', constraint='{constraint}'.\n"
            "Answers already gathered from earlier questions (may say 'none'):\n---\n{answers}\n---\n"
            "Judge like a TAM: do you know where/how the vuln was detected, the exact "
            "affected component+version, the exposure, whether backups/DR exist, and the "
            "real maintenance window? If key pieces are missing, you are NOT sufficient.\n"
            "If NOT sufficient: set sufficient=false and generate up to 5 crisp questions, "
            "each with 2-5 concrete tick-box options tailored to THIS case (never generic "
            "filler). Only ask what would change the recommendation, and do not re-ask "
            "anything already answered above.\n"
            "If the picture is clear enough, set sufficient=true and leave questions empty."
        ),
        expected_output="A Sufficiency object.",
        agent=agent,
        output_pydantic=Sufficiency,
    )
    crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=False)
    out = crew.kickoff(inputs={**intake.model_dump(), "message": message,
                               "answers": answers or "none"})
    return out.pydantic


# ---- Advice crew (shared analysis + persona synthesizer) ---------------------

def run_advice(intake: Intake, persona: str, answers: str = "") -> dict:
    a = _analysis_agents()
    synth = _synth_agent(persona)

    profile = Task(
        description=(
            "Summarize the environment: platform={platform}, product='{product}', "
            "version='{version}'. State the hard constraint that blocks patching: "
            "'{constraint}'. Fold in these specific customer answers from the intake "
            "questionnaire (may say 'none'):\n---\n{answers}\n---\n"
            "Reflect exposure, backups/DR and the real maintenance window if given."
        ),
        expected_output="A one-paragraph environment summary.",
        agent=a["profiler"],
    )
    research = Task(
        description=(
            "If a specific CVE ('{cve}') is already given, pass it straight through as the "
            "CVE to analyze — do not search. Otherwise use redhat_cve_search to find the "
            "CVEs affecting product '{product}' / platform '{platform}' (filter by the "
            "package or product; prefer 'critical' and 'important' severity). Choose the "
            "single most relevant CVE to analyze next and note a few other notable ones."
        ),
        expected_output="The CVE id to analyze next, plus a short list of other notable CVEs (id + severity).",
        agent=a["researcher"],
    )
    analyze = Task(
        description=(
            "Look up the CVE chosen by the researcher (or '{cve}' if it was given) for "
            "product '{product}' using the redhat_security_data tool. Report fix_state, "
            "severity, CVSS, fixing RHSA/NVRA if any, whether NDVM applies, and the source "
            "URL. Use ONLY the tool's output."
        ),
        expected_output="The CVE finding with fix_state and source URL.",
        agent=a["analyst"],
        context=[research],
    )
    retrieve = Task(
        description=(
            "Use mitigation_rag_search to find non-disruptive mitigations for platform "
            "'{platform}' relevant to {cve}, given the constraint '{constraint}'. List each "
            "candidate with its source URL. Use ONLY retrieved options."
        ),
        expected_output="A list of grounded candidate mitigations with sources.",
        agent=a["retriever"],
    )
    strategize = Task(
        description=(
            "Rank the retrieved candidates by disruption, effectiveness and effort for the "
            "constraint '{constraint}', weighing the customer's specific answers:\n"
            "---\n{answers}\n---\n"
            "e.g. if they have no maintenance window soon, penalise anything needing a "
            "reboot; if the host is internet-facing, favour options that cut exposure now. "
            "Pick the recommended option and justify why the others rank lower FOR THIS case."
        ),
        expected_output="A ranked shortlist with a recommended option and rationale.",
        agent=a["strategist"],
        context=[analyze, retrieve],
    )
    tone = ("Write for a Red Hat TAM: dense, evidence-first, every claim cited."
            if persona == "secondary"
            else "Write for a stressed Platform Owner: plain, confident, reassuring.")
    synthesize = Task(
        description=(
            f"{tone} Produce the final AdviceResult. Set persona='{persona}', "
            "platform='{platform}'. Copy the vulnerability fields (cve_id, threat_severity, "
            "cvss3, fix_state, ndvm_applies, rhsa, fixed_nvra, rationale, source_urls) "
            "exactly from the analyst's tool output. Fill options from the strategist's "
            "ranking, each with disruption, effectiveness (1-4), effort (1-4) and source_urls. "
            "Set recommended_title to the top option and write a clear explanation of the "
            "trade-offs. If the recommended option is automatable, put a short Ansible-style "
            "snippet in 'playbook'."
        ),
        expected_output="A complete AdviceResult.",
        agent=synth,
        context=[profile, analyze, retrieve, strategize],
        output_pydantic=AdviceResult,
    )
    crew = Crew(
        agents=[a["profiler"], a["researcher"], a["analyst"], a["retriever"],
                a["strategist"], synth],
        tasks=[profile, research, analyze, retrieve, strategize, synthesize],
        process=Process.sequential,
        verbose=False,
    )
    out = crew.kickoff(inputs={**intake.model_dump(), "persona": persona,
                               "answers": answers or "none"})
    return out.pydantic.model_dump()


# ---- Flow --------------------------------------------------------------------

class NDVMState(BaseModel):
    message: str = ""
    forced_persona: str = ""
    answers: str = ""
    force: bool = False          # skip the gate (e.g. after enough question rounds)
    intake: Intake | None = None
    gate: Sufficiency | None = None
    result: dict | None = None


class NDVMFlow(Flow[NDVMState]):
    @start()
    def triage(self):
        self.state.intake = run_router(self.state.message, self.state.forced_persona)
        self.state.gate = (Sufficiency(sufficient=True) if self.state.force
                           else run_gate(self.state.message, self.state.intake,
                                         self.state.answers))

    @router(triage)
    def route(self):
        if not self.state.gate.sufficient:
            return "need_info"          # withhold advice, ask the customer first
        return self.state.intake.persona  # "primary" | "secondary"

    @listen("need_info")
    def ask(self):
        self.state.result = None        # questions travel in state.gate

    @listen("primary")
    def primary_flow(self):
        self.state.result = run_advice(self.state.intake, "primary", self.state.answers)

    @listen("secondary")
    def secondary_flow(self):
        self.state.result = run_advice(self.state.intake, "secondary", self.state.answers)


def advise(message: str, forced_persona: str = "", answers: str = "",
           force: bool = False) -> dict:
    flow = NDVMFlow()
    flow.kickoff(inputs={"message": message, "forced_persona": forced_persona,
                         "answers": answers, "force": force})
    s = flow.state
    if not s.gate.sufficient:
        return {"intake": s.intake.model_dump(), "status": "need_info", "advice": None,
                "missing": s.gate.missing,
                "questions": [q.model_dump() for q in s.gate.questions]}
    return {"intake": s.intake.model_dump(), "status": "ok", "advice": s.result}
