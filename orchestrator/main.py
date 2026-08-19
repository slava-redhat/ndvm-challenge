"""FastAPI wrapper around the CrewAI NDVM flow."""
from fastapi import FastAPI
from pydantic import BaseModel

from accounts import account_cves, list_accounts, load_account
from crew import advise
from db import save_recommendation
from priority import assess

_TIER_ORDER = {"act_now": 0, "prioritize": 1, "scheduled": 2, "routine": 3}

app = FastAPI(title="NDVM Orchestrator")


class AdviseReq(BaseModel):
    message: str
    persona: str | None = None  # "primary" | "secondary" | None (let the router decide)
    answers: str | None = None  # tick-box answers gathered from the sufficiency gate
    force: bool = False         # skip the gate (client ran out of question rounds)
    account: str | None = None  # TAM-selected customer account (name or org id)


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/accounts")
def accounts_ep():
    """Synthetic customer accounts a TAM can look up (Insights-style estate)."""
    return list_accounts()


@app.get("/triage")
def triage_ep(account: str):
    """Respond at scale: rank ALL of a customer's tracked CVEs by KEV+EPSS urgency,
    so a TAM sees the whole board before deep-diving one CVE."""
    acc = load_account(account)
    if not acc:
        return {"status": "not_found"}
    rows = []
    for c in account_cves(acc):
        sig = assess(c["cve"], c["severity"], kev_hint=c["known_exploited"])
        tier, rationale = sig["tier"], sig["rationale"]
        # This is the CUSTOMER's board: no affected hosts = no exposure for them,
        # however scary the CVE is globally. Keep the KEV/EPSS facts for context.
        if c["affected_count"] == 0:
            tier, rationale = "routine", "Not affected — no exposed hosts in this estate."
        rows.append({**c, "tier": tier, "epss": sig["epss"],
                     "in_kev": sig["in_kev"], "rationale": rationale})
    rows.sort(key=lambda r: (_TIER_ORDER.get(r["tier"], 9), -(r["epss"] or 0),
                             -r["affected_count"]))
    return {"status": "ok", "account": acc["account"]["account_name"], "cves": rows}


@app.post("/advise")
def advise_ep(req: AdviseReq):
    result = advise(req.message, req.persona or "", req.answers or "", req.force,
                    req.account or "")
    if result.get("advice"):
        try:
            save_recommendation(result["advice"])
        except Exception:
            pass  # ponytail: audit is best-effort; never fail the user's answer over it
    return result
