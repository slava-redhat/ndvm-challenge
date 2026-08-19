"""FastAPI wrapper around the CrewAI NDVM flow."""
from fastapi import FastAPI
from pydantic import BaseModel

from accounts import list_accounts
from crew import advise
from db import save_recommendation

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
