"""FastAPI wrapper around the CrewAI NDVM flow."""
import json
import queue
import threading

from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import progress
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


def _persist(result: dict) -> None:
    if result.get("advice"):
        try:
            save_recommendation(result["advice"])
        except Exception:
            pass  # ponytail: audit is best-effort; never fail the user's answer over it


@app.post("/advise")
def advise_ep(req: AdviseReq):
    result = advise(req.message, req.persona or "", req.answers or "", req.force,
                    req.account or "")
    _persist(result)
    return result


@app.post("/advise_stream")
def advise_stream_ep(req: AdviseReq):
    """Same as /advise, but streams NDJSON progress events as the flow runs
    ({"type":"step",...}) and ends with {"type":"result",...} (or "error"). Lets the UI
    show the real audit trail live instead of an opaque spinner. The flow runs in a
    worker thread; step labels drain through a queue."""
    q: queue.Queue = queue.Queue()
    box: dict = {}

    def worker():
        try:
            with progress.using(q.put):  # emit(step) -> q.put(step); contextvar-scoped
                box["result"] = advise(req.message, req.persona or "", req.answers or "",
                                       req.force, req.account or "")
        except Exception as e:  # surface the failure to the client, don't hang the stream
            box["error"] = f"{type(e).__name__}: {e}"
        finally:
            q.put(None)  # sentinel: flow finished

    threading.Thread(target=worker, daemon=True).start()

    def gen():
        while (step := q.get()) is not None:
            yield json.dumps({"type": "step", "step": step}) + "\n"
        if "error" in box:
            yield json.dumps({"type": "error", "message": box["error"]}) + "\n"
            return
        result = box.get("result") or {}
        _persist(result)
        yield json.dumps({"type": "result", "data": result}) + "\n"

    return StreamingResponse(gen(), media_type="application/x-ndjson")
