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

# unknown sorts with prioritize (fail-closed) — never below routine
_TIER_ORDER = {"act_now": 0, "prioritize": 1, "unknown": 1, "scheduled": 2, "routine": 3}
MAX_GATE_ROUNDS = 2
_ADVISE_SLOTS = threading.Semaphore(4)  # bound concurrent CrewAI graphs

app = FastAPI(title="NDVM Orchestrator")


class AdviseReq(BaseModel):
    message: str
    persona: str | None = None  # "primary" | "secondary" | None (let the router decide)
    answers: str | None = None  # tick-box answers gathered from the sufficiency gate
    force: bool = False         # skip the gate (client ran out of question rounds)
    round: int = 0              # server-side gate cap (force when >= MAX_GATE_ROUNDS)
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
        except Exception as e:
            print(f"[persist] audit write failed: {type(e).__name__}: {e}", flush=True)


def _effective_force(req: AdviseReq) -> bool:
    return bool(req.force or req.round >= MAX_GATE_ROUNDS)


@app.post("/advise")
def advise_ep(req: AdviseReq):
    if not _ADVISE_SLOTS.acquire(blocking=False):
        return {"status": "error", "advice": None,
                "message": "orchestrator busy — retry shortly"}
    try:
        try:
            result = advise(req.message, req.persona or "", req.answers or "",
                            _effective_force(req), req.account or "")
        except Exception as e:
            return {"status": "error", "advice": None,
                    "message": f"{type(e).__name__}: {e}"}
        _persist(result)
        return result
    finally:
        _ADVISE_SLOTS.release()


@app.post("/advise_stream")
def advise_stream_ep(req: AdviseReq):
    """Same as /advise, but streams NDJSON progress events as the flow runs
    ({"type":"step",...}, {"type":"ping",...}) and ends with {"type":"result",...}
    (or "error"). Disconnect sets cancel so the worker stops between phases."""
    if not _ADVISE_SLOTS.acquire(blocking=False):
        def busy():
            yield json.dumps({"type": "error",
                              "message": "orchestrator busy — retry shortly"}) + "\n"
        return StreamingResponse(busy(), media_type="application/x-ndjson")

    q: queue.Queue = queue.Queue(maxsize=64)
    box: dict = {}
    cancel = threading.Event()

    def _put(item) -> None:
        if cancel.is_set():
            return
        try:
            q.put_nowait(item)
        except queue.Full:
            pass

    def worker():
        try:
            with progress.using(_put, cancel=cancel):
                box["result"] = advise(
                    req.message, req.persona or "", req.answers or "",
                    _effective_force(req), req.account or "")
        except Exception as e:
            if not cancel.is_set():
                box["error"] = f"{type(e).__name__}: {e}"
        finally:
            try:
                q.put_nowait(None)
            except queue.Full:
                pass
            _ADVISE_SLOTS.release()

    threading.Thread(target=worker, daemon=True).start()

    def gen():
        try:
            while True:
                try:
                    step = q.get(timeout=15)
                except queue.Empty:
                    if cancel.is_set():
                        return
                    yield json.dumps({"type": "ping"}) + "\n"
                    continue
                if step is None:
                    break
                yield json.dumps({"type": "step", "step": step}) + "\n"
            if cancel.is_set():
                return
            if "error" in box:
                yield json.dumps({"type": "error", "message": box["error"]}) + "\n"
                return
            result = box.get("result") or {}
            _persist(result)
            yield json.dumps({"type": "result", "data": result}) + "\n"
        except GeneratorExit:
            cancel.set()
            raise
        finally:
            cancel.set()

    return StreamingResponse(gen(), media_type="application/x-ndjson")
