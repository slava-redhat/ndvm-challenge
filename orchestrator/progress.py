"""Per-request progress channel: the flow emits step labels, the streaming endpoint
drains them. A contextvar keeps it request-safe under concurrency; the default is a
no-op so the plain (non-streaming) /advise path is completely unaffected.

Also carries an optional cancel Event so disconnect can stop wave work early.
"""
import contextvars
import threading
from contextlib import contextmanager

_emit = contextvars.ContextVar("ndvm_emit", default=None)
_cancel = contextvars.ContextVar("ndvm_cancel", default=None)


def emit(step: str) -> None:
    """Announce the phase now starting. No-op unless a streaming request is listening."""
    fn = _emit.get()
    if fn:
        fn(step)


def cancelled() -> bool:
    ev = _cancel.get()
    return bool(ev and ev.is_set())


def check_cancel() -> None:
    if cancelled():
        raise RuntimeError("request cancelled")


@contextmanager
def using(fn, cancel: threading.Event | None = None):
    tok_e = _emit.set(fn)
    tok_c = _cancel.set(cancel)
    try:
        yield
    finally:
        _emit.reset(tok_e)
        _cancel.reset(tok_c)
