"""Per-request progress channel: the flow emits step labels, the streaming endpoint
drains them. A contextvar keeps it request-safe under concurrency; the default is a
no-op so the plain (non-streaming) /advise path is completely unaffected."""
import contextvars
from contextlib import contextmanager

_emit = contextvars.ContextVar("ndvm_emit", default=None)


def emit(step: str) -> None:
    """Announce the phase now starting. No-op unless a streaming request is listening."""
    fn = _emit.get()
    if fn:
        fn(step)


@contextmanager
def using(fn):
    tok = _emit.set(fn)
    try:
        yield
    finally:
        _emit.reset(tok)
