"""Agent Tool Gateway: three ways to give an agent access to tools (see README.md)."""

def note(trace, actor, text, st="ok"):
    """Append one step to a run's trace. st is 'ok', 'fail' or 'hold'."""
    trace.append({"n": len(trace) + 1, "actor": actor, "text": text, "st": st})
