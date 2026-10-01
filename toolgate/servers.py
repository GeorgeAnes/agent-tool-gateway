"""Three tool servers (calc, docs, plant) speaking a subset of MCP: JSON-RPC 2.0 over HTTP POST,
tools/list and tools/call only (no initialize, sessions, streaming or notifications).

One server implementation, three ways to trust the caller (`mode`):
  key          design A: one shared static key, the same for every user and every server
  passthrough  design B: the user's token, verified, but its audience is not checked
  strict       design C: a token issued for this server only (audience checked)
"""
import json
import secrets
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import note
from .auth import ALL_GROUPS, AUD, SERVER_SCOPES, AuthError, require, verify
from .tools import TOOLS, ToolError, cut_size, read_tag, search_docs, write_setpoint

STATIC_KEY = secrets.token_urlsafe(24)  # design A's one secret, held by the agent and accepted by every server

def bearer(request, allow_query):
    """The token from the Authorization header. RFC 6750 also allows ?access_token=; the MCP authorization spec forbids it, so only lenient servers read it."""
    h = request.headers.get("authorization", "")
    if h[:7].lower() == "bearer ": return h[7:]
    return request.query_params.get("access_token") if allow_query else None

def challenge(e, resource_metadata=None):
    parts = [f'error="{e.code}"'] + ([f'resource_metadata="{resource_metadata}"'] if resource_metadata else [])
    return JSONResponse({"error": e.code, "error_description": e.reason}, e.status, headers={"WWW-Authenticate": "Bearer " + ", ".join(parts)})

async def fields(request):
    """(id, method, tool name, arguments) from a JSON-RPC body. Anything malformed becomes an unknown method rather than a 500."""
    try:
        body = await request.json()
        json.dumps(body, allow_nan=False)  # NaN, Infinity and 1e999 parse in Python but cannot be forwarded as JSON
    except (ValueError, RecursionError): body = None
    body = body if isinstance(body, dict) else {}
    params = body.get("params") if isinstance(body.get("params"), dict) else {}
    name, args = params.get("name"), params.get("arguments")
    return body.get("id"), body.get("method"), name if isinstance(name, str) else None, args if isinstance(args, dict) else {}

def reply(rid, result=None, error=None):
    return JSONResponse({"jsonrpc": "2.0", "id": rid, **({"error": error} if error else {"result": result})})

def authenticate(request, mode, name):
    cred = bearer(request, allow_query=mode != "strict")
    if mode == "key":  # the key names the agent, not the person: full entitlement, no user
        if not cred or not secrets.compare_digest(cred, STATIC_KEY): raise AuthError(401, "invalid_token", "bad key")
        return {"sub": "static-key", "scp": " ".join(SERVER_SCOPES[name]), "groups": ALL_GROUPS}
    return verify(cred or "", AUD[name] if mode == "strict" else None)

def execute(tool, args, claims, plant):
    if tool == "cut_size": return cut_size(args)
    if tool == "search_docs":  # groups come from the verified claims; any `groups` (or `k`) in args is ignored
        return {"hits": search_docs(str(args.get("query", "")), claims["groups"])}
    return (read_tag if tool == "read_tag" else write_setpoint)(plant, args)

def make_server(name, mode, defs, plant, audit, trace):
    app = FastAPI()
    mine = [t for t, (server, _, _) in TOOLS.items() if server == name]

    @app.post("/mcp")
    async def mcp(request: Request):
        rid, method, tool, args = await fields(request)
        try:
            claims = authenticate(request, mode, name)
            if method == "tools/list": return reply(rid, {"tools": [defs[t] for t in mine]})
            if method != "tools/call": return reply(rid, error={"code": -32601, "message": "method not found"})
            if tool not in mine: return reply(rid, error={"code": -32602, "message": "unknown tool"})
            require(claims, TOOLS[tool][1])
            note(trace, name, f"{mode} auth accepted {claims['sub']}" + (f", audience {claims['aud']}, scope {TOOLS[tool][1]}" if mode != "key" else ", full entitlement"))
        except AuthError as e:
            audit.append({"ts": time.time(), "at": name, "sub": None, "tool": tool, "decision": "deny", "reason": e.code})
            note(trace, name, f"refused {e.status} {e.code}: {e.reason}", "fail")
            return challenge(e)
        try:
            out, err = execute(tool, args, claims, plant), False
        except ToolError as e:
            out, err = str(e), True
        audit.append({"ts": time.time(), "at": name, "sub": claims["sub"], "tool": tool, "decision": "error" if err else "allow"})
        note(trace, name, f"{tool} {'failed: ' + out if err else 'ran'} for {claims['sub']}", "fail" if err else "ok")
        return reply(rid, {"content": [{"type": "text", "text": out if err else json.dumps(out)}], "isError": err})

    return app
