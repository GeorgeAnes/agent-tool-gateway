"""Design C: the gateway in front of the tool servers. One short method per job:
authenticate, authorize (scope per tool), hold (human approval bound to the exact arguments),
exchange (narrow on-behalf-of token per server), pin (tool-schema hash), audit."""
import hashlib
import json
import secrets
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import note
from .auth import AUD, AuthError, obo, require, resource_metadata, verify
from .servers import bearer, challenge, fields, reply
from .tools import TOOLS

def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

PINNED = ("name", "description", "inputSchema")  # the only tool fields that are hashed, and the only ones forwarded

def schema_hash(tool):
    return digest({k: tool.get(k) for k in PINNED})

class Hold(Exception): """Raised when a risky call needs a human to approve it first."""

class Gateway:
    def __init__(self, servers, pins, audit, trace, cache=False):
        self.servers, self.pins, self.audit, self.trace = servers, pins, audit, trace
        self.pending, self.quarantine = {}, set()  # ponytail: pending approvals and quarantine are never evicted; an engineer's token can add entries without limit
        self.cache = {} if cache else None  # (user token, server, scope) -> (obo token, expiry)
        self.app = FastAPI()
        self.app.get("/.well-known/oauth-protected-resource")(lambda: resource_metadata(AUD["gateway"]))
        self.app.post("/mcp")(self.mcp)
        self.app.post("/approvals/{aid}/approve")(self.approve)

    # job 1: who is calling? Header only, RS256, issuer, expiry, audience = this gateway.
    def authenticate(self, request):
        token = bearer(request, allow_query=False) or ""
        claims = verify(token, AUD["gateway"])
        note(self.trace, "gateway", f"token valid: RS256, issuer, expiry, audience {claims['aud']}; sub={claims['sub']}")
        return token, claims

    # job 2: may this user call this tool? One scope per tool.
    def authorize(self, claims, tool):
        require(claims, TOOLS[tool][1])
        note(self.trace, "gateway", f"scope {TOOLS[tool][1]} present for {tool}")

    # job 3: risky calls wait for a human. The approval is bound to (user, tool, exact arguments) and works once.
    def hold(self, claims, tool, args, aid):
        h = digest([claims["sub"], tool, args])
        if not aid:
            aid = secrets.token_urlsafe(8)
            note(self.trace, "gateway", f"{tool} is risk tier 'write': needs approval of these exact arguments")
            self.pending[aid] = dict(sub=claims["sub"], tool=tool, args=args, hash=h, exp=time.time() + 300, approved=False)
            raise Hold(aid, h)
        rec = self.pending.get(aid)
        why = ("unknown_or_used" if not rec else "expired" if rec["exp"] < time.time() else "wrong_user" if rec["sub"] != claims["sub"]
               else "not_approved" if not rec["approved"] else "arguments_changed" if rec["hash"] != h else None)
        if why: raise AuthError(403, "approval_invalid", why)
        del self.pending[aid]
        note(self.trace, "gateway", f"approval {aid} matches user, tool and exact arguments; consumed")

    # job 4: swap the user's token for one that works at a single server and carries a single scope.
    def exchange(self, token, server, scopes):
        k = (token, server, tuple(scopes))
        if self.cache is not None and self.cache.get(k, (0, 0))[1] > time.time() + 10: return self.cache[k][0]
        out = obo(token, server, scopes)
        if self.cache is not None:  # ponytail: expired entries are dropped on insert; live ones (120 s) are not capped
            self.cache = {a: b for a, b in self.cache.items() if b[1] > time.time()}
            self.cache[k] = (out, time.time() + 120)
        return out

    # job 5: tool descriptions are pinned. A tool whose schema hash changed is not shown and not callable.
    async def tools(self, token):
        out = []
        for server, client in self.servers.items():
            r = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                                  headers={"Authorization": "Bearer " + self.exchange(token, server, [])})
            for t in r.json().get("result", {}).get("tools", []):
                if schema_hash(t) == self.pins.get(t["name"]):
                    out.append({k: t[k] for k in PINNED})  # extra fields (title, annotations) are not covered by the hash, so they are dropped
                else:
                    self.quarantine.add(t["name"])
                    self.log({"sub": None}, t["name"], server, "deny", "schema_changed")
        note(self.trace, "gateway", f"tools/list: {len(out)} tools match their pinned schema hash" + (f"; withheld {sorted(self.quarantine)}" if self.quarantine else ""),
             "fail" if self.quarantine else "ok")
        return out

    # job 6: one audit line per decision, with the user.
    def log(self, claims, tool, server, decision, reason=""):
        line = {"ts": round(time.time(), 3), "at": "gateway", "sub": claims.get("sub"), "tool": tool, "server": server, "decision": decision, "reason": reason}
        self.audit.append(line)
        note(self.trace, "gateway", "audit " + json.dumps({k: v for k, v in line.items() if k != "ts" and v}),
             {"allow": "ok", "approved": "ok", "hold": "hold"}.get(decision, "fail"))

    async def mcp(self, request: Request):
        rid, method, tool, args = await fields(request)
        claims, server = {}, None
        meta = str(request.base_url) + ".well-known/oauth-protected-resource"  # ponytail: built from the Host header; a deployment would configure the public URL
        try:
            token, claims = self.authenticate(request)
            if method == "tools/list": return reply(rid, {"tools": await self.tools(token)})
            if method != "tools/call" or tool not in TOOLS:
                return reply(rid, error={"code": -32602, "message": "unknown method or tool"})
            server, scope, tier = TOOLS[tool]
            if tool in self.quarantine: raise AuthError(403, "schema_changed", tool)
            self.authorize(claims, tool)
            if tier == "write":
                self.hold(claims, tool, args, request.headers.get("x-approval-id"))
            otoken = self.exchange(token, server, [scope])
            note(self.trace, "issuer", f"on-behalf-of token for {server}: audience {AUD[server]}, scope {scope}, sub {claims['sub']}")
            call = {"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": {"name": tool, "arguments": args}}  # only the validated fields are forwarded
            r = await self.servers[server].post("/mcp", json=call, headers={"Authorization": "Bearer " + otoken})
            self.log(claims, tool, server, "allow" if r.status_code == 200 else "deny", "" if r.status_code == 200 else f"server {r.status_code}")
            return JSONResponse(r.json(), r.status_code)
        except AuthError as e:
            self.log(claims, tool, server, "deny", f"{e.code}: {e.reason}")
            return challenge(e, meta)
        except Hold as h:
            aid, digest_ = h.args
            self.log(claims, tool, server, "hold", "approval_required")
            return JSONResponse({"error": "approval_required", "approval_id": aid, "tool": tool, "arguments": args, "args_sha256": digest_}, 409)

    async def approve(self, aid: str, request: Request):
        try:  # a separate grant with scope gateway.approve: the agent's token never has it
            c = verify(bearer(request, False) or "", AUD["gateway"], "gateway.approve")
        except AuthError as e:
            return challenge(e)
        rec = self.pending.get(aid)
        if not rec or rec["sub"] != c["sub"]: return JSONResponse({"error": "not_your_approval"}, 403)
        rec["approved"] = True
        self.log(c, rec["tool"], TOOLS[rec["tool"]][0], "approved", aid)
        return {"approved": aid, "tool": rec["tool"], "arguments": rec["args"], "args_sha256": rec["hash"]}
