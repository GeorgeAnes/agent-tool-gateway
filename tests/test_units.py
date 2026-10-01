import json

import httpx
import pytest

from toolgate import agent
from toolgate.agent import BOWL, World, call_tool, rpc
from toolgate.tools import ToolError, cut_size, fresh_plant, search_docs, write_setpoint

pytestmark = pytest.mark.anyio
# Worked example, computed independently of cut_size(): RK4 integration of the worst-case particle trajectory
# (starts at r_liquid, radial speed k w^2 r, axial plug-flow speed Q / (pi (r2^2 - r1^2))) with bisection on the diameter.
# Bowl r2 0.20 m, r1 0.15 m, L 0.80 m, 3000 rpm, 10 m3/h, silica 2650 kg/m3 in water 998.2 kg/m3, 1.002 mPa s.
EXAMPLE = {**BOWL, "flow_m3_h": 10}

def test_worked_example_and_reynolds_guard():
    r = cut_size(EXAMPLE)
    assert r["sigma_m2"] == pytest.approx(1538.67, rel=1e-4)
    assert r["d100_um"] == pytest.approx(1.4178, rel=1e-4)
    assert r["re_wall"] == pytest.approx(0.00513, rel=1e-2)
    assert r["g_level_wall"] == pytest.approx(2012.8, rel=1e-4)
    with pytest.raises(ToolError, match="Reynolds number at the wall is 0.46"):
        cut_size({**EXAMPLE, "flow_m3_h": 200})

@pytest.mark.parametrize("bad", [{"rpm": float("nan")}, {"rpm": True}, {"flow_m3_h": -1}, {"r_liquid_m": 0.25}, {"rho_particle": 900}, {"viscosity_pa_s": "1"}])
def test_cut_size_rejects_implausible_inputs(bad):
    with pytest.raises(ToolError):
        cut_size({**EXAMPLE, **bad})

@pytest.mark.parametrize("args, why", [({"tag": "FEED_RATE", "value": 99}, "must be a number in"), ({"tag": "FEED_RATE", "value": 10}, "exceeds"),
                                       ({"tag": "BOWL_SPEED", "value": 3100}, "read-only"), ({"tag": "NOPE", "value": 1}, "unknown tag"),
                                       ({"tag": "FEED_RATE", "value": True}, "must be a number"), ({"tag": ["FEED_RATE"], "value": 8}, "unknown tag")])
def test_write_setpoint_checks_hold_under_every_design(args, why):
    plant = fresh_plant()
    with pytest.raises(ToolError, match=why):
        write_setpoint(plant, args)
    assert plant["FEED_RATE"]["value"] == 6.0
    assert write_setpoint(plant, {"tag": "FEED_RATE", "value": 8})["value"] == 8.0

def test_search_filters_before_ranking():
    q = "bowl imbalance root cause"
    assert {d["id"] for d in search_docs(q, ["public", "engineering"])} >= {"d13", "d16"}
    assert not {d["id"] for d in search_docs(q, ["public"])} & {"d13", "d14", "d15", "d16"}
    assert search_docs("anything", []) == []

async def test_jsonrpc_subset_errors():
    w, key = World("A"), agent.STATIC_KEY
    assert (await rpc(w.clients["calc"], "tools/list", cred="wrong"))[0] == 401
    assert [(await rpc(w.clients["calc"], m, p, cred=key))[1]["error"]["code"] for m, p in (("resources/list", {}), ("tools/call", {"name": "read_tag"}))] == [-32601, -32602]
    for raw in (b"not json", b'{"method": "tools/call", "params": [1]}', b'{"method": "tools/call", "params": {"name": ["x"], "arguments": 5}}'):
        r = await w.clients["calc"].post("/mcp", content=raw, headers={"Authorization": f"Bearer {key}"})
        assert r.status_code == 200 and "error" in r.json()  # never a 500
    st, body, _ = await call_tool(w, "cut_size", {**EXAMPLE, "rpm": -5}, None)
    assert st == 200 and body["result"]["isError"] and "rpm must be" in body["result"]["content"][0]["text"]

async def test_llm_planner_parses_an_openai_style_reply(monkeypatch):
    """Shape check against a fake endpoint only. No real LM Studio or Azure OpenAI in Foundry Models endpoint was available."""
    reply = {"choices": [{"message": {"tool_calls": [{"function": {"name": "read_tag", "arguments": json.dumps({"tag": "FEED_RATE"})}}]}}]}
    real = httpx.AsyncClient
    monkeypatch.setattr(agent.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=reply))))
    monkeypatch.setenv("OPENAI_BASE_URL", "http://lm.local/v1")
    monkeypatch.setenv("OPENAI_MODEL", "local")
    run = agent.Run(World("A"), "ben", "What is the feed rate?")
    assert await agent.llm_plan(run) == ("call", "read_tag", {"tag": "FEED_RATE"})
