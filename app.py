"""The demo page and a small JSON API: `python app.py`, then open http://127.0.0.1:8000"""
import os
import uuid
from pathlib import Path
from typing import Literal

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

import bench
from toolgate import attacks
from toolgate.agent import SCENARIOS, World, advance, approve, start
from toolgate.auth import USERS

app = FastAPI(title="Agent Tool Gateway")
RUNS, MATRIX = {}, {}  # ponytail: in-memory runs (the oldest of 100 is dropped) and one cached matrix; fine for a local demo

class RunReq(BaseModel):
    user: Literal["ana", "ben"]
    design: Literal["A", "B", "C"]
    request: str = Field(max_length=300)

def view(rid, run):
    return {"id": rid, "status": run.status, "answer": run.answer, "pending": run.pending, "trace": run.w.trace,
            "feed_rate": run.w.plant["FEED_RATE"]["value"]}

@app.get("/")
def index():
    return FileResponse(Path(__file__).parent / "web" / "index.html")

@app.get("/api/config")
def config():
    return {"users": [{"id": u, "role": v["role"]} for u, v in USERS.items()], "scenarios": [{"id": i, "label": l, "request": r} for i, l, r in SCENARIOS]}

@app.post("/api/run")
async def run(req: RunReq):
    r = await start(World(req.design), req.user, req.request)
    await advance(r)
    rid = uuid.uuid4().hex[:8]
    RUNS[rid] = r
    if len(RUNS) > 100: del RUNS[next(iter(RUNS))]
    return view(rid, r)

@app.post("/api/approve/{rid}")
async def approve_call(rid: str):
    r = RUNS.get(rid)
    if not r or r.status != "awaiting_approval": raise HTTPException(409, "nothing to approve")
    await approve(r)
    return view(rid, r)

@app.get("/api/matrix")
async def matrix():
    if not MATRIX:
        MATRIX.update(await attacks.everything(), versions=attacks.versions())
        MATRIX["held"] = {d: sum(not x["success"][d] for x in MATRIX["rows"]) for d in "ABC"}
    return MATRIX

@app.post("/api/bench")
async def run_bench():
    return {"versions": attacks.versions(), "n": bench.N, "results": await bench.bench()}

if __name__ == "__main__":
    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=8000)
