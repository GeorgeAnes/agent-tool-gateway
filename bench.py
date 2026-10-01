"""Cost per call of each design over 300 in-process read_tag calls, mock issuer. Says nothing about a real identity provider. `python bench.py`"""
import asyncio
import statistics
import time

from toolgate.agent import World, call_tool
from toolgate.attacks import versions
from toolgate.auth import TOOL_SCOPES, login

N = 300

async def measure(design, cache=False, n=N):
    w = World(design, cache=cache)
    tok = login("ben", w.aud, TOOL_SCOPES)
    for _ in range(20):  # warm-up
        await call_tool(w, "read_tag", {"tag": "FEED_RATE"}, tok)
    ms = []
    for _ in range(n):
        t = time.perf_counter()
        st, _, _ = await call_tool(w, "read_tag", {"tag": "FEED_RATE"}, tok)
        ms.append((time.perf_counter() - t) * 1000)
        assert st == 200
    ms.sort()
    return {"median_ms": round(statistics.median(ms), 3), "p95_ms": round(ms[int(0.95 * n) - 1], 3)}

async def bench():
    return {"A shared key": await measure("A"), "B forwarded token": await measure("B"),
            "C gateway": await measure("C"), "C gateway, exchanged token cached": await measure("C", cache=True)}

if __name__ == "__main__":
    print(f"Gateway cost per read_tag call, {N} calls each ({versions()})")
    for name, r in asyncio.run(bench()).items():
        print(f"{name:<36}median {r['median_ms']:>7} ms   p95 {r['p95_ms']:>7} ms")
