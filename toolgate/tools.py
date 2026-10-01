"""The tool logic behind the three servers: no HTTP and no auth in here."""
import json
import math
import re
from collections import Counter
from copy import deepcopy
from pathlib import Path

G = 9.80665
DOCS = json.loads((Path(__file__).parent.parent / "data" / "docs.json").read_text())
RESTRICTED = {d["id"] for d in DOCS if "public" not in d["acl"]}

class ToolError(Exception):
    """The arguments are wrong or physically implausible. Returned to the caller as a tool error."""

def num(args, key, lo, hi):
    v = args.get(key)
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:  # NaN and inf fail too
        raise ToolError(f"{key} must be a number in [{lo}, {hi}]")
    return float(v)

def cut_size(a):
    """Critical diameter d100 of a cylindrical centrifuge pool by sigma theory, derived from first principles.

    Assumptions: dilute suspension (no hindered settling), spherical particles, laminar Stokes settling (checked below),
    plug flow along the axis, no scroll or cone, and the worst-case particle enters at the liquid surface r1.
    w = angular speed, drho = particle minus fluid density, mu = viscosity, Q = flow.
    1. Stokes drag 3 pi mu d v balances centrifugal force minus buoyancy (pi/6) d^3 drho w^2 r, so v_r = k w^2 r with
       k = drho d^2 / (18 mu). At 1 g the same particle settles at v_g = k g.
    2. Radial travel r1 to r2 takes t_s = integral dr / (k w^2 r) = ln(r2/r1) / (k w^2).
    3. Plug flow through the annulus gives residence time t_r = pi L (r2^2 - r1^2) / Q.
    4. Capture needs t_r >= t_s, i.e. Q <= v_g Sigma with Sigma = pi L w^2 (r2^2 - r1^2) / (g ln(r2/r1)). This is the exact
       logarithmic form for this pool; the thin-pool shortcut 2 pi L w^2 r_mean^2 / g is 0.7% higher in the worked example.
    5. The smallest particle captured is d100 = sqrt(18 mu Q / (drho g Sigma)): the size above which every particle is
       captured under these assumptions. It is not the d50 that catalogs call the cut size (d50 is smaller).
    Guard: particle Reynolds number at the wall rho_f v d / mu must stay below 0.3 for Stokes drag to hold.
    """
    r2, r1, L = num(a, "r_outer_m", 0.005, 1.0), num(a, "r_liquid_m", 0.001, 1.0), num(a, "length_m", 0.01, 5.0)
    rpm, Q = num(a, "rpm", 50, 30000), num(a, "flow_m3_h", 0.001, 500) / 3600
    rho_p, rho_f, mu = num(a, "rho_particle", 100, 20000), num(a, "rho_fluid", 500, 2000), num(a, "viscosity_pa_s", 1e-4, 10)
    if r1 >= r2: raise ToolError("r_liquid_m must be smaller than r_outer_m")
    if rho_p <= rho_f: raise ToolError("particles must be denser than the fluid (flotation is not modeled)")
    w, drho = rpm * 2 * math.pi / 60, rho_p - rho_f
    sigma = math.pi * L * w * w * (r2 * r2 - r1 * r1) / (G * math.log(r2 / r1))
    d = math.sqrt(18 * mu * Q / (drho * G * sigma))
    re = rho_f * (drho * d * d * w * w * r2 / (18 * mu)) * d / mu
    if re > 0.3: raise ToolError(f"Stokes settling is not valid here: Reynolds number at the wall is {re:.2f}, limit 0.3")
    return {"sigma_m2": round(sigma, 2), "d100_um": round(d * 1e6, 4), "re_wall": round(re, 5), "g_level_wall": round(w * w * r2 / G, 1)}

STOP = set("a an and are at be by for from in is it of on or the to with".split())

def _tok(s):
    return [t for t in re.findall(r"[a-z0-9]+", s.lower()) if t not in STOP]

def search_docs(query, groups, k=3):
    """TF-IDF and cosine over 16 notes. Only notes whose ACL meets `groups` are ranked at all (filter before ranking).
    `groups` comes from the caller's verified token, never from tool arguments."""
    pool = [d for d in DOCS if set(d["acl"]) & set(groups)]
    df = Counter(t for d in pool for t in set(_tok(d["title"] + " " + d["text"])))
    idf = lambda t: math.log((1 + len(pool)) / (1 + df[t])) + 1
    vec = lambda s: {t: n * idf(t) for t, n in Counter(_tok(s)).items()}
    q = vec(query)

    def score(d):
        v = vec(d["title"] + " " + d["text"])
        return sum(q[t] * v[t] for t in q if t in v) / (math.hypot(*q.values()) * math.hypot(*v.values()) or 1)

    ranked = sorted(((score(d), d) for d in pool), key=lambda x: -x[0])[:k]
    return [{"id": d["id"], "title": d["title"], "text": d["text"]} for s, d in ranked if s > 0]

TAGS = {
    "FEED_RATE": dict(value=6.0, unit="m3/h", writable=True, lo=2.0, hi=10.0, step=3.0),
    "BOWL_SPEED": dict(value=3000.0, unit="rpm", writable=False),
    "TORQUE": dict(value=62.0, unit="percent", writable=False),
}

def fresh_plant():
    return deepcopy(TAGS)

def _tag(plant, a):
    if not isinstance(a.get("tag"), str) or a["tag"] not in plant: raise ToolError(f"unknown tag; known tags: {', '.join(plant)}")
    return plant[a["tag"]]

def read_tag(plant, a):
    t = _tag(plant, a)
    return {"tag": a["tag"], "value": t["value"], "unit": t["unit"]}

def write_setpoint(plant, a):
    """Tool-side checks that hold under every design: writable tag, inside [lo, hi], at most `step` from the current value."""
    t = _tag(plant, a)
    if not t["writable"]: raise ToolError(f"{a['tag']} is read-only")
    v = num(a, "value", t["lo"], t["hi"])
    if abs(v - t["value"]) > t["step"]:
        raise ToolError(f"change of {abs(v - t['value']):.1f} exceeds the {t['step']} allowed per write")
    t["value"] = v
    return {"tag": a["tag"], "value": v, "unit": t["unit"]}

def _schema(**props):
    return {"type": "object", "properties": {k: {"type": v} for k, v in props.items()}, "required": list(props)}

# name: (server, required scope, risk tier). One table read by the servers (scope) and the gateway (scope and tier).
TOOLS = {"cut_size": ("calc", "calc.run", "low"), "search_docs": ("docs", "docs.read", "data"),
         "read_tag": ("plant", "plant.read", "data"), "write_setpoint": ("plant", "plant.write", "write")}
_D = {  # name: (description, input properties)
    "cut_size": ("Smallest particle diameter (d100, micrometers) fully captured by a cylindrical centrifuge pool at a given flow, by sigma theory with a Stokes Reynolds-number check.",
                 dict(r_outer_m="number", r_liquid_m="number", length_m="number", rpm="number", flow_m3_h="number", rho_particle="number", rho_fluid="number", viscosity_pa_s="number")),
    "search_docs": ("Search plant notes the caller is allowed to read. Returns up to 3 notes.", dict(query="string")),
    "read_tag": ("Read the current value of a plant tag.", dict(tag="string")),
    "write_setpoint": ("Write a new setpoint to a writable plant tag.", dict(tag="string", value="number")),
}
DEFS = {n: dict(name=n, description=d, inputSchema=_schema(**p)) for n, (d, p) in _D.items()}
