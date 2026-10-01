# Agent Tool Gateway

An engineering agent calls four tools (a centrifuge cut-size calculator, an access-controlled document search, a plant tag reader and a setpoint writer) that run on three small tool servers. I sent the same requests through three designs: A, one shared static key; B, the user's token forwarded unchanged; C, a gateway that validates the user's token, exchanges it for a narrow per-server token, checks a scope per tool, holds writes for human approval bound to the exact arguments, pins tool schemas and writes an audit line.

In 15 executed attacks, A held 0, B held 9 and C held 14 (a row is held when the attack does not work). The one C does not stop is a human approving a poisoned but plausible write (row 15).

## Real and Simulated

- The issuer is a mock that runs in the same process. It signs RS256 access tokens, builds a JWKS that the verifiers load in-process (no endpoint serves it) and does an authorization-code exchange with PKCE. There is no browser sign-in, no client registration, no key rotation and no OpenID Connect.
- The protocol is a subset of the Model Context Protocol implemented in this repository, without the official SDK: `tools/list` and `tools/call` over JSON-RPC, with no version negotiation, sessions or streaming. I did not check it against any revision of the specification.
- Every hop is an in-process HTTP request, so latency says nothing about a real identity provider.
- The planner is a script, gullible on purpose: it obeys instructions it finds in tool output, so that prompt injection is reproducible. I kept it scripted for that reason. It makes no claim about how often a real model is fooled.
- A and B are controls built to fail. Two rows (12 and 14) test features only C has.

## Local Setup

Python 3.11 is the only version I ran.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

Bash equivalent:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
```

## Run the Demo

```powershell
python app.py
```

Open `http://127.0.0.1:8000`. The server runs until Ctrl+C (`make demo` does the same).

A two-minute walk through the page:

1. Ana (viewer), design A, "Open the poisoned report", Run. The injected write executes and the result shows `FEED_RATE is now 7.5`.
2. Switch to design C and Run again. The trace ends in `403 insufficient_scope` and the feed rate stays 6.0.
3. Pick Ben (engineer), design C, "Set the feed rate to 8", Run. The write is held and an Approve button appears. After you click it, the trace shows the on-behalf-of token for the plant server and the audit lines.

## Run Tests

```powershell
python -m pytest -q
```

44 tests pass (`make test`). They include the golden attack matrix, which fails if any cell changes, and a test for each security check that fails when that check is removed. `.github/workflows/ci.yml` runs the tests and builds the Docker image on every push.

The browser test needs Chromium (`playwright install chromium`). Without it that one test is skipped.

## Architecture

```
Person ---request---> Agent runtime (planner, MCP client) ---sign-in (PKCE)---+
   |                       |                                                  |
   |                       | user token (audience: gateway)                   v
   |                       v                                              +--------+
   |                  +---------+              exchange                   | Issuer |
   +---Approve------->| Gateway |<--------------------------------------->|        |
      (own token)     +----+----+                                         +--------+
                           | one narrow token per server (audience: that server)
              +------------+------------+
              v            v            v
        calc server   docs server   plant server
        cut_size      search_docs   read_tag, write_setpoint
```

- Person: asks, and approves held writes with a separate token (`gateway.approve`) that the agent never requests. That is a convention here (see Limitations).
- Agent runtime: planner plus MCP client, a component separate from the servers (the same process in this demo). Injection reaches it, so nothing it decides is trusted.
- Gateway: the enforcement point outside the model (token check, scope per tool, approval hold, token exchange, schema pin, audit).
- Issuer: signs tokens and does the on-behalf-of exchange. Every service trusts only its key.
- Servers: each accepts only a token whose audience is itself and checks its own scope. The docs server takes groups from the token. The plant server checks range and step size.

Request flow, design C:

1. The agent calls `tools/list` with no token. The gateway answers `401` with `WWW-Authenticate: resource_metadata=...`.
2. The agent reads `/.well-known/oauth-protected-resource`, finds the authorization server, signs in with an authorization code and PKCE, and gets a token for audience `api://gateway`.
3. On `tools/list` the gateway exchanges the token per server, fetches each tool list and withholds any tool whose schema hash differs from its pin.
4. The planner picks a tool and the agent sends `tools/call` with the user token.
5. The gateway verifies the RS256 signature, issuer, expiry and audience, then the scope for that tool.
6. For a write, the gateway answers `409` with an approval id and the exact arguments. The person clicks Approve, which uses the approver token. The agent retries with the id. The hash of (user, tool, arguments) must match, and an approval works once.
7. The gateway exchanges the token for one valid at a single server (scope = user AND server AND requested, 120 s).
8. The server verifies audience and scope, runs the tool and logs the user.
9. The gateway writes an audit line and returns the result.

## Repository Structure

```text
toolgate/auth.py       Mock issuer and token verifier
toolgate/tools.py      d100 physics, TF-IDF search, plant simulation
toolgate/servers.py    The three tool servers, in three trust modes
toolgate/gateway.py    Design C
toolgate/agent.py      Planner, agent loop and the world for each design
toolgate/attacks.py    The executed attacks
app.py, web/           Demo API and page
bench.py               Cost per call
tests/, conftest.py    Unit tests, golden attack matrix, one browser test
data/docs.json         16 synthetic notes: 12 public (one carries the injected instruction), 4 restricted to the engineering group
Makefile               demo, test, matrix and bench targets
requirements.txt       Runtime dependencies, pinned (requirements-dev.txt adds the test tools)
Dockerfile, docker-compose.yml   The demo in a container
.github/workflows/ci.yml         Tests and image build
```

## Results

All figures are from 30 September 2026 (Python 3.11.15, FastAPI 0.142.2, PyJWT 2.15.1, 2 vCPU Xeon 2.1 GHz VM).

### Attack matrix

```powershell
python -m toolgate.attacks
```

`make matrix` runs the same command. Rerunning gives the same rows; only the date in the header changes.

```
Attack matrix (30 September 2026, Python 3.11.15, FastAPI 0.142.2, PyJWT 2.15.1)
    attack                                                        A shared key    B forwarded     C gateway
 1. Anonymous write, no token                                     EXECUTES        blocked         blocked
 2. Forged signature (viewer edits her scope)                     EXECUTES        blocked         blocked
 3. Token with alg=none                                           EXECUTES        blocked         blocked
 4. HS256 token signed with the public key                        EXECUTES        blocked         blocked
 5. Genuine token issued for another API                          EXECUTES        EXECUTES        blocked
 6. Trusted key, other issuer                                     EXECUTES        blocked         blocked
 7. Expired token                                                 EXECUTES        blocked         blocked
 8. Valid token sent in the query string                          EXECUTES        EXECUTES        blocked
 9. Viewer's write via poisoned document                          EXECUTES        blocked         blocked
10. Compromised docs server replays its credential at the plant   EXECUTES        EXECUTES        blocked
11. Model-supplied groups in a search call                        EXECUTES        blocked         blocked
12. Engineer's write without approval                             EXECUTES        EXECUTES        blocked
13. Write not attributable to a user in any audit line            NOT ATTRIBUTED  attributed      attributed
14. Tool description changed after review reaches the planner     EXECUTES        EXECUTES        blocked
15. Engineer approves a poisoned, in-range write                  EXECUTES        EXECUTES        EXECUTES (NOT PROTECTED)
    held, of 15                                                   0               9               14

Restricted notes returned to the viewer over 20 queries: A=19, B=0, C=0
```

Each row runs against a fresh copy of each design. EXECUTES means the plant moved to 7.5, a restricted note came back, or the changed description reached the planner; NOT ATTRIBUTED means no audit line named the user. A "blocked" cell means the check stopped this attack here and says nothing further about C's security.

In A the tool servers see only the key, so a token presented to the agent is never looked at. B's servers verify signature, issuer, expiry and scope but cannot check audience, because one token must work everywhere. They also accept `?access_token=` (RFC 6750), which is a modeling choice.

### The cut-size tool

`cut_size` example: bowl r2 0.20 m, liquid surface r1 0.15 m, L 0.80 m, 3000 rpm, 10 m3/h, silica 2650 kg/m3 in water at 20 C. Sigma is 1538.67 m2, d100 is 1.4178 um and the wall Reynolds number is 0.00513. I computed the same values independently by integrating the worst-case particle trajectory numerically; the tests hard-code them. Sigma is the exact logarithmic form (the thin-pool shortcut gives 0.7% more). d100 is the size above which every particle is captured under plug flow, not the d50 that catalogs call the cut size. At 200 m3/h the Reynolds guard refuses (0.46 above 0.3). This checks the algebra, not the model against experiment.

### Cost per call

```powershell
python bench.py
```

`make bench` runs the same command. I ran it five times on the final code on a shared VM with other jobs running (load average about 4, so the p95 values are inflated by scheduling). The ordering A < B < C and cached < uncached held in all five runs. Medians ranged from 0.30 to 0.38 ms for A, 0.47 to 0.73 ms for B, 1.90 to 2.50 ms for C and 0.91 to 1.40 ms for C with the exchanged token cached. Fifth run:

```
Gateway cost per read_tag call, 300 calls each (30 September 2026, Python 3.11.15, FastAPI 0.142.2, PyJWT 2.15.1)
A shared key                        median    0.33 ms   p95   0.674 ms
B forwarded token                   median   0.562 ms   p95   1.245 ms
C gateway                           median   1.913 ms   p95   6.835 ms
C gateway, exchanged token cached   median   1.249 ms   p95   6.451 ms
```

C costs roughly 1.6 to 2.2 ms more per call than A in these runs, before any real identity provider round trip.

My reading: a pure calculator can sit on A, the cheapest design. Data access and writes belong on C. Row 15 is not protected: an engineer who approves a poisoned but plausible write gets it executed, and only the tool-side range and step checks remain.

## Using a Model Instead of the Script

`LLM=openai` replaces the scripted planner with an OpenAI-compatible chat endpoint such as LM Studio. It reads `OPENAI_BASE_URL`, `OPENAI_MODEL` and, if the endpoint wants one, `OPENAI_API_KEY`.

```powershell
$env:LLM = "openai"; $env:OPENAI_BASE_URL = "http://127.0.0.1:1234/v1"; $env:OPENAI_MODEL = "local-model"
python app.py
```

Bash equivalent:

```bash
LLM=openai OPENAI_BASE_URL=http://127.0.0.1:1234/v1 OPENAI_MODEL=local-model python app.py
```

I only parsed a fake reply in a test; I have not run it against a real endpoint.

## Docker

```powershell
docker compose up --build
```

serves the same UI on `127.0.0.1:8000`. The image sets `HOST=0.0.0.0` so the port can be published, and compose publishes it on `127.0.0.1` only. CI builds the image and does not start it (see Limitations).

## Design Choices and the Azure Mapping

- Custom gateway or Azure API Management: API Management has a `validate-jwt` policy that checks a token's signature, expiry, issuer and audience. Approval binding and schema pinning are custom here, and I did not check whether API Management could carry them.
- Container Apps or Azure Kubernetes Service: Container Apps is enough for a few small services. Kubernetes adds control this project does not need.
- Shared or delegated identity: shared (A) is right for tools with no user data. Delegated (B, C) is needed for per-user data and audit. Delegated cannot run unattended without a user token.

The Azure mapping below is not validated: nothing in it was run, and I did not check whether each service is generally available or in preview. What Entra ID, API Management and Azure AI Search do, as stated here, I read on Microsoft Learn on 30 September 2026.

- Issuer: Microsoft Entra ID, one app registration per API. Its documented on-behalf-of flow lets a middle-tier API exchange the caller's token for one for a downstream API, authenticating with a secret or certificate.
- Gateway: Azure API Management in front of the servers, plus custom code for approvals and pins.
- Agent runtime: Foundry Agent Service or Microsoft Agent Framework, or a container on Azure Container Apps. Servers also on Container Apps.
- Remaining secrets (design A's key): Azure Key Vault. Audit: Application Insights or Log Analytics.
- `search_docs`: Azure AI Search, whose documented security-filter pattern filters results by group ids stored on each document, in place of the TF-IDF toy.

## Limitations

- I chose the attacks while building the defenses. The matrix shows these checks stopping these attacks; it is no proof that C is secure. A design A deployment with a login on the agent's own front door would stop rows 1 to 4, 6 and 7 there; A as built has none.
- A compromised gateway or issuer is a total loss. The mock issuer has no client registrations and does not authenticate its callers, which Microsoft Entra ID does for a confidential client. Any code in the process can therefore ask it for a token for another audience such as `api://plant`, or for `gateway.approve`, and go around the gateway and its approval. That the agent does neither is a convention here; a deployment would also keep the servers unreachable except from the gateway. The Approve endpoint mints the approver token itself, so the click is not authenticated, and that token is not bound to one approval. The demo API has no CSRF protection and binds to 127.0.0.1.
- The schema pin is checked when tools are listed, and a changed tool is refused only after a list has flagged it. A server that changes behavior without changing its schema is not detected. Only name, description and input schema are hashed, and only those are forwarded. The `resource_metadata` URL in a 401 is built from the request's Host header.
- Not built: image input. Text read from an image (OCR, captions) would be untrusted tool output, like any tool result.
- The planner is scripted. Retrieval is a 16-note TF-IDF toy used for access control, not RAG, and I make no retrieval-quality claim. Data is synthetic. The physics is a pool only (no scroll, cone or hindered settling).
- One process, in-memory approvals and exchanged tokens (pending approvals are never evicted), no rate limits. An approval covers the arguments, not the plant state at execution time; the tool-side range and step checks bound the effect. There is no token binding and no revocation, so a stolen valid user token works until it expires (5 minutes here). The audit log is an in-memory list and is not tamper-evident. I cut the k-shortfall measurement (how many fewer hits come back when results are filtered after ranking).
- Not validated: running the built image and `docker compose up` (CI builds the image and does not start it); the PowerShell commands on Windows (CI runs on Ubuntu); Python versions other than 3.11; `LLM=openai` against a real LM Studio or Azure OpenAI in Foundry Models endpoint; interoperability with the official MCP client; every Azure mapping above.
