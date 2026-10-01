"""Mock identity provider, in the same process. It stands in for Microsoft Entra ID.

Real: RS256 signatures, a JWKS document, PKCE (S256), token exchange with scope = user AND server AND requested,
a verifier that pins the algorithm. Mock: no browser or passwords (sign-in is a function call), one key that never
rotates, and obo() does not authenticate its caller the way Microsoft Entra ID authenticates a confidential client.
"""
import base64
import hashlib
import json
import secrets
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER, KID = "https://login.mock/tenant-1", "key-1"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
AUD = {n: f"api://{n}" for n in ("agent", "gateway", "calc", "docs", "plant")}
SERVER_SCOPES = {"calc": ["calc.run"], "docs": ["docs.read"], "plant": ["plant.read", "plant.write"]}
TOOL_SCOPES = [s for v in SERVER_SCOPES.values() for s in v]
ALL_GROUPS = ["public", "engineering"]
USERS = {  # what the directory says about each person; gateway.approve is never requested by the agent
    "ana": {"role": "viewer", "scopes": ["calc.run", "docs.read", "plant.read"], "groups": ["public"]},
    "ben": {"role": "engineer", "scopes": TOOL_SCOPES + ["gateway.approve"], "groups": ["public", "engineering"]},
}

class AuthError(Exception):
    def __init__(self, status, code, reason=""):
        super().__init__(f"{status} {code}: {reason}")
        self.status, self.code, self.reason = status, code, reason

def jwks():
    """The public half of the signing key, as a verifier would download it."""
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
    return {"keys": [{**jwk, "kid": KID, "use": "sig", "alg": "RS256"}]}

_KEYS = jwt.PyJWKSet.from_dict(jwks())

def mint(sub, aud, scp, ttl=300, *, iss=ISSUER, **extra):
    now = int(time.time())
    claims = dict(iss=iss, sub=sub, aud=aud, scp=" ".join(scp), iat=now, exp=now + ttl,
                  jti=secrets.token_hex(8), **extra)
    return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": KID})

def require(claims, scope):
    if scope not in claims.get("scp", "").split(): raise AuthError(403, "insufficient_scope", scope)

def verify(token, audience, scope=None):
    """Signature (RS256 only, key chosen by kid from the JWKS), issuer, expiry, audience, scope.

    audience=None skips the audience check. Only design B's servers do that, and that is its flaw.
    PyJWT reads the wall clock; tests use a negative ttl and leeway stays 0.
    """
    if not token: raise AuthError(401, "invalid_token", "no credential")
    try:
        kid = jwt.get_unverified_header(token).get("kid")
        claims = jwt.decode(token, _KEYS[kid].key, algorithms=["RS256"], issuer=ISSUER, audience=audience,
                            leeway=0, options={"require": ["exp", "iss", "sub", "aud"], "verify_aud": audience is not None})
    except (jwt.PyJWTError, KeyError) as e:
        raise AuthError(401, "invalid_token", type(e).__name__)
    if scope:
        require(claims, scope)
    return claims

CODES = {}

def _s256(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

def authorize(user, resource, scopes, challenge):
    """Scripted 'sign-in' step of the authorization-code flow: returns a one-time code bound to a PKCE challenge."""
    code = secrets.token_urlsafe(16)
    granted = [s for s in scopes if s in USERS[user]["scopes"]]
    CODES[code] = dict(user=user, resource=resource, scp=granted, challenge=challenge, exp=time.time() + 60)
    return code

def exchange_code(code, verifier):
    rec = CODES.pop(code, None)  # single use, even when the verifier is wrong
    if not rec or rec["exp"] < time.time() or not secrets.compare_digest(_s256(verifier), rec["challenge"]):
        raise AuthError(400, "invalid_grant", "unknown code or PKCE verifier mismatch")
    return mint(rec["user"], rec["resource"], rec["scp"], groups=USERS[rec["user"]]["groups"])

def login(user, resource, scopes):
    """What a client does: make a verifier, send its hash, exchange the code with the verifier."""
    verifier = secrets.token_urlsafe(32)
    return exchange_code(authorize(user, resource, scopes, _s256(verifier)), verifier)

def obo(user_token, server, requested):
    """On-behalf-of exchange. Only a token issued for the gateway can be exchanged.
    The new token is for one server and carries scope = user AND server AND requested."""
    c = verify(user_token, AUD["gateway"])
    scp = [s for s in c["scp"].split() if s in SERVER_SCOPES[server] and s in requested]
    if set(requested) - set(scp): raise AuthError(403, "invalid_scope", " ".join(sorted(set(requested) - set(scp))))
    return mint(c["sub"], AUD[server], scp, ttl=120, groups=c["groups"], azp=AUD["gateway"])

def resource_metadata(resource):
    """Body of /.well-known/oauth-protected-resource (RFC 9728): where to get a token for this resource."""
    return {"resource": resource, "authorization_servers": [ISSUER], "scopes_supported": TOOL_SCOPES,
            "bearer_methods_supported": ["header"]}
