import secrets
import time

import jwt
import pytest

from toolgate.auth import _s256, AUD, CODES, ISSUER, KEY, KID, TOOL_SCOPES, AuthError, authorize, exchange_code, login, obo, verify

GW = AUD["gateway"]

def test_pkce_and_single_use_code():
    v = secrets.token_urlsafe(32)
    code = authorize("ben", GW, TOOL_SCOPES, _s256(v))
    for verifier in ("not-the-verifier", v):  # the failed attempt burns the code, so even the right verifier fails after it
        with pytest.raises(AuthError):
            exchange_code(code, verifier)
    assert verify(exchange_code(authorize("ben", GW, TOOL_SCOPES, _s256(v)), v), GW)["sub"] == "ben"
    late = authorize("ben", GW, TOOL_SCOPES, _s256(v))
    CODES[late]["exp"] = 0
    with pytest.raises(AuthError):
        exchange_code(late, v)

def test_obo_scope_is_user_and_server_and_requested():
    ben, ana = login("ben", GW, TOOL_SCOPES), login("ana", GW, TOOL_SCOPES)
    assert verify(obo(ben, "plant", ["plant.read"]), AUD["plant"])["scp"] == "plant.read"
    for token, server, asked in [(ana, "plant", ["plant.write"]), (ben, "plant", ["docs.read"]), (login("ben", AUD["agent"], TOOL_SCOPES), "plant", ["plant.read"])]:
        with pytest.raises(AuthError):
            obo(token, server, asked)

def test_token_without_expiry_is_refused():
    token = jwt.encode(dict(iss=ISSUER, sub="ben", aud=GW, scp="calc.run", iat=int(time.time())), KEY, algorithm="RS256", headers={"kid": KID})
    with pytest.raises(AuthError, match="MissingRequiredClaimError"):
        verify(token, GW)
