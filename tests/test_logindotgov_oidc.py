import pytest
from unittest.mock import patch, MagicMock
from jwcrypto import jwk
from logindotgov.oidc import LoginDotGovOIDCClient, LoginDotGovOIDCError, LoginDotGovOIDCCodeError, LoginDotGovOIDCStateError, LoginDotGovOIDCNonceError, LoginDotGovOIDCAccessTokenError, IAL1, IAL2, MOCK_URL, encode_left128bits, SIGNING_ALGO
from urllib.parse import urlparse, parse_qs
import pprint
from jwcrypto.common import json_decode
import jwt
from requests.exceptions import RequestException
import time
import logging

client_private_key_jwk = jwk.JWK.generate(kty="RSA", size=4096)
client_private_key = client_private_key_jwk.export_to_pem(True, None).decode("utf-8")
client_public_key_jwk = jwk.JWK()
client_public_key_jwk.import_key(**json_decode(client_private_key_jwk.export_public()))
client_public_key = client_public_key_jwk.export_to_pem().decode("utf-8")
state = "statestatestatestatestate"
nonce = "noncenoncenoncenoncenonce"
client_id = "urn:myapp"
redirect_uri = "https://myapp.example.gov/auth/result"

############################################################
# mock login.gov OIDC server

access_token = "the-access-token"
auth_code = "the-code"
server_private_key_jwk = jwk.JWK.generate(kty="RSA", size=4096)
server_private_key_attrs = json_decode(server_private_key_jwk.export_public())
server_private_key_pem = server_private_key_jwk.export_to_pem(True, None).decode("utf-8")
server_public_key_jwk = jwk.JWK()
server_public_key_jwk.import_key(**server_private_key_attrs)
server_public_key = server_public_key_jwk.export_public(True)
server_public_key_pem = server_public_key_jwk.export_to_pem().decode("utf-8")
token_endpoint = f"{MOCK_URL}api/openid_connect/token"

class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data

    def raise_for_status(self):
        if self.status_code != 200:
            raise RequestException("oops")
        return None

def mock_oidc_config_endpoint():
    config = {
        "authorization_endpoint": f"{MOCK_URL}openid_connect/authorize",
        "jwks_uri": f"{MOCK_URL}api/openid_connect/certs",
        "token_endpoint": token_endpoint,
        "userinfo_endpoint": f"{MOCK_URL}api/openid_connect/userinfo",
    }
    return MockResponse(config, 200)

def mock_oidc_certs_endpoint():
    return MockResponse({"keys": [ {**server_public_key, "kid": server_public_key_jwk.thumbprint()} ] }, 200)

def mock_oidc_userinfo_endpoint(args):
    if "headers" not in args or args["headers"] != {'Authorization': 'Bearer the-access-token'}:
        return MockResponse({"error": "missing or invalid Bearer"}, 401)

    return MockResponse({"sub": "the-users-uuid", "iss": MOCK_URL, "email": "you@example.gov"}, 200)

def mock_oidc_token_endpoint(payload):
    client_assertion = payload["client_assertion"]
    client_jwt = jwt.decode(client_assertion, client_public_key, audience=[token_endpoint], algorithms=[SIGNING_ALGO])
    if client_jwt["iss"] != client_id:
        raise Exception("client_id mismatch")
    # TODO check aud

    args = {
        "iss": MOCK_URL,
        "sub": "the-users-uuid",
        "aud": client_id,
        "acr": IAL1,
        "at_hash": encode_left128bits(access_token),
        "c_hash": encode_left128bits(auth_code),
        "exp": time.time() + 60,
        "iat": time.time(),
        "jti": "a-secret-unique-key",
        "nbf": time.time(),
        "nonce": nonce,
    }
    id_token = jwt.encode(args, server_private_key_pem, algorithm=SIGNING_ALGO, headers={"kid": server_public_key_jwk.thumbprint()})
    resp = {
        "id_token": id_token,
        "expires_in": 60,
        "token_type": "Bearer",
        "access_token": access_token,
    }
    return MockResponse(resp, 200)

def mocked_logindotdov_oidc_server(*args, **kwargs):
    if "/authorize" in args[0]:
        redirect_to = "TODO"
        return MockResponse(f"{redirect_to}?code={auth_code}&state={state}", 302)

    if "/openid-configuration" in args[0]:
        return mock_oidc_config_endpoint()

    if "/certs" in args[0]:
        return mock_oidc_certs_endpoint()

    if "/token" in args[0]:
        return mock_oidc_token_endpoint(kwargs["data"])

    if "/userinfo" in args[0]:
        return mock_oidc_userinfo_endpoint(kwargs)

    return MockResponse("oops", 404)

@patch("logindotgov.oidc.requests.get", new=MagicMock(side_effect=mocked_logindotdov_oidc_server))
def test_init():
    config = LoginDotGovOIDCClient.discover()
    client = LoginDotGovOIDCClient(config=config, client_id=client_id, private_key=client_private_key)
    assert client

@patch("logindotgov.oidc.requests.get", new=MagicMock(side_effect=mocked_logindotdov_oidc_server))
def test_build_authorization_url():
    client = LoginDotGovOIDCClient(client_id=client_id, private_key=client_private_key)
    login_uri = client.build_authorization_url(state=state, nonce=nonce, redirect_uri=redirect_uri)
    #print("login_uri={}".format(login_uri))
    login_uri_parsed = urlparse(login_uri)
    #print("login_uri_parsed={}".format(pprint.pformat(login_uri_parsed)))
    query = parse_qs(login_uri_parsed.query)
    #print("query={}".format(pprint.pformat(query)))
    assert query == {
        'acr_values': ['http://idmanagement.gov/ns/assurance/ial/1'],
        'client_id': ['urn:myapp'],
        'nonce': ['noncenoncenoncenoncenonce'],
        'prompt': ['select_account'],
        'redirect_uri': ['https://myapp.example.gov/auth/result'],
        'response_type': ['code'],
        'scope': ['openid email'],
        'state': ['statestatestatestatestate']
    }
    assert login_uri_parsed.netloc == 'mockhost.login.gov'
    assert login_uri_parsed.path == '/openid_connect/authorize'

@patch("logindotgov.oidc.requests.get", new=MagicMock(side_effect=mocked_logindotdov_oidc_server))
def test_validate_code_and_state():
    client = LoginDotGovOIDCClient(client_id=client_id, private_key=client_private_key)
    valid_code, valid_state = client.validate_code_and_state({ "code": auth_code, "state": state })
    assert valid_code == auth_code
    assert valid_state == state

    with pytest.raises(LoginDotGovOIDCError) as e_info:
        client.validate_code_and_state({ "error": "oops", "error_description": "there was a problem" })
    assert str(e_info.value) == "there was a problem"

    with pytest.raises(LoginDotGovOIDCCodeError) as e_info:
        client.validate_code_and_state({ "state": state })
    assert str(e_info.value) == "Missing code param"

    with pytest.raises(LoginDotGovOIDCStateError) as e_info:
        client.validate_code_and_state({ "code": auth_code })
    assert str(e_info.value) == "Missing state param"

@patch("logindotgov.oidc.requests.get", new=MagicMock(side_effect=mocked_logindotdov_oidc_server))
@patch("logindotgov.oidc.requests.post", new=MagicMock(side_effect=mocked_logindotdov_oidc_server))
def test_tokens():
    logger = logging.getLogger("test_tokens")
    client = LoginDotGovOIDCClient(client_id=client_id, private_key=client_private_key, logger=logger)
    tokens = client.get_tokens(auth_code)
    #print("tokens={}".format(pprint.pformat(tokens)))
    decoded_tokens = client.validate_tokens(tokens, nonce, auth_code)
    #print("decoded_tokens={}".format(pprint.pformat(decoded_tokens)))
    assert decoded_tokens["acr"] == IAL1
    assert decoded_tokens["aud"] == client_id
    assert decoded_tokens["iss"] == MOCK_URL
    assert decoded_tokens["nonce"] == nonce
    assert decoded_tokens["sub"] == 'the-users-uuid'

    with pytest.raises(LoginDotGovOIDCNonceError) as e_info:
        decoded_tokens = client.validate_tokens(tokens, "not-the-nonce", auth_code)
    assert str(e_info.value) == "login.gov nonce does not match client nonce"

    with pytest.raises(LoginDotGovOIDCAccessTokenError) as e_info:
        decoded_tokens = client.validate_tokens({**tokens, "access_token": "not-the-access-token"}, nonce, auth_code)
    assert str(e_info.value) == "login.gov access_token hash does not match access_code"

    with pytest.raises(LoginDotGovOIDCCodeError) as e_info:
        decoded_tokens = client.validate_tokens(tokens, nonce, "not-the-auth-code")
    assert str(e_info.value) == "login.gov code hash does not match initial code"

@patch("logindotgov.oidc.requests.get", new=MagicMock(side_effect=mocked_logindotdov_oidc_server))
@patch("logindotgov.oidc.requests.post", new=MagicMock(side_effect=mocked_logindotdov_oidc_server))
def test_userinfo():
    client = LoginDotGovOIDCClient(client_id=client_id, private_key=client_private_key)
    tokens = client.get_tokens(auth_code)
    decoded_tokens = client.validate_tokens(tokens, nonce, auth_code)
    userinfo = client.get_userinfo(tokens["access_token"])
    assert userinfo == {"sub": "the-users-uuid", "iss": MOCK_URL, "email": "you@example.gov"}

