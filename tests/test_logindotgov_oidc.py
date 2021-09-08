import pytest
from unittest.mock import patch, MagicMock
from jwcrypto import jwk
from logindotgov.oidc import (
    LoginDotGovOIDCClient,
    LoginDotGovOIDCError,
    LoginDotGovOIDCCodeError,
    LoginDotGovOIDCStateError,
    LoginDotGovOIDCNonceError,
    LoginDotGovOIDCAccessTokenError,
    IAL1,
    MOCK_URL,
    encode_left128bits,
    SIGNING_ALGO,
)
from logindotgov.mock_server import OIDC as MockServer
from urllib.parse import urlparse, parse_qs, parse_qsl
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

MockServer.register_client(client_id, client_public_key, redirect_uri)

def mocked_logindotdov_oidc_server(*args, **kwargs):
    server = MockServer()
    return server.route_request(args, kwargs)

@patch(
    "logindotgov.oidc.requests.get",
    new=MagicMock(side_effect=mocked_logindotdov_oidc_server),
)
def test_init():
    config = LoginDotGovOIDCClient.discover()
    client = LoginDotGovOIDCClient(
        config=config, client_id=client_id, private_key=client_private_key
    )
    assert client


@patch(
    "logindotgov.oidc.requests.get",
    new=MagicMock(side_effect=mocked_logindotdov_oidc_server),
)
def test_build_authorization_url():
    client = LoginDotGovOIDCClient(client_id=client_id, private_key=client_private_key)
    login_uri = client.build_authorization_url(
        state=state, nonce=nonce, redirect_uri=redirect_uri
    )
    # print("login_uri={}".format(login_uri))
    login_uri_parsed = urlparse(login_uri)
    # print("login_uri_parsed={}".format(pprint.pformat(login_uri_parsed)))
    query = parse_qs(login_uri_parsed.query)
    # print("query={}".format(pprint.pformat(query)))
    assert query == {
        "acr_values": ["http://idmanagement.gov/ns/assurance/ial/1"],
        "client_id": ["urn:myapp"],
        "nonce": ["noncenoncenoncenoncenonce"],
        "prompt": ["select_account"],
        "redirect_uri": ["https://myapp.example.gov/auth/result"],
        "response_type": ["code"],
        "scope": ["openid email"],
        "state": ["statestatestatestatestate"],
    }
    assert login_uri_parsed.netloc == "mockhost.login.gov"
    assert login_uri_parsed.path == "/openid_connect/authorize"


@patch(
    "logindotgov.oidc.requests.get",
    new=MagicMock(side_effect=mocked_logindotdov_oidc_server),
)
def test_validate_code_and_state():
    code = "valid-code"
    state = "valid-state"
    client = LoginDotGovOIDCClient(client_id=client_id, private_key=client_private_key)
    valid_code, valid_state = client.validate_code_and_state(
        {"code": code, "state": state }
    )
    assert valid_code == code
    assert valid_state == state

    with pytest.raises(LoginDotGovOIDCError) as e_info:
        client.validate_code_and_state(
            {"error": "oops", "error_description": "there was a problem"}
        )
    assert str(e_info.value) == "there was a problem"

    with pytest.raises(LoginDotGovOIDCCodeError) as e_info:
        client.validate_code_and_state({"state": state})
    assert str(e_info.value) == "Missing code param"

    with pytest.raises(LoginDotGovOIDCStateError) as e_info:
        client.validate_code_and_state({"code": code})
    assert str(e_info.value) == "Missing state param"


@patch(
    "logindotgov.oidc.requests.get",
    new=MagicMock(side_effect=mocked_logindotdov_oidc_server),
)
@patch(
    "logindotgov.oidc.requests.post",
    new=MagicMock(side_effect=mocked_logindotdov_oidc_server),
)
def test_tokens_and_userinfo():
    logger = logging.getLogger("test_tokens")
    client = LoginDotGovOIDCClient(
        client_id=client_id, private_key=client_private_key, logger=logger
    )
    login_uri = client.build_authorization_url(
        state=state, nonce=nonce, redirect_uri=redirect_uri
    )
    login_uri_parsed = urlparse(login_uri)
    query = dict(parse_qsl(login_uri_parsed.query))
    authorize_response = MockServer.authorize_endpoint(query)
    authorize_parsed = urlparse(authorize_response.json_data)
    code, valid_state = client.validate_code_and_state(dict(parse_qsl(authorize_parsed.query)))
    tokens = client.get_tokens(code)
    # print("tokens={}".format(pprint.pformat(tokens)))
    decoded_tokens = client.validate_tokens(tokens, nonce, code)
    # print("decoded_tokens={}".format(pprint.pformat(decoded_tokens)))
    assert decoded_tokens["acr"] == IAL1
    assert decoded_tokens["aud"] == client_id
    assert decoded_tokens["iss"] == MOCK_URL
    assert decoded_tokens["sub"] == "the-users-uuid"

    userinfo = client.get_userinfo(tokens["access_token"])
    # print("userinfo={}".format(pprint.pformat(userinfo)))
    assert userinfo["sub"] == "the-users-uuid"
    assert userinfo["iss"] == MOCK_URL
    assert userinfo["email"] == "you@example.gov"

    with pytest.raises(LoginDotGovOIDCNonceError) as e_info:
        decoded_tokens = client.validate_tokens(tokens, "not-the-nonce", code)
    assert str(e_info.value) == "login.gov nonce does not match client nonce"

    with pytest.raises(LoginDotGovOIDCAccessTokenError) as e_info:
        decoded_tokens = client.validate_tokens(
            {**tokens, "access_token": "not-the-access-token"}, nonce, code
        )
    assert str(e_info.value) == "login.gov access_token hash does not match access_code"

    with pytest.raises(LoginDotGovOIDCCodeError) as e_info:
        decoded_tokens = client.validate_tokens(tokens, nonce, "not-the-auth-code")
    assert str(e_info.value) == "login.gov code hash does not match initial code"

