# mock the login.gov service for testing

from logindotgov.oidc import (
    IAL1,
    MOCK_URL,
    SIGNING_ALGO,
    encode_left128bits,
    LoginDotGovOIDCError,
)
from requests.exceptions import RequestException
from jwcrypto import jwk
from jwcrypto.common import json_decode
import jwt
import time
import secrets

# import pprint


class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data

    def raise_for_status(self):  # pragma: no cover
        if self.status_code != 200:
            raise RequestException("oops")
        return None


class OIDC:
    token_uri = f"{MOCK_URL}api/openid_connect/token"
    server_private_key_jwk = jwk.JWK.generate(kty="RSA", size=4096)
    server_private_key_attrs = json_decode(server_private_key_jwk.export_public())
    server_private_key_pem = server_private_key_jwk.export_to_pem(True, None).decode(
        "utf-8"
    )
    server_public_key_jwk = jwk.JWK()
    server_public_key_jwk.import_key(**server_private_key_attrs)
    server_public_key = server_public_key_jwk.export_public(True)
    server_public_key_pem = server_public_key_jwk.export_to_pem().decode("utf-8")

    # client_id -> public_key/uri
    client_registry = {}

    # code -> client_id/acr/nonce ...
    auth_codes = {}

    @classmethod
    def register_client(cls, client_id, public_key, redirect_uri):
        cls.client_registry[client_id] = {
            "key": public_key,
            "redirect_uri": redirect_uri,
        }
        return True

    @classmethod
    def unregister_client(cls, client_id):  # pragma: no cover
        del cls.client_registry[client_id]
        return True

    @classmethod
    def authorize_endpoint(cls, params):
        state = params["state"]
        nonce = params["nonce"]
        client_id = params["client_id"]
        redirect_uri = params["redirect_uri"]
        if client_id not in cls.client_registry:
            return MockResponse(
                f"{redirect_uri}?error=true&error_description=unknown%20client_id", 302
            )
        if redirect_uri != cls.client_registry[client_id]["redirect_uri"]:
            return MockResponse(
                f"{redirect_uri}?error=true&error_description=redirect_uri%20mismatch",
                302,
            )

        code = secrets.token_hex(16)
        cls.auth_codes[code] = {
            "client_id": client_id,
            "state": state,
            "nonce": nonce,
            "acr": params["acr_values"],
            "scope": params["scope"],
            "access_token": secrets.token_hex(16),
        }

        return MockResponse(f"{redirect_uri}?code={code}&state={state}", 302)

    def route_request(self, args, kwargs):
        endpoint = args[0]
        if "/authorize" in endpoint:
            return self.__class__.authorize_endpoint(kwargs["data"])

        if "/openid-configuration" in endpoint:
            return self.config_endpoint()

        if "/certs" in endpoint:
            return self.certs_endpoint()

        if "/token" in endpoint:
            return self.token_endpoint(kwargs["data"])

        if "/userinfo" in endpoint:
            return self.userinfo_endpoint(kwargs)

        return MockResponse("route not found", 404)

    def config_endpoint(self):
        config = {
            "authorization_endpoint": f"{MOCK_URL}openid_connect/authorize",
            "jwks_uri": f"{MOCK_URL}api/openid_connect/certs",
            "token_endpoint": self.token_uri,
            "userinfo_endpoint": f"{MOCK_URL}api/openid_connect/userinfo",
        }
        return MockResponse(config, 200)

    def certs_endpoint(self):
        return MockResponse(
            {
                "keys": [
                    {
                        **self.server_public_key,
                        "kid": self.server_public_key_jwk.thumbprint(),
                    }
                ]
            },
            200,
        )

    def validate_access_token(self, access_token):
        for code, entry in self.__class__.auth_codes.items():
            if entry["access_token"] == access_token:
                return entry
        return False

    def userinfo_endpoint(self, args):
        if "headers" not in args or "Authorization" not in args["headers"]:
            return MockResponse({"error": "missing or invalid Bearer"}, 401)

        access_token = args["headers"]["Authorization"][7:]

        code_entry = self.validate_access_token(access_token)
        if not code_entry:
            return MockResponse({"error": "missing or invalid Bearer"}, 401)

        payload = {"sub": "the-users-uuid", "iss": MOCK_URL, "email": "you@example.gov"}
        for s in code_entry["scope"]:
            payload[s] = secrets.token_hex(4)
        return MockResponse(payload, 200)

    def token_endpoint(self, payload):
        client_assertion = payload["client_assertion"]
        code = payload["code"]
        codes = self.__class__.auth_codes
        if code not in codes:
            return MockResponse("invalid code", 400)
        # print("auth code {} entry: {}".format(code, pprint.pformat(codes[code])))
        client_id = codes[code]["client_id"]
        nonce = codes[code]["nonce"]
        access_token = codes[code]["access_token"]
        client_public_key = self.__class__.client_registry[client_id]["key"]
        client_jwt = jwt.decode(
            client_assertion,
            client_public_key,
            audience=[self.token_uri],
            algorithms=[SIGNING_ALGO],
        )
        if client_jwt["iss"] != client_id:
            raise Exception("client_id mismatch")
        if client_jwt["aud"] != self.token_uri:
            raise LoginDotGovOIDCError("aud does not equal token endpoint")

        args = {
            "iss": MOCK_URL,
            "sub": "the-users-uuid",
            "aud": client_id,
            "acr": IAL1,  # TODO variable based on initial scope
            "at_hash": encode_left128bits(access_token),
            "c_hash": encode_left128bits(code),
            "exp": time.time() + 60,
            "iat": time.time(),
            "jti": "a-secret-unique-key",
            "nbf": time.time(),
            "nonce": nonce,
        }
        id_token = jwt.encode(
            args,
            self.server_private_key_pem,
            algorithm=SIGNING_ALGO,
            headers={"kid": self.server_public_key_jwk.thumbprint()},
        )
        resp = {
            "id_token": id_token,
            "expires_in": 60,
            "token_type": "Bearer",
            "access_token": access_token,
        }
        return MockResponse(resp, 200)
