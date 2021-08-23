# mock the login.gov service for testing

from logindotgov.oidc import IAL1, MOCK_URL, SIGNING_ALGO, encode_left128bits
from requests.exceptions import RequestException
from jwcrypto import jwk
from jwcrypto.common import json_decode
import jwt
import time


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

    def __init__(
        self,
        access_token,
        auth_code,
        client_id,
        redirect_uri,
        client_public_key,
        nonce,
        state,
    ):
        self.access_token = access_token
        self.auth_code = auth_code
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.client_public_key = client_public_key
        self.nonce = nonce
        self.state = state

    def route_request(self, args, kwargs):
        endpoint = args[0]
        if "/authorize" in endpoint:
            return self.authorize_endpoint(kwargs["data"])

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

    # TODO
    def authorize_endpoint(self, params):
        auth_code = self.auth_code
        state = params["state"]
        return MockResponse(f"{self.redirect_uri}?code={auth_code}&state={state}", 302)

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

    def userinfo_endpoint(self, args):
        if "headers" not in args or args["headers"] != {
            "Authorization": "Bearer the-access-token"
        }:
            return MockResponse({"error": "missing or invalid Bearer"}, 401)

        return MockResponse(
            {"sub": "the-users-uuid", "iss": MOCK_URL, "email": "you@example.gov"}, 200
        )

    def token_endpoint(self, payload):
        client_assertion = payload["client_assertion"]
        client_jwt = jwt.decode(
            client_assertion,
            self.client_public_key,
            audience=[self.token_uri],
            algorithms=[SIGNING_ALGO],
        )
        if client_jwt["iss"] != self.client_id:
            raise Exception("client_id mismatch")
        # TODO check aud

        args = {
            "iss": MOCK_URL,
            "sub": "the-users-uuid",
            "aud": self.client_id,
            "acr": IAL1,
            "at_hash": encode_left128bits(self.access_token),
            "c_hash": encode_left128bits(self.auth_code),
            "exp": time.time() + 60,
            "iat": time.time(),
            "jti": "a-secret-unique-key",
            "nbf": time.time(),
            "nonce": self.nonce,
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
            "access_token": self.access_token,
        }
        return MockResponse(resp, 200)
