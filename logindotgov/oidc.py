"""
login.gov OpenID Connect (OIDC) Relying Party (RP) client.

THIS IS NOT A GENERAL PURPOSE OAuth2 or OIDC LIBRARY.
See the README for the rationale for this specific implementation.
"""

import os
import secrets
import requests
import jwt
import hashlib
import base64
import time
from jwcrypto import jwk
from urllib.parse import urlencode

SANDBOX_URL = "https://idp.int.identitysandbox.gov/"
PRODUCTION_URL = "https://secure.login.gov/"
MOCK_URL = "https://mockhost.login.gov/"
GRANT_TYPE = "authorization_code"
SIGNING_ALGO = "RS256"
IAL1 = "http://idmanagement.gov/ns/assurance/ial/1"
IAL2 = "http://idmanagement.gov/ns/assurance/ial/2"
IAL2_STRICT = "http://idmanagement.gov/ns/assurance/ial/2?strict=true"


class LoginDotGovOIDCError(Exception):
    pass


class LoginDotGovOIDCTokenExchangeError(LoginDotGovOIDCError):
    pass


class LoginDotGovOIDCNonceError(LoginDotGovOIDCError):
    pass


class LoginDotGovOIDCAccessTokenError(LoginDotGovOIDCError):
    pass


class LoginDotGovOIDCCodeError(LoginDotGovOIDCError):
    pass


class LoginDotGovOIDCStateError(LoginDotGovOIDCError):
    pass


def encode_left128bits(string):
    # 128 bits / 8 bits per byte = 16
    # ref https://github.com/18F/identity-idp/blob/799fc62621a30c54e7edba17e376d94606d0c956/app/services/id_token_builder.rb#L69
    return (
        base64.urlsafe_b64encode(hashlib.sha256(string.encode("utf-8")).digest()[0:16])
        .decode("utf-8")
        .rstrip("=")
    )


class LoginDotGovOIDCClient(object):
    @staticmethod
    def get_url():  # pragma: no cover
        env = os.environ.get("LOGIN_DOT_GOV_ENV", "sandbox")
        if env == "sandbox":
            return SANDBOX_URL
        elif env == "production" or env == "prod":
            return PRODUCTION_URL
        else:
            return MOCK_URL

    @staticmethod
    def discover(url=None):
        base_url = url if url else LoginDotGovOIDCClient.get_url()
        return requests.get(f"{base_url}.well-known/openid-configuration").json()

    def __init__(self, **kwargs):
        self.config = (
            kwargs["config"] if "config" in kwargs else self.__class__.discover()
        )
        self.client_id = kwargs["client_id"]
        self.private_key = kwargs["private_key"]
        self.logger = kwargs.get("logger")  # optional

    def build_authorization_url(self, **kwargs):
        params = {
            "response_type": "code",
            "redirect_uri": kwargs["redirect_uri"],
            "acr_values": kwargs.get("acrs", IAL1),
            "client_id": self.client_id,
            "state": kwargs["state"],
            "nonce": kwargs["nonce"],
            "prompt": kwargs.get("prompt", "select_account"),
        }
        url = self.config["authorization_endpoint"]
        scopes = kwargs.get("scopes", ["openid", "email"])
        return f"{url}?{urlencode(params)}&scope={'+'.join(scopes)}"

    def validate_code_and_state(self, params):
        if params.get("error"):
            raise LoginDotGovOIDCError(params["error_description"])
        code = params.get("code")
        if code is None:
            raise LoginDotGovOIDCCodeError("Missing code param")
        state = params.get("state")
        if state is None:
            raise LoginDotGovOIDCStateError("Missing state param")
        return code, state

    def get_tokens(self, code):
        jwt_args = {
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": self.config["token_endpoint"],
            "jti": secrets.token_hex(16),
            "exp": int(time.time()) + 300,  # 5 minutes from now
        }
        encoded_jwt = jwt.encode(jwt_args, self.private_key, algorithm=SIGNING_ALGO)

        payload = {
            "client_assertion": encoded_jwt,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "code": code,
            "grant_type": GRANT_TYPE,
        }

        resp = requests.post(self.config["token_endpoint"], data=payload)

        # TODO check errors, status
        return resp.json()

    def validate_tokens(self, tokens, nonce, code):
        access_token = tokens["access_token"]
        id_token = tokens["id_token"]
        decoded_id_token = None

        logindotgov_public_key_resp = requests.get(self.config["jwks_uri"])

        # loop through each key till we find one that works. usually there is only 1
        # but it is possible that they are being rotated.
        for ldg_key in logindotgov_public_key_resp.json()["keys"]:
            jwk_key = jwk.JWK(**ldg_key)
            jwk_pem = jwk_key.export_to_pem().decode("utf-8")
            try:
                decoded_id_token = jwt.decode(
                    id_token,
                    jwk_pem,
                    audience=[self.client_id],
                    algorithms=[SIGNING_ALGO],
                )
            except Exception as error:
                # just log and loop again
                if self.logger:
                    self.logger.exception(error)
                pass

        if not decoded_id_token:
            raise LoginDotGovOIDCTokenExchangeError(
                "Could not decode id_token with public certs"
            )

        auth_nonce = decoded_id_token["nonce"]
        auth_c_hash = decoded_id_token["c_hash"]
        auth_at_hash = decoded_id_token["at_hash"]

        if auth_nonce != nonce:
            raise LoginDotGovOIDCNonceError(
                "login.gov nonce does not match client nonce"
            )

        code_bits = encode_left128bits(code)
        access_token_bits = encode_left128bits(access_token)
        if code_bits != auth_c_hash:
            raise LoginDotGovOIDCCodeError(
                "login.gov code hash does not match initial code"
            )
        if access_token_bits != auth_at_hash:
            raise LoginDotGovOIDCAccessTokenError(
                "login.gov access_token hash does not match access_code"
            )

        return decoded_id_token

    def get_userinfo(self, access_token):
        headers = {"Authorization": f"Bearer {access_token}"}
        userinfo_resp = requests.get(self.config["userinfo_endpoint"], headers=headers)
        return userinfo_resp.json()
