# logindotgov-oidc-py

OpenID Connect (OIDC) Relying Party client in Python for login.gov.

## Why?

There are many OIDC clients available for Python. Most of them implement all the ODIC protocols,
with varying degrees of user-friendliness.

This library is scoped narrowly to the protocol of the [login.gov OIDC implementation](https://developers.login.gov/oidc/),
with an emphasis on ease of use and correct, secure implementation of the OIDC standard that login.gov uses.

## Requirements

* Python 3.x
* pytest
* requests
* jwt
* jwcrypto

## Development

### Setup

```sh
% python3 -m venv .venv
% . .venv/bin/activate
(.venv) % make deps
```

### Tests

```sh
(.venv) % make test
(.venv) % make lint
```

## Examples

Here's an example Django view called `login-dot-gov/views.py`. It assumes that you have set some configuration
in your main Django `settings.py` file, as in:

```python
# settings.py
# you registered this with login.gov already
LOGIN_DOT_GOV_REDIRECT_URI = "https://myapp.example.gov/logindotgov/result"
LOGIN_DOT_GOV_CLIENT_ID = "urn:gov:gsa:openidconnect.profiles:sp:sso:myagency:my-app"

# the user attributes you want back.
LOGIN_DOT_GOV_IAL1_SCOPES = ["openid", "email"]

# the private key should be a PEM-encoded string
LOGIN_DOT_GOV_CLIENT_PRIVATE_KEY = read_from_secret_store() # you write this
```

```python
# views.py
from django.shortcuts import redirect
from django.http import HttpResponse, JsonResponse
import logging
import secrets
from logindotgov.oidc import LoginDotGovOIDCClient, LoginDotGovOIDCError, IAL1

from django.conf import settings

logger = logging.getLogger("logindotgov")

# cache the well-known config. alternately, this can be fetched on each login.
logindotgov_config = LoginDotGovOIDCClient.discover()

# just for debugging. Dumps the contents of your session to a JSON response.
def explain(request):
    this_session = {}
    for k in request.session.keys():
        this_session[k] = request.session[k]
    return JsonResponse(this_session)

def index(request):
    # if we already have a verified session, redirect to the root url
    if request.session.get("verified"):
        return redirect("/")

    # otherwise, initiate login.gov session
    # create our session with a "state" we can use to track IdP response.
    state = secrets.token_hex(11)
    nonce = secrets.token_hex(11)
    client = LoginDotGovOIDCClient(
        config=logindotgov_config,
        client_id=settings.LOGIN_DOT_GOV_CLIENT_ID,
        private_key=LOGIN_DOT_GOV_PRIVATE_KEY,
    )
    login_url = client.build_authorization_url(
        state=state,
        nonce=nonce,
        redirect_uri=LOGIN_DOT_GOV_REDIRECT_URI,
        acrs=IAL1,
        scopes=LOGIN_DOT_GOV_IAL1_SCOPES,
    )

    # stash these for when the user gets redirected back here.
    request.session["logindotgov"] = { "state": state, "nonce": nonce }

    return redirect(login_url)

# OIDC OP redirects here after auth attempt
def result(request):
    client = LoginDotGovOIDCClient(
        config=logindotgov_config,
        client_id=settings.LOGIN_DOT_GOV_CLIENT_ID,
        private_key=LOGIN_DOT_GOV_PRIVATE_KEY,
    )

    # all the error handling here is for example only. Do something friendlier in your actual code.
    try:
        auth_code, auth_state = client.validate_code_and_state(request.GET)
    except LoginDotGovOIDCError as error:
        logger.exception(error)
        return HttpResponse(error) # example only.

    session_state = request.session["logindotgov"]["state"]
    session_nonce = request.session["logindotgov"]["nonce"]

    if auth_state != session_state:
        logger.error("state mismatch")
        return redirect("/") # example only.

    tokens = client.get_tokens(auth_code)

    if "access_token" not in tokens:
        return HttpResponse(pprint.pformat(tokens))  # example only.

    try:
        decoded_id_token = client.validate_tokens(tokens, session_nonce, auth_code)
    except LoginDotGovOIDCError as error:
        logger.exception(error)
        return HttpResponse("Error exchanging token")  # example only.

    userinfo = client.get_userinfo(tokens["access_token"])

    # mark the session as complete
    request.session["verified"] = True
    request.session["logindotgov"]["userinfo"] = userinfo

    # Redirect to /explain to demonstrate what your session looks like.
    # In actual code, this would redirect to your app.
    return redirect("/login-dot-gov/explain")
```

The accompanying `urls.py` file looks like:

```python
from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('result', views.result, name="result"),
    path('explain', views.explain, name="explain"),
]
```
