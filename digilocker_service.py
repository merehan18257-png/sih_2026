import os
import base64
import hashlib
import secrets

import requests

from urllib.parse import urlencode
from dotenv import load_dotenv


load_dotenv()


CLIENT_ID = os.getenv("DIGILOCKER_CLIENT_ID")
CLIENT_SECRET = os.getenv("DIGILOCKER_CLIENT_SECRET")

REDIRECT_URI = os.getenv(
    "DIGILOCKER_REDIRECT_URI"
)

AUTHORIZE_URL = os.getenv(
    "DIGILOCKER_AUTHORIZE_URL"
)

TOKEN_URL = os.getenv(
    "DIGILOCKER_TOKEN_URL"
)


def create_pkce():

    verifier = secrets.token_urlsafe(64)

    digest = hashlib.sha256(
        verifier.encode("utf-8")
    ).digest()

    challenge = base64.urlsafe_b64encode(
        digest
    ).decode("utf-8").rstrip("=")

    return verifier, challenge


def create_authorization_url(request):

    state = secrets.token_urlsafe(32)

    verifier, challenge = create_pkce()

    request.session["digilocker_state"] = state

    request.session["digilocker_verifier"] = verifier

    params = {

        "response_type": "code",

        "client_id": CLIENT_ID,

        "redirect_uri": REDIRECT_URI,

        "state": state,

        "code_challenge": challenge,

        "code_challenge_method": "S256",

    }

    return (
        AUTHORIZE_URL
        + "?"
        + urlencode(params)
    )


def get_access_token(
    code,
    verifier
):

    data = {

        "grant_type":
            "authorization_code",

        "code":
            code,

        "client_id":
            CLIENT_ID,

        "client_secret":
            CLIENT_SECRET,

        "redirect_uri":
            REDIRECT_URI,

        "code_verifier":
            verifier,

    }

    response = requests.post(
        TOKEN_URL,
        data=data,
        timeout=30
    )

    response.raise_for_status()

    return response.json()


def get_digilocker_user(
    access_token
):

    USER_URL = (
        "https://entity.digilocker.gov.in/"
        "public/oauth2/1/user"
    )

    response = requests.get(

        USER_URL,

        headers={
            "Authorization":
                f"Bearer {access_token}"
        },

        timeout=30
    )

    response.raise_for_status()

    return response.json()