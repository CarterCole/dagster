import base64
import json
import time
from unittest import mock

import pytest
from dagster._core.errors import DagsterInvalidConfigError
from dagster_webserver.auth.config import load_auth_config
from dagster_webserver.auth.oidc import OidcClient, OidcError
from dagster_webserver.auth.session import SignedCookieCodec

ISSUER = "https://example.okta.com/oauth2/default"
SECRET = "s" * 40


def make_id_token(claims) -> str:
    def enc(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.signature"


def default_claims(**overrides):
    return {
        "iss": ISSUER,
        "aud": "client-123",
        "sub": "00u1",
        "email": "alice@example.com",
        "name": "Alice",
        "nonce": "the-nonce",
        "exp": time.time() + 300,
        "groups": ["data-eng"],
        **overrides,
    }


def test_signed_cookie_round_trip():
    codec = SignedCookieCodec(SECRET, salt="session")
    value = codec.encode({"email": "alice@example.com"}, max_age_seconds=60)
    payload = codec.decode(value)
    assert payload
    assert payload["email"] == "alice@example.com"


def test_signed_cookie_rejects_tampering_expiry_and_other_salts():
    codec = SignedCookieCodec(SECRET, salt="session")
    value = codec.encode({"email": "alice@example.com"}, max_age_seconds=60)
    _, signature = value.split(".")

    forged_body = base64.urlsafe_b64encode(
        json.dumps({"email": "mallory@example.com", "exp": time.time() + 60}).encode()
    ).decode()
    assert codec.decode(f"{forged_body}.{signature}") is None
    assert SignedCookieCodec(SECRET, salt="oidc-login-flow").decode(value) is None
    assert SignedCookieCodec("t" * 40, salt="session").decode(value) is None
    assert codec.decode(codec.encode({"email": "a"}, max_age_seconds=-1)) is None
    assert codec.decode("garbage") is None
    assert codec.decode(None) is None


def test_load_auth_config(monkeypatch):
    assert load_auth_config({}) is None
    assert load_auth_config({"auth": {"enabled": False}}) is None

    monkeypatch.setenv("OKTA_SECRET", "shh")
    monkeypatch.setenv("SESSION_SECRET", SECRET)
    config = load_auth_config(
        {
            "auth": {
                "oidc": {
                    "issuer": ISSUER + "/",
                    "client_id": "client-123",
                    "client_secret": {"env": "OKTA_SECRET"},
                },
                "session_secret": {"env": "SESSION_SECRET"},
                "admin_users": ["Admin@Example.com"],
            }
        }
    )
    assert config
    assert config.oidc.issuer == ISSUER
    assert config.oidc.client_secret == "shh"
    assert config.session_secret == SECRET
    assert config.admin_users == ["admin@example.com"]
    assert config.secure_cookies


def test_load_auth_config_rejects_short_secret():
    with pytest.raises(DagsterInvalidConfigError, match="at least 32"):
        load_auth_config(
            {
                "auth": {
                    "oidc": {"issuer": ISSUER, "client_id": "client-123"},
                    "session_secret": "short",
                }
            }
        )


def _client() -> OidcClient:
    config = load_auth_config(
        {
            "auth": {
                "oidc": {"issuer": ISSUER, "client_id": "client-123", "client_secret": "shh"},
                "session_secret": SECRET,
            }
        }
    )
    assert config
    return OidcClient(config.oidc)


METADATA = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/v1/authorize",
    "token_endpoint": f"{ISSUER}/v1/token",
    "userinfo_endpoint": f"{ISSUER}/v1/userinfo",
}


def _response(status_code, body):
    response = mock.MagicMock(status_code=status_code, text=json.dumps(body))
    response.json.return_value = body
    return response


def _exchange(client: OidcClient, claims, userinfo=None):
    with (
        mock.patch("requests.get") as get,
        mock.patch("requests.post") as post,
    ):
        get.side_effect = lambda url, **_: _response(
            200, METADATA if url.endswith("openid-configuration") else (userinfo or {})
        )
        post.return_value = _response(
            200, {"id_token": make_id_token(claims), "access_token": "at"}
        )
        user = client.exchange_code(
            code="code",
            redirect_uri="https://dagster/auth/callback",
            code_verifier="v",
            nonce="the-nonce",
        )
        return user, post


def test_exchange_code():
    user, post = _exchange(_client(), default_claims())
    assert user.email == "alice@example.com"
    assert user.groups == ["data-eng"]
    assert post.call_args.kwargs["auth"] == ("client-123", "shh")
    assert post.call_args.kwargs["data"]["code_verifier"] == "v"


def test_exchange_code_falls_back_to_userinfo_for_groups():
    claims = default_claims()
    del claims["groups"]
    user, _ = _exchange(_client(), claims, userinfo={"groups": ["from-userinfo", "b"]})
    assert user.groups == ["b", "from-userinfo"]


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"iss": "https://evil.example.com"}, "issuer"),
        ({"aud": "someone-else"}, "audience"),
        ({"exp": time.time() - 3600}, "expired"),
        ({"nonce": "replayed"}, "nonce"),
        ({"email": None, "preferred_username": None}, "no email"),
    ],
)
def test_exchange_code_rejects_bad_claims(overrides, message):
    with pytest.raises(OidcError, match=message):
        _exchange(_client(), default_claims(**overrides))


def test_authorization_url():
    client = _client()
    with mock.patch("requests.get", return_value=_response(200, METADATA)):
        url = client.build_authorization_url(
            redirect_uri="https://dagster/auth/callback",
            state="st",
            nonce="n",
            code_challenge="ch",
        )
    assert url.startswith(f"{ISSUER}/v1/authorize?")
    assert "code_challenge_method=S256" in url
    assert "scope=openid+profile+email&" in url
