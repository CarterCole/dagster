import base64
import hashlib
import json
import secrets
import threading
import time
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlencode

from dagster_shared.record import record

from dagster_webserver.auth.config import OidcConfig
from dagster_webserver.auth.identity import AuthenticatedUser

# Tolerated clock drift between the webserver and the identity provider.
CLOCK_SKEW_SECONDS = 120
HTTP_TIMEOUT_SECONDS = 10


class OidcError(Exception):
    """Raised when the sign-in flow fails. The message is safe to show to the user."""


@record
class PkcePair:
    verifier: str
    challenge: str

    @staticmethod
    def generate() -> "PkcePair":
        verifier = secrets.token_urlsafe(64)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        return PkcePair(verifier=verifier, challenge=challenge)


def decode_jwt_claims(token: str) -> Mapping[str, Any]:
    """Decodes a JWT's claims without verifying its signature. See `OidcClient.exchange_code` for
    why that is safe for ID tokens received from the token endpoint.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise OidcError("The identity provider returned a malformed ID token.")
    payload = parts[1]
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except ValueError:
        raise OidcError("The identity provider returned a malformed ID token.")
    if not isinstance(claims, dict):
        raise OidcError("The identity provider returned a malformed ID token.")
    return claims


class OidcClient:
    """Minimal OpenID Connect relying party for the Authorization Code flow with PKCE.

    Built for Okta (issuer `https://<org>.okta.com/oauth2/default` or a custom authorization
    server), but works with any provider that publishes discovery metadata.
    """

    def __init__(self, config: OidcConfig):
        self._config = config
        self._metadata: Mapping[str, Any] | None = None
        self._lock = threading.Lock()

    @property
    def config(self) -> OidcConfig:
        return self._config

    def metadata(self) -> Mapping[str, Any]:
        import requests  # lazy: slow to import

        with self._lock:
            if self._metadata is not None:
                return self._metadata
            try:
                response = requests.get(
                    f"{self._config.issuer}/.well-known/openid-configuration",
                    timeout=HTTP_TIMEOUT_SECONDS,
                )
                response.raise_for_status()
                metadata = response.json()
            except (requests.RequestException, ValueError) as e:
                raise OidcError(f"Could not load OIDC discovery metadata from the issuer: {e}")
            if metadata.get("issuer", "").rstrip("/") != self._config.issuer:
                raise OidcError(
                    f"Issuer mismatch: configured {self._config.issuer}, but discovery metadata"
                    f" reports {metadata.get('issuer')}."
                )
            self._metadata = metadata
            return metadata

    def build_authorization_url(
        self, *, redirect_uri: str, state: str, nonce: str, code_challenge: str
    ) -> str:
        params = {
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self._config.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{self.metadata()['authorization_endpoint']}?{urlencode(params)}"

    def exchange_code(
        self, *, code: str, redirect_uri: str, code_verifier: str, nonce: str
    ) -> AuthenticatedUser:
        import requests  # lazy: slow to import

        metadata = self.metadata()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "client_id": self._config.client_id,
        }
        auth = (
            (self._config.client_id, self._config.client_secret)
            if self._config.client_secret
            else None
        )
        try:
            response = requests.post(
                metadata["token_endpoint"],
                data=data,
                auth=auth,
                headers={"Accept": "application/json"},
                timeout=HTTP_TIMEOUT_SECONDS,
            )
        except requests.RequestException as e:
            raise OidcError(f"Could not reach the identity provider's token endpoint: {e}")
        if response.status_code != 200:
            raise OidcError(f"Token exchange failed ({response.status_code}): {response.text}")

        tokens = response.json()
        id_token = tokens.get("id_token")
        if not id_token:
            raise OidcError("The identity provider did not return an ID token.")

        # The ID token came straight from the token endpoint over TLS, in exchange for a
        # single-use code bound to our PKCE verifier (and client secret when configured). Per
        # OpenID Connect Core 1.0 section 3.1.3.7, TLS server validation may be used in place of
        # checking the token signature in this case; we still validate the claims.
        claims = decode_jwt_claims(id_token)
        self._validate_claims(claims, nonce)

        groups = claims.get(self._config.groups_claim)
        if groups is None and tokens.get("access_token") and metadata.get("userinfo_endpoint"):
            groups = self._fetch_userinfo(
                metadata["userinfo_endpoint"], tokens["access_token"]
            ).get(self._config.groups_claim)

        email = claims.get("email") or claims.get("preferred_username")
        if not email:
            raise OidcError(
                "The ID token has no email. Make sure the `email` scope is requested and granted."
            )

        return AuthenticatedUser(
            subject=claims["sub"],
            email=email,
            name=claims.get("name"),
            groups=_normalize_groups(groups),
        )

    def _validate_claims(self, claims: Mapping[str, Any], nonce: str) -> None:
        if str(claims.get("iss", "")).rstrip("/") != self._config.issuer:
            raise OidcError("ID token issuer does not match the configured issuer.")

        audience = claims.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        if self._config.client_id not in audiences:
            raise OidcError("ID token audience does not include this client.")
        if len(audiences) > 1 and claims.get("azp") != self._config.client_id:
            raise OidcError("ID token authorized party does not match this client.")

        if not isinstance(claims.get("exp"), (int, float)) or (
            claims["exp"] + CLOCK_SKEW_SECONDS < time.time()
        ):
            raise OidcError("ID token has expired. Check that the server clock is correct.")

        if not claims.get("nonce") or not secrets.compare_digest(str(claims["nonce"]), nonce):
            raise OidcError("ID token nonce does not match the sign-in request.")

        if not claims.get("sub"):
            raise OidcError("ID token has no subject.")

    def _fetch_userinfo(self, userinfo_endpoint: str, access_token: str) -> Mapping[str, Any]:
        import requests  # lazy: slow to import

        try:
            response = requests.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=HTTP_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as e:
            raise OidcError(f"Could not load group membership from the userinfo endpoint: {e}")


def _normalize_groups(groups: Any) -> Sequence[str]:
    if isinstance(groups, str):
        return [groups]
    if isinstance(groups, list):
        return sorted({str(group) for group in groups})
    return []
