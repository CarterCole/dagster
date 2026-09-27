import os
from collections.abc import Mapping, Sequence
from typing import Any

from dagster._core.errors import DagsterInvalidConfigError
from dagster_shared.record import record

# Add "groups" when using the Okta org authorization server; custom authorization servers have no
# `groups` scope by default and reject unknown scopes.
DEFAULT_OIDC_SCOPES = ("openid", "profile", "email")
DEFAULT_GROUPS_CLAIM = "groups"
DEFAULT_SESSION_MAX_AGE_SECONDS = 12 * 60 * 60
MIN_SESSION_SECRET_LENGTH = 32


@record
class OidcConfig:
    """Settings for the OpenID Connect provider (e.g. an Okta authorization server)."""

    issuer: str
    client_id: str
    client_secret: str | None
    redirect_uri: str | None
    scopes: Sequence[str]
    groups_claim: str


@record
class AuthConfig:
    """Parsed `webserver.auth` section of dagster.yaml."""

    oidc: OidcConfig
    session_secret: str
    session_max_age_seconds: int
    secure_cookies: bool
    # Principals that are always admins, regardless of the stored access policy. This guarantees
    # someone can always reach the access control page, even with an empty or broken policy.
    admin_users: Sequence[str]
    admin_groups: Sequence[str]


def _resolve_source(value: Any, key: str) -> Any:
    """Resolves `{env: VAR}` values. Instance settings are validated but not post-processed, so
    StringSource/IntSource/BoolSource fields arrive here unresolved.
    """
    if isinstance(value, Mapping) and "env" in value:
        env_var = value["env"]
        resolved = os.getenv(env_var)
        if resolved is None:
            raise DagsterInvalidConfigError(
                f"webserver.auth.{key} references environment variable {env_var}, which is not set.",
                [],
                value,
            )
        return resolved
    return value


def _resolve_bool(value: Any, key: str, default: bool) -> bool:
    resolved = _resolve_source(value, key)
    if resolved is None:
        return default
    if isinstance(resolved, str):
        return resolved.strip().lower() in ("1", "true", "yes")
    return bool(resolved)


def load_auth_config(webserver_settings: Mapping[str, Any]) -> AuthConfig | None:
    """Returns the auth config, or None if authentication is not configured."""
    auth = webserver_settings.get("auth")
    if not auth or not _resolve_bool(auth.get("enabled"), "enabled", default=True):
        return None

    oidc = auth.get("oidc") or {}
    issuer = _resolve_source(oidc.get("issuer"), "oidc.issuer")
    client_id = _resolve_source(oidc.get("client_id"), "oidc.client_id")
    if not issuer or not client_id:
        raise DagsterInvalidConfigError(
            "webserver.auth.oidc requires both `issuer` and `client_id`.", [], oidc
        )

    session_secret = _resolve_source(auth.get("session_secret"), "session_secret")
    if not session_secret or len(session_secret) < MIN_SESSION_SECRET_LENGTH:
        raise DagsterInvalidConfigError(
            f"webserver.auth.session_secret must be at least {MIN_SESSION_SECRET_LENGTH}"
            " characters. Generate one with `python -c 'import secrets;"
            " print(secrets.token_urlsafe(48))'`.",
            [],
            None,
        )

    max_age = _resolve_source(auth.get("session_max_age_seconds"), "session_max_age_seconds")

    return AuthConfig(
        oidc=OidcConfig(
            issuer=issuer.rstrip("/"),
            client_id=client_id,
            client_secret=_resolve_source(oidc.get("client_secret"), "oidc.client_secret"),
            redirect_uri=_resolve_source(oidc.get("redirect_uri"), "oidc.redirect_uri"),
            scopes=list(oidc.get("scopes") or DEFAULT_OIDC_SCOPES),
            groups_claim=oidc.get("groups_claim") or DEFAULT_GROUPS_CLAIM,
        ),
        session_secret=session_secret,
        session_max_age_seconds=int(max_age) if max_age else DEFAULT_SESSION_MAX_AGE_SECONDS,
        secure_cookies=_resolve_bool(auth.get("secure_cookies"), "secure_cookies", default=True),
        admin_users=[user.lower() for user in auth.get("admin_users") or []],
        admin_groups=list(auth.get("admin_groups") or []),
    )
