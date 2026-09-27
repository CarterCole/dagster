from collections.abc import Mapping, Sequence
from typing import Any

from dagster_shared.record import record

# Key under which the authentication middleware stores the signed-in user on the ASGI scope.
AUTH_USER_SCOPE_KEY = "dagster_auth_user"


@record
class AuthenticatedUser:
    """The identity of a signed-in viewer, as asserted by the OIDC provider."""

    subject: str
    email: str
    name: str | None
    groups: Sequence[str]

    def to_session_payload(self) -> Mapping[str, Any]:
        return {"sub": self.subject, "email": self.email, "name": self.name, "groups": self.groups}

    @staticmethod
    def from_session_payload(payload: Mapping[str, Any]) -> "AuthenticatedUser":
        return AuthenticatedUser(
            subject=payload["sub"],
            email=payload["email"],
            name=payload.get("name"),
            groups=list(payload.get("groups") or []),
        )
