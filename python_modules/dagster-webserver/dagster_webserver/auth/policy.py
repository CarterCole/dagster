import json
import threading
import time
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any

from dagster._core.instance import DagsterInstance
from dagster._core.workspace.permissions import (
    EDITOR_PERMISSIONS,
    LOCATION_SCOPED_PERMISSIONS,
    PermissionResult,
    Permissions,
)
from dagster_shared.record import record

from dagster_webserver.auth.identity import AuthenticatedUser

ALL_LOCATIONS = "*"
ACCESS_POLICY_STORAGE_KEY = "dagster_webserver/access_policy"


class Role(str, Enum):
    """Roles in ascending order of privilege. A higher role includes everything a lower one can do."""

    NONE = "none"  # cannot see runs
    VIEWER = "viewer"  # can see runs
    LAUNCHER = "launcher"  # can also launch, re-execute and terminate runs and backfills
    EDITOR = "editor"  # can also manage schedules, sensors, assets and partitions
    ADMIN = "admin"  # on "*" only: can also manage the access policy

    @property
    def rank(self) -> int:
        return _ROLE_ORDER.index(self)

    def at_least(self, other: "Role") -> bool:
        return self.rank >= other.rank


_ROLE_ORDER = [Role.NONE, Role.VIEWER, Role.LAUNCHER, Role.EDITOR, Role.ADMIN]

LAUNCHER_PERMISSIONS = {
    Permissions.LAUNCH_PIPELINE_EXECUTION,
    Permissions.LAUNCH_PIPELINE_REEXECUTION,
    Permissions.TERMINATE_PIPELINE_EXECUTION,
    Permissions.LAUNCH_PARTITION_BACKFILL,
    Permissions.CANCEL_PARTITION_BACKFILL,
}


class PrincipalType(str, Enum):
    USER = "user"  # matched against the user's email, case-insensitively
    GROUP = "group"  # matched against the user's Okta group names, exactly


class AccessPolicyValidationError(Exception):
    pass


@record
class AccessRule:
    principal_type: PrincipalType
    principal: str
    role: Role
    locations: Sequence[str]

    def matches(self, user: AuthenticatedUser) -> bool:
        if self.principal_type == PrincipalType.USER:
            return self.principal.lower() == user.email.lower()
        return self.principal in user.groups

    def to_json(self) -> Mapping[str, Any]:
        return {
            "principalType": self.principal_type.value,
            "principal": self.principal,
            "role": self.role.value,
            "locations": list(self.locations),
        }

    @staticmethod
    def from_json(value: Any) -> "AccessRule":
        if not isinstance(value, Mapping):
            raise AccessPolicyValidationError("Each rule must be an object.")
        principal = value.get("principal")
        if not isinstance(principal, str) or not principal.strip():
            raise AccessPolicyValidationError("Each rule needs a non-empty principal.")
        locations = value.get("locations")
        if (
            not isinstance(locations, list)
            or not locations
            or not all(isinstance(loc, str) and loc.strip() for loc in locations)
        ):
            raise AccessPolicyValidationError(
                f"Rule for {principal} needs at least one code location (or {ALL_LOCATIONS!r})."
            )
        return AccessRule(
            principal_type=_parse_enum(PrincipalType, value.get("principalType"), "principalType"),
            principal=principal.strip(),
            role=_parse_enum(Role, value.get("role"), "role"),
            locations=sorted({loc.strip() for loc in locations}),
        )


@record
class ViewerAccess:
    """The roles a single signed-in user holds, resolved from the policy."""

    user: AuthenticatedUser
    # Role on every code location, including ones that no longer exist.
    global_role: Role
    # Explicit per-location grants that exceed the global role.
    location_roles: Mapping[str, Role]

    @property
    def is_admin(self) -> bool:
        return self.global_role == Role.ADMIN

    @property
    def can_view_all_runs(self) -> bool:
        return self.global_role.at_least(Role.VIEWER)

    def role_for_location(self, location_name: str) -> Role:
        return _max_role(self.global_role, self.location_roles.get(location_name, Role.NONE))

    def can_view_location_runs(self, location_name: str | None) -> bool:
        # Runs whose code location is unknown (e.g. launched outside the webserver with
        # `execute_in_process`) are only visible to users who can see every location.
        if location_name is None:
            return self.can_view_all_runs
        return self.role_for_location(location_name).at_least(Role.VIEWER)

    def to_json(self) -> Mapping[str, Any]:
        return {
            "user": {
                "email": self.user.email,
                "name": self.user.name,
                "groups": list(self.user.groups),
            },
            "isAdmin": self.is_admin,
            "globalRole": self.global_role.value,
            "locationRoles": {name: role.value for name, role in self.location_roles.items()},
        }


@record
class AccessPolicy:
    # Role granted to every signed-in user on every code location.
    default_role: Role
    rules: Sequence[AccessRule]

    @staticmethod
    def empty() -> "AccessPolicy":
        return AccessPolicy(default_role=Role.NONE, rules=[])

    def resolve(
        self,
        user: AuthenticatedUser,
        admin_users: Sequence[str] = (),
        admin_groups: Sequence[str] = (),
    ) -> ViewerAccess:
        global_role = self.default_role
        location_roles: dict[str, Role] = {}

        if user.email.lower() in admin_users or any(group in user.groups for group in admin_groups):
            global_role = Role.ADMIN

        for rule in self.rules:
            if not rule.matches(user):
                continue
            for location in rule.locations:
                if location == ALL_LOCATIONS:
                    global_role = _max_role(global_role, rule.role)
                else:
                    # Admin is an instance-wide role; on a single location it acts as editor.
                    role = Role.EDITOR if rule.role == Role.ADMIN else rule.role
                    location_roles[location] = _max_role(
                        location_roles.get(location, Role.NONE), role
                    )

        return ViewerAccess(
            user=user,
            global_role=global_role,
            location_roles={
                name: role for name, role in location_roles.items() if role.rank > global_role.rank
            },
        )

    def to_json(self) -> Mapping[str, Any]:
        return {
            "defaultRole": self.default_role.value,
            "rules": [rule.to_json() for rule in self.rules],
        }

    @staticmethod
    def from_json(value: Any) -> "AccessPolicy":
        if not isinstance(value, Mapping):
            raise AccessPolicyValidationError("The access policy must be an object.")
        rules = value.get("rules", [])
        if not isinstance(rules, list):
            raise AccessPolicyValidationError("`rules` must be a list.")
        default_role = _parse_enum(Role, value.get("defaultRole", Role.NONE.value), "defaultRole")
        if default_role == Role.ADMIN:
            raise AccessPolicyValidationError("The default role cannot be admin.")
        return AccessPolicy(
            default_role=default_role,
            rules=[AccessRule.from_json(rule) for rule in rules],
        )


def _parse_enum(enum_cls: type[Enum], value: Any, field: str) -> Any:
    try:
        return enum_cls(value)
    except ValueError:
        options = ", ".join(member.value for member in enum_cls)
        raise AccessPolicyValidationError(f"Invalid {field} {value!r}; expected one of {options}.")


def _max_role(a: Role, b: Role) -> Role:
    return a if a.rank >= b.rank else b


def _disabled_reason(role: Role) -> str:
    return f"Your access role ({role.value}) does not allow this. Ask a Dagster admin for access."


def _role_allows(role: Role, permission: str) -> bool:
    if role.at_least(Role.EDITOR):
        return EDITOR_PERMISSIONS[permission]
    if role == Role.LAUNCHER:
        return permission in LAUNCHER_PERMISSIONS
    return False


def permissions_for_role(role: Role) -> Mapping[str, PermissionResult]:
    results = {}
    for permission in EDITOR_PERMISSIONS:
        enabled = _role_allows(role, permission)
        results[permission] = PermissionResult(
            enabled=enabled, disabled_reason=None if enabled else _disabled_reason(role)
        )
    return results


def location_scoped_permissions_for_role(role: Role) -> Mapping[str, PermissionResult]:
    return {
        permission: result
        for permission, result in permissions_for_role(role).items()
        if permission in LOCATION_SCOPED_PERMISSIONS
    }


class AccessPolicyStore:
    """Persists the access policy in the instance's key-value storage, so it is shared by every
    webserver replica pointed at the same instance and survives restarts without migrations.

    Reads are cached briefly so that each GraphQL request does not hit the database; replicas
    converge on a new policy within `cache_ttl_seconds`.
    """

    def __init__(self, instance: DagsterInstance, cache_ttl_seconds: float = 5.0):
        self._instance = instance
        self._cache_ttl_seconds = cache_ttl_seconds
        self._lock = threading.Lock()
        self._cached: AccessPolicy | None = None
        self._cached_at = 0.0

    def get(self) -> AccessPolicy:
        with self._lock:
            if self._cached and time.monotonic() - self._cached_at < self._cache_ttl_seconds:
                return self._cached

        raw = self._instance.run_storage.get_cursor_values({ACCESS_POLICY_STORAGE_KEY}).get(
            ACCESS_POLICY_STORAGE_KEY
        )
        policy = AccessPolicy.from_json(json.loads(raw)) if raw else AccessPolicy.empty()

        with self._lock:
            self._cached = policy
            self._cached_at = time.monotonic()
        return policy

    def set(self, policy: AccessPolicy) -> None:
        self._instance.run_storage.set_cursor_values(
            {ACCESS_POLICY_STORAGE_KEY: json.dumps(policy.to_json())}
        )
        with self._lock:
            self._cached = policy
            self._cached_at = time.monotonic()
