import pytest
from dagster._core.test_utils import instance_for_test
from dagster._core.workspace.permissions import Permissions
from dagster_webserver.auth.identity import AuthenticatedUser
from dagster_webserver.auth.policy import (
    AccessPolicy,
    AccessPolicyStore,
    AccessPolicyValidationError,
    AccessRule,
    PrincipalType,
    Role,
    location_scoped_permissions_for_role,
    permissions_for_role,
)

ALICE = AuthenticatedUser(
    subject="00u1", email="Alice@Example.com", name="Alice", groups=["data-eng", "everyone"]
)


def _rule(principal_type, principal, role, locations):
    return AccessRule(
        principal_type=principal_type, principal=principal, role=role, locations=locations
    )


def test_default_policy_grants_nothing():
    access = AccessPolicy.empty().resolve(ALICE)
    assert access.global_role == Role.NONE
    assert not access.can_view_all_runs
    assert not access.can_view_location_runs("etl")
    assert not access.can_view_location_runs(None)


def test_user_rule_matches_email_case_insensitively():
    policy = AccessPolicy(
        default_role=Role.NONE,
        rules=[_rule(PrincipalType.USER, "alice@example.COM", Role.LAUNCHER, ["etl"])],
    )
    access = policy.resolve(ALICE)
    assert access.role_for_location("etl") == Role.LAUNCHER
    assert access.role_for_location("ml") == Role.NONE


def test_highest_role_wins_across_rules():
    policy = AccessPolicy(
        default_role=Role.VIEWER,
        rules=[
            _rule(PrincipalType.GROUP, "data-eng", Role.LAUNCHER, ["etl", "ml"]),
            _rule(PrincipalType.GROUP, "everyone", Role.EDITOR, ["ml"]),
            _rule(PrincipalType.GROUP, "not-my-group", Role.ADMIN, ["*"]),
        ],
    )
    access = policy.resolve(ALICE)
    assert access.global_role == Role.VIEWER
    assert access.role_for_location("etl") == Role.LAUNCHER
    assert access.role_for_location("ml") == Role.EDITOR
    assert access.role_for_location("other") == Role.VIEWER
    assert not access.is_admin


def test_admin_on_single_location_is_editor():
    policy = AccessPolicy(
        default_role=Role.NONE,
        rules=[_rule(PrincipalType.GROUP, "data-eng", Role.ADMIN, ["etl"])],
    )
    access = policy.resolve(ALICE)
    assert access.role_for_location("etl") == Role.EDITOR
    assert not access.is_admin


def test_bootstrap_admins():
    assert AccessPolicy.empty().resolve(ALICE, admin_users=["alice@example.com"]).is_admin
    assert AccessPolicy.empty().resolve(ALICE, admin_groups=["data-eng"]).is_admin
    assert not AccessPolicy.empty().resolve(ALICE, admin_groups=["DATA-ENG"]).is_admin


def test_role_permissions():
    viewer = permissions_for_role(Role.VIEWER)
    assert not any(result.enabled for result in viewer.values())
    assert "viewer" in (viewer[Permissions.LAUNCH_PIPELINE_EXECUTION].disabled_reason or "")

    launcher = location_scoped_permissions_for_role(Role.LAUNCHER)
    assert launcher[Permissions.LAUNCH_PIPELINE_EXECUTION].enabled
    assert launcher[Permissions.TERMINATE_PIPELINE_EXECUTION].enabled
    assert not launcher[Permissions.START_SCHEDULE].enabled
    assert not launcher[Permissions.WIPE_ASSETS].enabled
    assert Permissions.RELOAD_WORKSPACE not in launcher

    editor = permissions_for_role(Role.EDITOR)
    assert editor[Permissions.START_SCHEDULE].enabled
    assert editor[Permissions.RELOAD_WORKSPACE].enabled


def test_policy_json_round_trip():
    policy = AccessPolicy(
        default_role=Role.VIEWER,
        rules=[_rule(PrincipalType.GROUP, "data-eng", Role.LAUNCHER, ["ml", "etl"])],
    )
    restored = AccessPolicy.from_json(policy.to_json())
    assert restored.default_role == Role.VIEWER
    assert restored.rules[0].locations == ["etl", "ml"]
    assert restored.rules[0].role == Role.LAUNCHER


@pytest.mark.parametrize(
    "value, message",
    [
        ({"defaultRole": "admin"}, "cannot be admin"),
        ({"defaultRole": "superuser"}, "Invalid defaultRole"),
        ({"rules": [{"principalType": "user", "principal": "", "role": "viewer"}]}, "principal"),
        (
            {
                "rules": [
                    {
                        "principalType": "team",
                        "principal": "x",
                        "role": "viewer",
                        "locations": ["*"],
                    }
                ]
            },
            "Invalid principalType",
        ),
        (
            {
                "rules": [
                    {"principalType": "user", "principal": "x", "role": "viewer", "locations": []}
                ]
            },
            "at least one code location",
        ),
    ],
)
def test_policy_validation(value, message):
    with pytest.raises(AccessPolicyValidationError, match=message):
        AccessPolicy.from_json(value)


def test_policy_store_persists_in_instance():
    with instance_for_test() as instance:
        store = AccessPolicyStore(instance, cache_ttl_seconds=0)
        assert store.get() == AccessPolicy.empty()

        policy = AccessPolicy(
            default_role=Role.VIEWER,
            rules=[_rule(PrincipalType.USER, "alice@example.com", Role.ADMIN, ["*"])],
        )
        store.set(policy)
        assert AccessPolicyStore(instance).get() == policy
