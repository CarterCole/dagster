import os
from collections.abc import Iterator
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest
from dagster import __version__
from dagster._cli.workspace.cli_target import WorkspaceOpts, workspace_opts_to_load_target
from dagster._core.instance import DagsterInstance
from dagster._core.storage.tags import REPOSITORY_LABEL_TAG
from dagster._core.test_utils import create_run_for_test, instance_for_test
from dagster._core.workspace.context import WorkspaceProcessContext
from dagster_webserver.auth.app import LOGIN_FLOW_COOKIE, SESSION_COOKIE
from dagster_webserver.auth.identity import AuthenticatedUser
from dagster_webserver.auth.policy import (
    AccessPolicy,
    AccessPolicyStore,
    AccessRule,
    PrincipalType,
    Role,
)
from dagster_webserver.auth.session import SignedCookieCodec
from dagster_webserver.graphql import GraphQLWS
from dagster_webserver.webserver import DagsterWebserver
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from dagster_webserver_tests.auth.test_session_and_oidc import (
    ISSUER,
    METADATA,
    SECRET,
    _response,
    default_claims,
    make_id_token,
)

# The fixture workspace has a single code location.
LOCATION = "load_from_file"
OTHER_LOCATION = "someone_elses_location"

RUNS_QUERY = """
{
  runsOrError {
    ... on Runs { results { runId } count }
  }
}
"""

RUNS_FEED_QUERY = """
{
  runsFeedOrError(limit: 10, view: RUNS) {
    ... on RunsFeedConnection { results { id } }
  }
}
"""

RUN_QUERY = """
query($runId: ID!) {
  runOrError(runId: $runId) { __typename }
  logsForRun(runId: $runId) { __typename }
}
"""

LOCATION_PERMISSIONS_QUERY = """
{
  workspaceOrError {
    ... on Workspace {
      locationEntries { name permissions { permission value disabledReason } }
    }
  }
}
"""

LAUNCH_MUTATION = """
mutation($selector: JobOrPipelineSelector!) {
  launchRun(executionParams: {selector: $selector, runConfigData: "{}"}) { __typename }
}
"""


def _session_cookie(email: str, groups=()) -> str:
    user = AuthenticatedUser(subject=email, email=email, name=None, groups=list(groups))
    return SignedCookieCodec(SECRET, salt="session").encode(user.to_session_payload(), 3600)


@pytest.fixture
def instance() -> Iterator[DagsterInstance]:
    with instance_for_test(
        overrides={
            "webserver": {
                "auth": {
                    "oidc": {"issuer": ISSUER, "client_id": "client-123", "client_secret": "shh"},
                    "session_secret": SECRET,
                    "secure_cookies": False,
                    "admin_users": ["admin@example.com"],
                }
            }
        }
    ) as instance:
        AccessPolicyStore(instance).set(
            AccessPolicy(
                default_role=Role.NONE,
                rules=[
                    AccessRule(
                        principal_type=PrincipalType.GROUP,
                        principal="data-eng",
                        role=Role.VIEWER,
                        locations=[LOCATION],
                    ),
                    AccessRule(
                        principal_type=PrincipalType.USER,
                        principal="launcher@example.com",
                        role=Role.LAUNCHER,
                        locations=[LOCATION],
                    ),
                ],
            )
        )
        yield instance


@pytest.fixture
def runs(instance: DagsterInstance) -> dict[str, str]:
    visible = create_run_for_test(
        instance, job_name="math", tags={REPOSITORY_LABEL_TAG: f"test_repository@{LOCATION}"}
    )
    hidden = create_run_for_test(
        instance, job_name="other", tags={REPOSITORY_LABEL_TAG: f"repo@{OTHER_LOCATION}"}
    )
    unlabeled = create_run_for_test(instance, job_name="adhoc")
    return {"visible": visible.run_id, "hidden": hidden.run_id, "unlabeled": unlabeled.run_id}


@pytest.fixture
def client(instance: DagsterInstance) -> Iterator[TestClient]:
    with WorkspaceProcessContext(
        instance=instance,
        version=__version__,
        read_only=False,
        workspace_load_target=workspace_opts_to_load_target(
            WorkspaceOpts(
                workspace=[os.path.join(os.path.dirname(__file__), "..", "workspace.yaml")]
            )
        ),
    ) as process_context:
        app = DagsterWebserver(process_context).create_asgi_app(debug=True)
        yield TestClient(app, follow_redirects=False)


def _gql(client: TestClient, email: str, query: str, variables=None, groups=()):
    client.cookies.set(SESSION_COOKIE, _session_cookie(email, groups))
    try:
        response = client.post("/graphql", json={"query": query, "variables": variables or {}})
    finally:
        client.cookies.clear()
    return response.json()


def test_unauthenticated_requests_are_refused(client: TestClient):
    response = client.get("/runs?view=all", headers={"Accept": "text/html"})
    assert response.status_code == 302
    assert response.headers["location"] == "/auth/login?next=%2Fruns%3Fview%3Dall"

    response = client.post("/graphql", json={"query": "{ version }"})
    assert response.status_code == 401

    assert client.get("/server_info").status_code == 200

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/graphql", subprotocols=[GraphQLWS.PROTOCOL.value]):
            pass


def test_forged_session_is_refused(client: TestClient):
    forged = SignedCookieCodec("x" * 40, salt="session").encode(
        {"sub": "a", "email": "admin@example.com", "groups": []}, 3600
    )
    client.cookies.set(SESSION_COOKIE, forged)
    assert client.post("/graphql", json={"query": "{ version }"}).status_code == 401


def test_run_lists_only_include_visible_runs(client: TestClient, runs):
    viewer = _gql(client, "bob@example.com", RUNS_QUERY, groups=["data-eng"])
    assert [r["runId"] for r in viewer["data"]["runsOrError"]["results"]] == [runs["visible"]]
    assert viewer["data"]["runsOrError"]["count"] == 1

    feed = _gql(client, "bob@example.com", RUNS_FEED_QUERY, groups=["data-eng"])
    assert [r["id"] for r in feed["data"]["runsFeedOrError"]["results"]] == [runs["visible"]]

    nobody = _gql(client, "nobody@example.com", RUNS_QUERY)
    assert nobody["data"]["runsOrError"]["results"] == []

    admin = _gql(client, "admin@example.com", RUNS_QUERY)
    assert {r["runId"] for r in admin["data"]["runsOrError"]["results"]} == set(runs.values())


def test_direct_run_lookups_hide_runs(client: TestClient, runs):
    for run_id, expected in [
        (runs["visible"], "Run"),
        (runs["hidden"], "RunNotFoundError"),
        (runs["unlabeled"], "RunNotFoundError"),
    ]:
        result = _gql(client, "bob@example.com", RUN_QUERY, {"runId": run_id}, groups=["data-eng"])
        assert result["data"]["runOrError"]["__typename"] == expected
        assert result["data"]["logsForRun"]["__typename"] in (
            {"EventConnection"} if expected == "Run" else {"RunNotFoundError"}
        )


def test_subscriptions_to_hidden_runs_are_refused(client: TestClient, runs):
    client.cookies.set(SESSION_COOKIE, _session_cookie("bob@example.com", ["data-eng"]))
    with client.websocket_connect("/graphql", subprotocols=[GraphQLWS.PROTOCOL.value]) as ws:
        ws.send_json({"type": GraphQLWS.CONNECTION_INIT})
        assert ws.receive_json()["type"] == GraphQLWS.CONNECTION_ACK
        ws.send_json(
            {
                "type": GraphQLWS.START,
                "id": "1",
                "payload": {
                    "query": "subscription($runId: ID!) { pipelineRunLogs(runId: $runId) { __typename } }",
                    "variables": {"runId": runs["hidden"]},
                },
            }
        )
        message = ws.receive_json()
        assert message["type"] == GraphQLWS.ERROR
        assert "could not be found" in message["payload"]["message"]


def test_debug_download_hides_runs(client: TestClient, runs):
    client.cookies.set(SESSION_COOKIE, _session_cookie("bob@example.com", ["data-eng"]))
    assert client.get(f"/download_debug/{runs['hidden']}").status_code == 404


def _location_permissions(client: TestClient, email: str) -> dict[str, bool]:
    result = _gql(client, email, LOCATION_PERMISSIONS_QUERY)
    [entry] = result["data"]["workspaceOrError"]["locationEntries"]
    assert entry["name"] == LOCATION
    return {p["permission"]: p["value"] for p in entry["permissions"]}


def test_location_permissions_follow_roles(client: TestClient):
    launcher = _location_permissions(client, "launcher@example.com")
    assert launcher["launch_pipeline_execution"]
    assert not launcher["start_schedule"]

    nobody = _location_permissions(client, "nobody@example.com")
    assert not any(nobody.values())

    admin = _location_permissions(client, "admin@example.com")
    assert admin["start_schedule"]


def test_launch_requires_launcher_role(client: TestClient):
    selector = {
        "repositoryLocationName": LOCATION,
        "repositoryName": "test_repository",
        "jobName": "math",
    }
    result = _gql(client, "bob@example.com", LAUNCH_MUTATION, {"selector": selector}, ["data-eng"])
    assert result["data"]["launchRun"]["__typename"] == "UnauthorizedError"


def test_mutations_over_get_are_refused(client: TestClient):
    client.cookies.set(SESSION_COOKIE, _session_cookie("admin@example.com"))
    response = client.get(
        "/graphql", params={"query": "mutation { reloadWorkspace { __typename } }"}
    )
    assert response.status_code == 405
    assert client.get("/graphql", params={"query": "{ version }"}).status_code == 200


def test_policy_api(client: TestClient):
    client.cookies.set(SESSION_COOKIE, _session_cookie("bob@example.com", ["data-eng"]))
    assert client.get("/auth/api/policy").status_code == 403
    me = client.get("/auth/me").json()
    assert me["globalRole"] == "none"
    assert me["locationRoles"] == {LOCATION: "viewer"}

    client.cookies.set(SESSION_COOKIE, _session_cookie("admin@example.com"))
    current = client.get("/auth/api/policy").json()
    assert current["locationNames"] == [LOCATION]
    assert current["bootstrapAdmins"]["users"] == ["admin@example.com"]
    assert len(current["policy"]["rules"]) == 2

    new_policy = {"defaultRole": "viewer", "rules": []}
    assert client.put("/auth/api/policy", content="{}").status_code == 415
    assert (
        client.put("/auth/api/policy", json={"defaultRole": "admin", "rules": []}).status_code
        == 400
    )
    response = client.put("/auth/api/policy", json=new_policy)
    assert response.status_code == 200
    assert response.json()["policy"] == new_policy

    client.cookies.set(SESSION_COOKIE, _session_cookie("bob@example.com"))
    assert client.get("/auth/me").json()["globalRole"] == "viewer"


def test_login_flow(client: TestClient):
    with mock.patch("requests.get", return_value=_response(200, METADATA)):
        response = client.get("/auth/login", params={"next": "/runs"})
    assert response.status_code == 302
    authorize = urlparse(response.headers["location"])
    params = parse_qs(authorize.query)
    assert params["redirect_uri"] == ["http://testserver/auth/callback"]
    assert LOGIN_FLOW_COOKIE in response.cookies

    # A callback with the wrong state is refused.
    assert client.get("/auth/callback", params={"code": "c", "state": "wrong"}).status_code == 400

    claims = default_claims(nonce=params["nonce"][0], groups=["data-eng"])
    with mock.patch("requests.post") as post:
        post.return_value = _response(200, {"id_token": make_id_token(claims)})
        response = client.get("/auth/callback", params={"code": "c", "state": params["state"][0]})
    assert response.status_code == 302
    assert response.headers["location"] == "/runs"
    assert SESSION_COOKIE in response.cookies

    me = client.get("/auth/me").json()
    assert me["user"]["email"] == "alice@example.com"
    assert me["locationRoles"] == {LOCATION: "viewer"}

    client.get("/auth/logout")
    assert client.get("/auth/me").status_code == 401


def test_login_rejects_open_redirects(client: TestClient):
    with mock.patch("requests.get", return_value=_response(200, METADATA)):
        response = client.get("/auth/login", params={"next": "//evil.example.com"})
    flow = SignedCookieCodec(SECRET, salt="oidc-login-flow").decode(
        response.cookies[LOGIN_FLOW_COOKIE]
    )
    assert flow
    assert flow["next"] == "/"
