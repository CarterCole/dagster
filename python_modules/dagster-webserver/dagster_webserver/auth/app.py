import html
import logging
import secrets
from collections.abc import Callable, Sequence
from urllib.parse import urlencode

from dagster._core.instance import DagsterInstance
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.requests import HTTPConnection, Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import BaseRoute, Route
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.websockets import WebSocketClose

from dagster_webserver.auth.config import AuthConfig
from dagster_webserver.auth.identity import AUTH_USER_SCOPE_KEY, AuthenticatedUser
from dagster_webserver.auth.oidc import OidcClient, OidcError, PkcePair
from dagster_webserver.auth.policy import (
    AccessPolicy,
    AccessPolicyStore,
    AccessPolicyValidationError,
    ViewerAccess,
)
from dagster_webserver.auth.session import SignedCookieCodec

logger = logging.getLogger("dagster_webserver.auth")

SESSION_COOKIE = "dagster_session"
LOGIN_FLOW_COOKIE = "dagster_oidc_flow"
LOGIN_FLOW_MAX_AGE_SECONDS = 10 * 60
# Browsers drop cookies over ~4KB. Users in many Okta groups can exceed that; see the docs on
# limiting the groups claim with a filter.
MAX_COOKIE_BYTES = 4000

# Paths (relative to the app path prefix) reachable without signing in. The server info endpoints
# back health checks, e.g. the Helm chart's readiness probe.
PUBLIC_PATHS = frozenset(
    ["/auth/login", "/auth/callback", "/auth/logout", "/server_info", "/dagit_info"]
)


def _is_safe_next_path(path: str | None) -> bool:
    # Only same-origin absolute paths, to prevent open redirects via `?next=`.
    if not path:
        return False
    return path.startswith("/") and not path.startswith("//") and "\\" not in path


class WebserverAuth:
    """Okta (OIDC) sign-in and role-based access control for the webserver."""

    def __init__(
        self,
        config: AuthConfig,
        instance: DagsterInstance,
        app_path_prefix: str,
        get_location_names: Callable[[], Sequence[str]],
    ):
        self._config = config
        self._app_path_prefix = app_path_prefix
        self._get_location_names = get_location_names
        self._oidc = OidcClient(config.oidc)
        self._policy_store = AccessPolicyStore(instance)
        self._session_codec = SignedCookieCodec(config.session_secret, salt="session")
        self._login_flow_codec = SignedCookieCodec(config.session_secret, salt="oidc-login-flow")

    @property
    def policy_store(self) -> AccessPolicyStore:
        return self._policy_store

    # ----- identity -----

    def user_from_headers(self, headers: Headers) -> AuthenticatedUser | None:
        cookies = {}
        for chunk in headers.get("cookie", "").split(";"):
            name, sep, value = chunk.strip().partition("=")
            if sep:
                cookies[name] = value
        payload = self._session_codec.decode(cookies.get(SESSION_COOKIE))
        if payload is None:
            return None
        try:
            return AuthenticatedUser.from_session_payload(payload)
        except (KeyError, TypeError):
            return None

    def resolve_access(self, user: AuthenticatedUser) -> ViewerAccess:
        return self._policy_store.get().resolve(
            user, admin_users=self._config.admin_users, admin_groups=self._config.admin_groups
        )

    def access_for_connection(self, conn: HTTPConnection) -> ViewerAccess:
        user = conn.scope.get(AUTH_USER_SCOPE_KEY)
        if not isinstance(user, AuthenticatedUser):
            # The authentication middleware guarantees a user on every non-public path.
            raise Exception("Request reached an access-controlled path without a signed-in user.")
        return self.resolve_access(user)

    # ----- paths -----

    def _relative_path(self, path: str) -> str:
        if self._app_path_prefix and path.startswith(self._app_path_prefix):
            return path[len(self._app_path_prefix) :] or "/"
        return path

    def is_public_path(self, path: str) -> bool:
        return self._relative_path(path) in PUBLIC_PATHS

    def login_url(self, next_path: str | None = None) -> str:
        url = f"{self._app_path_prefix}/auth/login"
        return f"{url}?{urlencode({'next': next_path})}" if next_path else url

    def _redirect_uri(self, request: Request) -> str:
        if self._config.oidc.redirect_uri:
            return self._config.oidc.redirect_uri
        return f"{request.url.scheme}://{request.url.netloc}{self._app_path_prefix}/auth/callback"

    def _set_cookie(
        self, response: Response, name: str, value: str, max_age: int, path: str
    ) -> None:
        if len(value) > MAX_COOKIE_BYTES:
            logger.warning(
                f"The {name} cookie is {len(value)} bytes, which browsers may reject. Limit the"
                " groups claim in Okta with a filter so it only includes the groups Dagster uses."
            )
        response.set_cookie(
            name,
            value,
            max_age=max_age,
            path=path,
            httponly=True,
            secure=self._config.secure_cookies,
            samesite="lax",
        )

    # ----- endpoints -----

    def build_routes(self) -> list[BaseRoute]:
        return [
            Route("/auth/login", self.login_endpoint, methods=["GET"]),
            Route("/auth/callback", self.callback_endpoint, methods=["GET"]),
            Route("/auth/logout", self.logout_endpoint, methods=["GET", "POST"]),
            Route("/auth/me", self.me_endpoint, methods=["GET"]),
            Route("/auth/api/policy", self.get_policy_endpoint, methods=["GET"]),
            Route("/auth/api/policy", self.put_policy_endpoint, methods=["PUT"]),
        ]

    async def login_endpoint(self, request: Request) -> Response:
        next_path = request.query_params.get("next")
        if not _is_safe_next_path(next_path):
            next_path = f"{self._app_path_prefix}/"

        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        pkce = PkcePair.generate()
        try:
            authorization_url = await run_in_threadpool(
                self._oidc.build_authorization_url,
                redirect_uri=self._redirect_uri(request),
                state=state,
                nonce=nonce,
                code_challenge=pkce.challenge,
            )
        except OidcError as e:
            return _error_page("Sign-in is unavailable", str(e), status_code=502)

        response = RedirectResponse(authorization_url, status_code=302)
        self._set_cookie(
            response,
            LOGIN_FLOW_COOKIE,
            self._login_flow_codec.encode(
                {"state": state, "nonce": nonce, "verifier": pkce.verifier, "next": next_path},
                LOGIN_FLOW_MAX_AGE_SECONDS,
            ),
            max_age=LOGIN_FLOW_MAX_AGE_SECONDS,
            path=f"{self._app_path_prefix}/auth",
        )
        return response

    async def callback_endpoint(self, request: Request) -> Response:
        if error := request.query_params.get("error"):
            description = request.query_params.get("error_description") or error
            return _error_page(
                "Sign-in failed", description, status_code=403, retry_url=self.login_url()
            )

        flow = self._login_flow_codec.decode(request.cookies.get(LOGIN_FLOW_COOKIE))
        state = request.query_params.get("state") or ""
        code = request.query_params.get("code")
        if flow is None or not code or not secrets.compare_digest(state, flow.get("state", "")):
            return _error_page(
                "Sign-in expired",
                "The sign-in request expired or was started in another browser. Please try again.",
                status_code=400,
                retry_url=self.login_url(),
            )

        try:
            user = await run_in_threadpool(
                self._oidc.exchange_code,
                code=code,
                redirect_uri=self._redirect_uri(request),
                code_verifier=flow["verifier"],
                nonce=flow["nonce"],
            )
        except OidcError as e:
            logger.warning(f"OIDC sign-in failed: {e}")
            return _error_page(
                "Sign-in failed", str(e), status_code=403, retry_url=self.login_url()
            )

        logger.info(f"Signed in {user.email} (groups: {', '.join(user.groups) or 'none'})")
        next_path = flow.get("next")
        response = RedirectResponse(
            next_path
            if isinstance(next_path, str) and _is_safe_next_path(next_path)
            else f"{self._app_path_prefix}/",
            status_code=302,
        )
        self._set_cookie(
            response,
            SESSION_COOKIE,
            self._session_codec.encode(
                user.to_session_payload(), self._config.session_max_age_seconds
            ),
            max_age=self._config.session_max_age_seconds,
            path=self._app_path_prefix or "/",
        )
        response.delete_cookie(LOGIN_FLOW_COOKIE, path=f"{self._app_path_prefix}/auth")
        return response

    async def logout_endpoint(self, _request: Request) -> Response:
        # This ends the Dagster session only. The Okta session stays active, so signing in again
        # is instant for as long as Okta keeps the user signed in.
        response = HTMLResponse(
            _page(
                "Signed out",
                "<p>You have been signed out of Dagster.</p>"
                f'<p><a href="{html.escape(self.login_url())}">Sign in again</a></p>',
            )
        )
        response.delete_cookie(SESSION_COOKIE, path=self._app_path_prefix or "/")
        return response

    async def me_endpoint(self, request: Request) -> Response:
        return JSONResponse(self.access_for_connection(request).to_json())

    def _policy_response(self) -> JSONResponse:
        return JSONResponse(
            {
                "policy": self._policy_store.get().to_json(),
                "bootstrapAdmins": {
                    "users": list(self._config.admin_users),
                    "groups": list(self._config.admin_groups),
                },
                "locationNames": sorted(self._get_location_names()),
            }
        )

    async def get_policy_endpoint(self, request: Request) -> Response:
        if not self.access_for_connection(request).is_admin:
            return JSONResponse({"error": "Only admins can view the access policy."}, 403)
        return await run_in_threadpool(self._policy_response)

    async def put_policy_endpoint(self, request: Request) -> Response:
        access = self.access_for_connection(request)
        if not access.is_admin:
            return JSONResponse({"error": "Only admins can change the access policy."}, 403)
        # Requiring a JSON body means a cross-site form can't submit this; SameSite=Lax cookies
        # keep cross-site scripts from sending it with credentials.
        if "application/json" not in request.headers.get("content-type", ""):
            return JSONResponse({"error": "Expected an application/json body."}, 415)
        try:
            policy = AccessPolicy.from_json(await request.json())
        except ValueError:
            return JSONResponse({"error": "The request body is not valid JSON."}, 400)
        except AccessPolicyValidationError as e:
            return JSONResponse({"error": str(e)}, 400)

        await run_in_threadpool(self._policy_store.set, policy)
        logger.info(
            f"Access policy updated by {access.user.email}: default role"
            f" {policy.default_role.value}, {len(policy.rules)} rule(s)"
        )
        return await run_in_threadpool(self._policy_response)


class AuthenticationMiddleware:
    """ASGI middleware requiring a valid session on every non-public HTTP and websocket request.

    Written as plain ASGI (not `BaseHTTPMiddleware`) so it also guards the GraphQL websocket and
    doesn't buffer streaming responses.
    """

    def __init__(self, app: ASGIApp, auth: WebserverAuth):
        self._app = app
        self._auth = auth

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket") or self._auth.is_public_path(scope["path"]):
            await self._app(scope, receive, send)
            return

        user = self._auth.user_from_headers(Headers(scope=scope))
        if user is not None:
            scope[AUTH_USER_SCOPE_KEY] = user
            await self._app(scope, receive, send)
            return

        if scope["type"] == "websocket":
            await WebSocketClose(code=1008, reason="Not signed in")(scope, receive, send)
            return

        request = Request(scope)
        if request.method == "GET" and "text/html" in request.headers.get("accept", ""):
            next_path = request.url.path + (f"?{request.url.query}" if request.url.query else "")
            response: Response = RedirectResponse(self._auth.login_url(next_path), status_code=302)
        else:
            response = JSONResponse(
                {"error": "Not signed in.", "loginUrl": self._auth.login_url()}, status_code=401
            )
        await response(scope, receive, send)


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{html.escape(title)}</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:15vh auto;"
        "padding:0 16px;line-height:1.5;color:#1d1d1f}code{word-break:break-all}</style>"
        f"</head><body><h1>{html.escape(title)}</h1>{body}</body></html>"
    )


def _error_page(
    title: str, message: str, status_code: int, retry_url: str | None = None
) -> HTMLResponse:
    retry = f'<p><a href="{html.escape(retry_url)}">Try again</a></p>' if retry_url else ""
    return HTMLResponse(
        _page(title, f"<p><code>{html.escape(message)}</code></p>{retry}"), status_code=status_code
    )
