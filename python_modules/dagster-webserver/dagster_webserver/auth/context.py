from collections.abc import Mapping, Sequence
from functools import cached_property

from dagster._core.storage.dagster_run import DagsterRun, RunsFilter
from dagster._core.storage.tags import REPOSITORY_LABEL_TAG
from dagster._core.workspace.context import WorkspaceRequestContext
from dagster._core.workspace.permissions import (
    PermissionResult,
    get_location_scoped_user_permissions,
    get_user_permissions,
)
from dagster._record import copy

from dagster_webserver.auth.policy import (
    ViewerAccess,
    location_scoped_permissions_for_role,
    permissions_for_role,
)

# Matches no run: used when a viewer is not allowed to see runs from any code location.
NO_VISIBLE_RUNS_SENTINEL = "__dagster_webserver_no_visible_runs__"


def location_name_from_repository_label(label: str) -> str | None:
    # Labels are formatted `<repository name>@<code location name>`.
    _, sep, location_name = label.partition("@")
    return location_name if sep else None


def location_name_for_run(run: DagsterRun) -> str | None:
    if run.remote_job_origin:
        return run.remote_job_origin.location_name
    label = run.tags.get(REPOSITORY_LABEL_TAG)
    return location_name_from_repository_label(label) if label else None


class AccessControlledWorkspaceRequestContext(WorkspaceRequestContext):
    """A request context whose permissions and run visibility come from the signed-in viewer's
    roles, rather than from the webserver-wide read-only flag.

    Starting the webserver with `--read-only` still takes precedence: nobody can mutate anything.
    """

    def __init__(self, *, access: ViewerAccess, **kwargs):
        super().__init__(**kwargs)
        self._access = access

    @staticmethod
    def from_request_context(
        context: WorkspaceRequestContext, access: ViewerAccess
    ) -> "AccessControlledWorkspaceRequestContext":
        return AccessControlledWorkspaceRequestContext(
            access=access,
            instance=context.instance,
            current_workspace=context.get_current_workspace(),
            process_context=context.process_context,
            version=context.version,
            source=context.source,
            read_only=context.read_only,
        )

    @property
    def access(self) -> ViewerAccess:
        return self._access

    @property
    def permissions(self) -> Mapping[str, PermissionResult]:
        if self.read_only:
            return get_user_permissions(True)
        return permissions_for_role(self._access.global_role)

    def permissions_for_location(self, *, location_name: str) -> Mapping[str, PermissionResult]:
        if self.read_only:
            return get_location_scoped_user_permissions(True)
        return location_scoped_permissions_for_role(self._access.role_for_location(location_name))

    def can_view_run(self, run: DagsterRun) -> bool:
        return self._access.can_view_location_runs(location_name_for_run(run))

    @cached_property
    def _visible_repository_labels(self) -> Sequence[str]:
        # Collect labels from the runs table rather than the current workspace, so that runs from
        # code locations that are failing to load (or were removed) stay visible to their viewers.
        labels = set()
        for key, values in self.instance.get_run_tags(tag_keys=[REPOSITORY_LABEL_TAG]):
            if key != REPOSITORY_LABEL_TAG:
                continue
            for label in values:
                location_name = location_name_from_repository_label(label)
                if location_name and self._access.can_view_location_runs(location_name):
                    labels.add(label)
        return sorted(labels)

    def scope_runs_filter(self, filters: RunsFilter | None) -> RunsFilter | None:
        if self._access.can_view_all_runs:
            return filters

        allowed = set(self._visible_repository_labels)
        filters = filters or RunsFilter()
        requested = filters.tags.get(REPOSITORY_LABEL_TAG)
        if requested is not None:
            allowed &= {requested} if isinstance(requested, str) else set(requested)

        return copy(
            filters,
            tags={
                **filters.tags,
                REPOSITORY_LABEL_TAG: sorted(allowed) or [NO_VISIBLE_RUNS_SENTINEL],
            },
        )
