from collections.abc import Awaitable, Callable, Mapping, Sequence
from inspect import isawaitable
from typing import Any

from dagster._core.workspace.context import BaseWorkspaceRequestContext
from dagster_graphql.schema.errors import GrapheneRunNotFoundError
from dagster_graphql.schema.pipelines.pipeline import GrapheneRun
from graphql import (
    DocumentNode,
    FieldNode,
    GraphQLError,
    GraphQLFormattedError,
    GraphQLInterfaceType,
    GraphQLObjectType,
    GraphQLOutputType,
    GraphQLResolveInfo,
    GraphQLSchema,
    GraphQLUnionType,
    get_named_type,
    is_list_type,
    is_non_null_type,
    parse,
)
from graphql.execution.values import get_argument_values
from graphql.utilities import get_operation_ast

RUN_TYPE_NAME = "Run"
RUN_NOT_FOUND_TYPE_NAME = "RunNotFoundError"
COMPUTE_LOGS_KEY_SEGMENT = "compute_logs"


def run_id_from_log_key(log_key: Sequence[str] | None) -> str | None:
    # Compute logs for a run step are keyed `[run_id, "compute_logs", step_key]`.
    if log_key and len(log_key) >= 2 and log_key[1] == COMPUTE_LOGS_KEY_SEGMENT:
        return log_key[0]
    return None


def run_id_from_field_args(args: Mapping[str, Any]) -> str | None:
    if args.get("runId"):
        return str(args["runId"])
    return run_id_from_log_key(args.get("logKey"))


def can_view_run_id(context: BaseWorkspaceRequestContext, run_id: str) -> bool:
    run = context.instance.get_run_by_id(run_id)
    # A run that doesn't exist reveals nothing; let the resolver report it as not found.
    return run is None or context.can_view_run(run)


def _hidden_run_message(run_id: str) -> str:
    # Same wording as a missing run, so a hidden run's existence is not confirmed.
    return f"Run {run_id} could not be found."


class RunVisibilityMiddleware:
    """GraphQL middleware that hides runs the viewer is not allowed to see.

    It works on types rather than on individual resolvers, so it also covers the many indirect
    paths to a run (run groups, asset materializations, schedule ticks, the runs feed, ...):

    * Any field whose type is `Run`, or a union/interface that can be a `Run`, has hidden runs
      removed from its result (list fields) or replaced with `RunNotFoundError` / null.
    * Root fields keyed by a run (`runId` or a compute `logKey` argument, e.g. `logsForRun` or
      `capturedLogs`) are refused before they resolve.

    Run lists are also pre-filtered in storage by `scope_runs_filter`, so pagination stays correct;
    this middleware is the backstop for every other path.
    """

    def __init__(self, schema: GraphQLSchema):
        self._schema = schema
        run_type = schema.get_type(RUN_TYPE_NAME)
        self._run_not_found_type = schema.get_type(RUN_NOT_FOUND_TYPE_NAME)
        assert isinstance(run_type, GraphQLObjectType)

        root_type_names = {
            root.name for root in (schema.query_type, schema.subscription_type) if root is not None
        }
        self._run_fields: set[tuple[str, str]] = set()
        self._run_keyed_fields: set[tuple[str, str]] = set()
        for type_name, gql_type in schema.type_map.items():
            if not isinstance(gql_type, GraphQLObjectType) or type_name.startswith("__"):
                continue
            for field_name, field in gql_type.fields.items():
                named = get_named_type(field.type)
                if named is run_type or (
                    isinstance(named, (GraphQLInterfaceType, GraphQLUnionType))
                    and schema.is_sub_type(named, run_type)
                ):
                    self._run_fields.add((type_name, field_name))
                if type_name in root_type_names and (
                    "runId" in field.args or "logKey" in field.args
                ):
                    self._run_keyed_fields.add((type_name, field_name))

    def resolve(
        self, next_: Callable[..., Any], root: Any, info: GraphQLResolveInfo, **kwargs: Any
    ) -> Any:
        key = (info.parent_type.name, info.field_name)
        if key in self._run_keyed_fields:
            run_id = run_id_from_field_args(kwargs)
            if run_id and not can_view_run_id(info.context, run_id):
                return self._hidden(info.return_type, run_id)

        result = next_(root, info, **kwargs)
        if key not in self._run_fields:
            return result
        if isawaitable(result):
            return self._filter_awaitable(result, info)
        return self._filter(result, info)

    async def _filter_awaitable(self, result: Awaitable[Any], info: GraphQLResolveInfo) -> Any:
        return self._filter(await result, info)

    def _filter(self, result: Any, info: GraphQLResolveInfo) -> Any:
        context: BaseWorkspaceRequestContext = info.context
        if isinstance(result, GrapheneRun):
            if context.can_view_run(result.dagster_run):
                return result
            return self._hidden(info.return_type, result.dagster_run.run_id)
        if isinstance(result, (list, tuple)):
            return [
                item
                for item in result
                if not isinstance(item, GrapheneRun) or context.can_view_run(item.dagster_run)
            ]
        return result

    def _hidden(self, return_type: GraphQLOutputType, run_id: str) -> Any:
        named = get_named_type(return_type)
        if (
            self._run_not_found_type is not None
            and isinstance(named, (GraphQLInterfaceType, GraphQLUnionType))
            and self._schema.is_sub_type(named, self._run_not_found_type)
        ):
            return GrapheneRunNotFoundError(run_id)
        if not is_non_null_type(return_type) and not is_list_type(return_type):
            return None
        raise GraphQLError(_hidden_run_message(run_id))

    def check_subscription(
        self,
        context: BaseWorkspaceRequestContext,
        query: str,
        variables: Mapping[str, Any] | None,
        operation_name: str | None,
    ) -> GraphQLFormattedError | None:
        """Subscriptions don't run through GraphQL middleware, so run-keyed subscriptions
        (`pipelineRunLogs`, `capturedLogs`) are checked before they start.
        """
        try:
            document: DocumentNode = parse(query)
        except GraphQLError:
            return None  # let the normal subscribe path report the syntax error

        operation = get_operation_ast(document, operation_name)
        subscription_type = self._schema.subscription_type
        if operation is None or subscription_type is None:
            return None

        for selection in operation.selection_set.selections:
            if not isinstance(selection, FieldNode):
                return GraphQLError(
                    "Fragments are not supported at the subscription root."
                ).formatted
            field = subscription_type.fields.get(selection.name.value)
            if field is None:
                continue
            try:
                args = get_argument_values(field, selection, dict(variables or {}))
            except GraphQLError as error:
                return error.formatted
            run_id = run_id_from_field_args(args)
            if run_id and not can_view_run_id(context, run_id):
                return GraphQLError(_hidden_run_message(run_id)).formatted
        return None
