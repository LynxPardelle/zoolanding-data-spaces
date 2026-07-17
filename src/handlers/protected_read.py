"""Authenticated administrative reads for Data Spaces."""

from __future__ import annotations

from typing import Any

try:  # Lambda CodeUri is src/.
    from common.auth_admin import authorize_request
    from common.http import (
        bounded_page_size,
        closed_object,
        decode_cursor,
        dispatch,
        domain_header,
        encode_cursor,
        resolved_scope,
        safe_id,
        validated_space,
        validation_error,
    )
    from common.published_policy import resolve_policies
    from storage import DataSpaceStore
except ModuleNotFoundError:  # Repository-root tests import src.*.
    from src.common.auth_admin import authorize_request
    from src.common.http import (
        bounded_page_size,
        closed_object,
        decode_cursor,
        dispatch,
        domain_header,
        encode_cursor,
        resolved_scope,
        safe_id,
        validated_space,
        validation_error,
    )
    from src.common.published_policy import resolve_policies
    from src.storage import DataSpaceStore


PATH = "/features/data-spaces/read"
OPERATIONS = {"collectionList", "collectionSchema", "recordList", "recordDetail"}


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    return dispatch(event, PATH, lambda payload, _request_id: _handle(event, payload))


def _handle(event: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    request = closed_object(payload, {"operation", "spaceId", "input"})
    operation = request["operation"]
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise validation_error()
    space_id = safe_id(request["spaceId"])
    input_value = _validated_input(operation, request["input"])
    domain = domain_header(event)

    policies = resolve_policies(domain)
    space = validated_space(policies, space_id)
    authorize_request(
        event=event,
        policies=policies,
        space_id=space_id,
        capability="data-space:record:read",
        mutation=False,
    )
    scope = resolved_scope(policies, space_id)
    store = _store()

    if operation == "collectionSchema":
        return {"item": store.get_collection(scope, input_value["collectionId"])}
    if operation == "recordDetail":
        return {"item": store.get_record(scope, input_value["collectionId"], input_value["recordId"])}

    maximum = space["publicRead"]["maxPageSize"]
    limit = bounded_page_size(input_value.get("limit"), maximum)
    if operation == "collectionList":
        cursor = decode_cursor(policies, scope, "collections", "", input_value.get("cursor"))
        items, next_cursor = store.list_collections(scope, limit, cursor)
        return {"items": items, "cursor": encode_cursor(policies, scope, "collections", "", next_cursor)}

    collection_id = input_value["collectionId"]
    cursor = decode_cursor(policies, scope, "records", collection_id, input_value.get("cursor"))
    items, next_cursor = store.list_records(scope, collection_id, limit, cursor)
    return {"items": items, "cursor": encode_cursor(policies, scope, "records", collection_id, next_cursor)}


def _validated_input(operation: str, value: Any) -> dict[str, Any]:
    if operation == "collectionList":
        return closed_object(value, set(), {"limit", "cursor"})
    if operation == "collectionSchema":
        item = closed_object(value, {"collectionId"})
        safe_id(item["collectionId"])
        return item
    if operation == "recordList":
        item = closed_object(value, {"collectionId"}, {"limit", "cursor"})
        safe_id(item["collectionId"])
        return item
    item = closed_object(value, {"collectionId", "recordId"})
    safe_id(item["collectionId"])
    safe_id(item["recordId"])
    return item


def _store() -> DataSpaceStore:
    return DataSpaceStore.from_environment()
