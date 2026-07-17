"""Sanitized published Data Spaces reads."""

from __future__ import annotations

from typing import Any

try:  # Lambda CodeUri is src/.
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
    from common.published_policy import resolve_data_spaces_policy
    from storage import DataSpaceStore
except ModuleNotFoundError:  # Repository-root tests import src.*.
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
    from src.common.published_policy import resolve_data_spaces_policy
    from src.storage import DataSpaceStore


PATH = "/features/data-spaces/public-read"
OPERATIONS = {"recordList", "recordDetail"}


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
    policies = resolve_data_spaces_policy(domain_header(event))
    space = validated_space(policies, space_id, public=True)
    scope = resolved_scope(policies, space_id)
    store = _store()

    collection_id = input_value["collectionId"]
    if operation == "recordDetail":
        return {"item": store.get_public_record(scope, collection_id, input_value["recordId"])}
    limit = bounded_page_size(input_value.get("limit"), space["publicRead"]["maxPageSize"])
    cursor = decode_cursor(policies, scope, "public-records", collection_id, input_value.get("cursor"))
    items, next_cursor = store.list_public_records(scope, collection_id, limit, cursor)
    return {
        "items": items,
        "cursor": encode_cursor(policies, scope, "public-records", collection_id, next_cursor),
    }


def _validated_input(operation: str, value: Any) -> dict[str, Any]:
    if operation == "recordList":
        item = closed_object(value, {"collectionId"}, {"limit", "cursor"})
    else:
        item = closed_object(value, {"collectionId", "recordId"})
        safe_id(item["recordId"])
    safe_id(item["collectionId"])
    return item


def _store() -> DataSpaceStore:
    return DataSpaceStore.from_environment()
