"""Authenticated, CSRF-protected Data Spaces mutations."""

from __future__ import annotations

import hashlib
import time
from typing import Any

try:  # Lambda CodeUri is src/.
    from common.auth_admin import authorize_request
    from common.http import (
        closed_object,
        dispatch,
        domain_header,
        idempotency_header,
        positive_int,
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
        closed_object,
        dispatch,
        domain_header,
        idempotency_header,
        positive_int,
        resolved_scope,
        safe_id,
        validated_space,
        validation_error,
    )
    from src.common.published_policy import resolve_policies
    from src.storage import DataSpaceStore


PATH = "/features/data-spaces/action"
CAPABILITIES = {
    "createCollection": "data-space:schema:write",
    "updateCollection": "data-space:schema:write",
    "createRecord": "data-space:record:write",
    "updateRecord": "data-space:record:write",
    "publishRecord": "data-space:publish",
    "unpublishRecord": "data-space:publish",
}


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    return dispatch(event, PATH, lambda payload, _request_id: _handle(event, payload))


def _handle(event: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    request = closed_object(payload, {"operation", "spaceId", "input"})
    operation = request["operation"]
    if not isinstance(operation, str) or operation not in CAPABILITIES:
        raise validation_error()
    space_id = safe_id(request["spaceId"])
    input_value = _validated_input(operation, request["input"])
    idempotency_key = idempotency_header(event)
    domain = domain_header(event)

    policies = resolve_policies(domain)
    space = validated_space(policies, space_id)
    context = authorize_request(
        event=event,
        policies=policies,
        space_id=space_id,
        capability=CAPABILITIES[operation],
        mutation=True,
    )
    scope = resolved_scope(policies, space_id)
    store = _store()
    common = {
        "idempotency_key": idempotency_key,
        "actor_hash": hashlib.sha256(context.subject.encode("utf-8")).hexdigest(),
        "now_epoch": int(time.time()),
    }
    limits = space["limits"]

    if operation == "createCollection":
        return store.create_collection(
            scope,
            input_value["collectionId"],
            input_value["schema"],
            limits,
            allowed_classifications=tuple(space["allowedClassifications"]),
            **common,
        )
    if operation == "updateCollection":
        return store.update_collection(
            scope,
            input_value["collectionId"],
            input_value["schema"],
            limits,
            expected_revision=input_value["expectedRevision"],
            allowed_classifications=tuple(space["allowedClassifications"]),
            **common,
        )
    if operation == "createRecord":
        return store.create_record(
            scope,
            input_value["collectionId"],
            input_value["recordId"],
            input_value["data"],
            limits,
            **common,
        )
    if operation == "updateRecord":
        return store.update_record(
            scope,
            input_value["collectionId"],
            input_value["recordId"],
            input_value["data"],
            limits,
            expected_revision=input_value["expectedRevision"],
            **common,
        )
    method = store.publish_record if operation == "publishRecord" else store.unpublish_record
    return method(
        scope,
        input_value["collectionId"],
        input_value["recordId"],
        expected_revision=input_value["expectedRevision"],
        **common,
    )


def _validated_input(operation: str, value: Any) -> dict[str, Any]:
    if operation in {"createCollection", "updateCollection"}:
        required = {"collectionId", "schema"}
        if operation == "updateCollection":
            required.add("expectedRevision")
        item = closed_object(value, required)
        safe_id(item["collectionId"])
        if not isinstance(item["schema"], dict):
            raise validation_error()
    elif operation in {"createRecord", "updateRecord"}:
        required = {"collectionId", "recordId", "data"}
        if operation == "updateRecord":
            required.add("expectedRevision")
        item = closed_object(value, required)
        safe_id(item["collectionId"])
        safe_id(item["recordId"])
        if not isinstance(item["data"], dict):
            raise validation_error()
    else:
        item = closed_object(value, {"collectionId", "recordId", "expectedRevision"})
        safe_id(item["collectionId"])
        safe_id(item["recordId"])
    if "expectedRevision" in item:
        positive_int(item["expectedRevision"])
    return item


def _store() -> DataSpaceStore:
    return DataSpaceStore.from_environment()
