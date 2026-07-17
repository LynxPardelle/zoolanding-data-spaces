"""AWS_IAM-protected immutable record snapshot reads."""

from __future__ import annotations

import hashlib
import json
from typing import Any

try:  # Lambda CodeUri is src/.
    from common.iam_caller import require_internal_snapshot_caller
    from common.http import (
        closed_object,
        dispatch,
        domain_header,
        field_ids,
        positive_int,
        resolved_scope,
        safe_id,
        validated_space,
        validation_error,
    )
    from common.published_policy import resolve_data_spaces_policy
    from storage import DataSpaceStore
except ModuleNotFoundError:  # Repository-root tests import src.*.
    from src.common.iam_caller import require_internal_snapshot_caller
    from src.common.http import (
        closed_object,
        dispatch,
        domain_header,
        field_ids,
        positive_int,
        resolved_scope,
        safe_id,
        validated_space,
        validation_error,
    )
    from src.common.published_policy import resolve_data_spaces_policy
    from src.storage import DataSpaceStore


PATH = "/internal/v1/data-spaces/record-snapshot"


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    return dispatch(event, PATH, lambda payload, _request_id: _handle(event, payload))


def _handle(event: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    require_internal_snapshot_caller(event)
    request = closed_object(payload, {"spaceId", "collectionId", "recordId", "revision", "fieldIds"})
    space_id = safe_id(request["spaceId"])
    collection_id = safe_id(request["collectionId"])
    record_id = safe_id(request["recordId"])
    revision = positive_int(request["revision"])
    selected_fields = field_ids(request["fieldIds"])

    policies = resolve_data_spaces_policy(domain_header(event))
    space = validated_space(policies, space_id)
    if len(selected_fields) > space["limits"]["maxFieldsPerCollection"]:
        raise validation_error()
    scope = resolved_scope(policies, space_id)
    item = _store().get_record_revision(scope, collection_id, record_id, revision)
    if (
        item.get("collectionId") != collection_id
        or item.get("recordId") != record_id
        or item.get("revision") != revision
        or not isinstance(item.get("schemaRevision"), int)
        or not isinstance(item.get("data"), dict)
    ):
        raise RuntimeError("invalid immutable snapshot")
    if any(field not in item["data"] for field in selected_fields):
        raise validation_error()
    values = {field: item["data"][field] for field in selected_fields}
    snapshot = {
        "spaceId": space_id,
        "collectionId": collection_id,
        "recordId": record_id,
        "revision": revision,
        "schemaRevision": item["schemaRevision"],
        "values": values,
    }
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {**snapshot, "contentHash": hashlib.sha256(canonical).hexdigest()}


def _store() -> DataSpaceStore:
    return DataSpaceStore.from_environment()
