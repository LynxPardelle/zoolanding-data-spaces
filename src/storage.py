"""Single-table persistence with server-derived keys and conditional writes."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import math
import os
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Mapping

try:  # Lambda packages the contents of src/ at the import root.
    from domain.records import public_projection
    from domain.schema_policy import validate_record, validate_schema
except ModuleNotFoundError:  # Repository-root unit test imports use src.*.
    from src.domain.records import public_projection
    from src.domain.schema_policy import validate_record, validate_schema


SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
ACTOR_HASH_RE = re.compile(r"^[a-f0-9]{64}$")
IDEMPOTENCY_TTL_SECONDS = 90 * 24 * 60 * 60
MAX_PAGE_SIZE = 100


class StorageError(RuntimeError):
    pass


class StorageConflict(StorageError):
    pass


class StorageNotFound(StorageError):
    pass


class StorageLimitExceeded(StorageError):
    pass


class ConditionalWriteFailed(RuntimeError):
    """Backend-neutral conditional transaction failure."""


@dataclass(frozen=True)
class Scope:
    environment: str
    tenant_id: str
    draft_id: str
    space_id: str

    def __post_init__(self) -> None:
        if self.environment not in {"test", "production"}:
            raise ValueError("environment must be test or production")
        for value in (self.tenant_id, self.draft_id, self.space_id):
            _safe_id(value)

    @property
    def partition_key(self) -> str:
        return (
            f"ENV#{self.environment}#TENANT#{self.tenant_id}#"
            f"DRAFT#{self.draft_id}#SPACE#{self.space_id}"
        )


class DataSpaceStore:
    def __init__(self, backend: Any, table_name: str) -> None:
        if not isinstance(table_name, str) or not table_name.strip():
            raise ValueError("table_name is required")
        self.backend = backend
        self.table_name = table_name.strip()

    @classmethod
    def from_environment(cls) -> "DataSpaceStore":
        table_name = os.environ.get("DATA_SPACES_TABLE_NAME", "").strip()
        if not table_name:
            raise RuntimeError("DATA_SPACES_TABLE_NAME is required")
        import boto3  # Runtime dependency; unit tests inject a fake backend.

        return cls(_DynamoBackend(boto3.client("dynamodb")), table_name)

    def create_collection(
        self,
        scope: Scope,
        collection_id: str,
        schema: Mapping[str, Any],
        limits: Mapping[str, Any],
        *,
        idempotency_key: str,
        actor_hash: str,
        now_epoch: int,
        allowed_classifications: tuple[str, ...] = ("public", "internal"),
    ) -> dict[str, Any]:
        collection_id = _safe_id(collection_id)
        limits = _limits(limits)
        request = {
            "action": "createCollection",
            "collectionId": collection_id,
            "schema": schema,
            "actorHash": _actor_hash(actor_hash),
        }
        replay, receipt = self._replay(scope, idempotency_key, request)
        if replay is not None:
            return replay
        checked_schema = validate_schema(
            schema,
            max_fields=limits["maxFieldsPerCollection"],
            allowed_classifications=allowed_classifications,
        )
        timestamp = _timestamp(now_epoch)
        space = self.backend.get(self.table_name, scope.partition_key, "SPACE")
        collection_count = space.get("collectionCount", 0) if space else 0
        if collection_count >= limits["maxCollections"]:
            raise StorageLimitExceeded("maxCollections reached")
        current = {
            "pk": scope.partition_key,
            "sk": f"SCHEMA#{collection_id}",
            "itemType": "CollectionSchema",
            "collectionId": collection_id,
            "revision": 1,
            "recordCount": 0,
            "schema": checked_schema,
            "createdAt": timestamp,
            "updatedAt": timestamp,
        }
        revision = {**current, "sk": f"SCHEMA_REV#{collection_id}#0000000001", "itemType": "CollectionSchemaRevision"}
        revision.pop("recordCount")
        result = {"collectionId": collection_id, "revision": 1}
        space_item = {
            "pk": scope.partition_key,
            "sk": "SPACE",
            "itemType": "DataSpace",
            "spaceId": scope.space_id,
            "collectionCount": collection_count + 1,
            "createdAt": space.get("createdAt", timestamp) if space else timestamp,
        }
        operations = [
            {
                "kind": "put",
                "item": space_item,
                "condition": {"collectionCount": collection_count} if space else "absent",
            },
        ]
        operations.extend(
            [
                {"kind": "put", "item": current, "condition": "absent"},
                {"kind": "put", "item": revision, "condition": "absent"},
                {"kind": "put", "item": self._audit(scope, request, receipt, now_epoch, collectionId=collection_id)},
                {"kind": "put", "item": self._receipt(scope, receipt, result, now_epoch), "condition": "absent"},
            ]
        )
        self._transact(operations)
        return result

    def update_collection(
        self,
        scope: Scope,
        collection_id: str,
        schema: Mapping[str, Any],
        limits: Mapping[str, Any],
        *,
        expected_revision: int,
        idempotency_key: str,
        actor_hash: str,
        now_epoch: int,
        allowed_classifications: tuple[str, ...] = ("public", "internal"),
    ) -> dict[str, Any]:
        collection_id = _safe_id(collection_id)
        expected_revision = _revision(expected_revision)
        limits = _limits(limits)
        request = {
            "action": "updateCollection",
            "collectionId": collection_id,
            "expectedRevision": expected_revision,
            "schema": schema,
            "actorHash": _actor_hash(actor_hash),
        }
        replay, receipt = self._replay(scope, idempotency_key, request)
        if replay is not None:
            return replay
        checked_schema = validate_schema(
            schema,
            max_fields=limits["maxFieldsPerCollection"],
            allowed_classifications=allowed_classifications,
        )
        current = self._get(scope, f"SCHEMA#{collection_id}")
        if current["revision"] != expected_revision:
            raise StorageConflict("collection revision is stale")
        if current.get("recordCount", 0) > 0 and not _schema_preserves_existing_fields(current["schema"], checked_schema):
            raise StorageConflict("schema changes must preserve existing fields once records exist")

        next_revision = expected_revision + 1
        timestamp = _timestamp(now_epoch)
        updated = {
            **current,
            "revision": next_revision,
            "schema": checked_schema,
            "updatedAt": timestamp,
        }
        immutable = {
            **updated,
            "sk": f"SCHEMA_REV#{collection_id}#{next_revision:010d}",
            "itemType": "CollectionSchemaRevision",
        }
        immutable.pop("recordCount", None)
        result = {"collectionId": collection_id, "revision": next_revision}
        self._transact(
            [
                {
                    "kind": "put",
                    "item": updated,
                    "condition": {"revision": expected_revision, "recordCount": current.get("recordCount", 0)},
                },
                {"kind": "put", "item": immutable, "condition": "absent"},
                {"kind": "put", "item": self._audit(scope, request, receipt, now_epoch, collectionId=collection_id)},
                {"kind": "put", "item": self._receipt(scope, receipt, result, now_epoch), "condition": "absent"},
            ]
        )
        return result

    def create_record(
        self,
        scope: Scope,
        collection_id: str,
        record_id: str,
        data: Mapping[str, Any],
        limits: Mapping[str, Any],
        *,
        idempotency_key: str,
        actor_hash: str,
        now_epoch: int,
    ) -> dict[str, Any]:
        collection_id, record_id = _safe_id(collection_id), _safe_id(record_id)
        limits = _limits(limits)
        request = {
            "action": "createRecord",
            "collectionId": collection_id,
            "recordId": record_id,
            "data": data,
            "actorHash": _actor_hash(actor_hash),
        }
        replay, receipt = self._replay(scope, idempotency_key, request)
        if replay is not None:
            return replay
        collection = self._get(scope, f"SCHEMA#{collection_id}")
        checked_data = validate_record(collection["schema"], data, limits["maxRecordBytes"])
        record_count = collection.get("recordCount", 0)
        if record_count >= limits["maxRecordsPerCollection"]:
            raise StorageLimitExceeded("maxRecordsPerCollection reached")

        timestamp = _timestamp(now_epoch)
        current = {
            "pk": scope.partition_key,
            "sk": f"RECORD#{collection_id}#{record_id}",
            "itemType": "Record",
            "collectionId": collection_id,
            "recordId": record_id,
            "revision": 1,
            "schemaRevision": collection["revision"],
            "status": "draft",
            "data": checked_data,
            "createdAt": timestamp,
            "updatedAt": timestamp,
        }
        immutable = {
            **current,
            "sk": f"RECORD_REV#{collection_id}#{record_id}#0000000001",
            "itemType": "RecordRevision",
        }
        result = {"collectionId": collection_id, "recordId": record_id, "revision": 1, "status": "draft"}
        self._transact(
            [
                {
                    "kind": "put",
                    "item": {**collection, "recordCount": record_count + 1, "updatedAt": timestamp},
                    "condition": {"revision": collection["revision"], "recordCount": record_count},
                },
                {"kind": "put", "item": current, "condition": "absent"},
                {"kind": "put", "item": immutable, "condition": "absent"},
                {"kind": "put", "item": self._audit(scope, request, receipt, now_epoch, collectionId=collection_id, recordId=record_id)},
                {"kind": "put", "item": self._receipt(scope, receipt, result, now_epoch), "condition": "absent"},
            ]
        )
        return result

    def update_record(
        self,
        scope: Scope,
        collection_id: str,
        record_id: str,
        data: Mapping[str, Any],
        limits: Mapping[str, Any],
        *,
        expected_revision: int,
        idempotency_key: str,
        actor_hash: str,
        now_epoch: int,
    ) -> dict[str, Any]:
        collection_id, record_id = _safe_id(collection_id), _safe_id(record_id)
        expected_revision = _revision(expected_revision)
        limits = _limits(limits)
        request = {
            "action": "updateRecord",
            "collectionId": collection_id,
            "recordId": record_id,
            "expectedRevision": expected_revision,
            "data": data,
            "actorHash": _actor_hash(actor_hash),
        }
        replay, receipt = self._replay(scope, idempotency_key, request)
        if replay is not None:
            return replay
        collection = self._get(scope, f"SCHEMA#{collection_id}")
        current = self._get(scope, f"RECORD#{collection_id}#{record_id}")
        checked_data = validate_record(collection["schema"], data, limits["maxRecordBytes"])
        if current["revision"] != expected_revision:
            raise StorageConflict("record revision is stale")

        next_revision = expected_revision + 1
        updated = {
            **current,
            "revision": next_revision,
            "schemaRevision": collection["revision"],
            "data": checked_data,
            "updatedAt": _timestamp(now_epoch),
        }
        immutable = {
            **updated,
            "sk": f"RECORD_REV#{collection_id}#{record_id}#{next_revision:010d}",
            "itemType": "RecordRevision",
        }
        result = {
            "collectionId": collection_id,
            "recordId": record_id,
            "revision": next_revision,
            "status": updated["status"],
        }
        self._transact(
            [
                {
                    "kind": "condition",
                    "pk": scope.partition_key,
                    "sk": f"SCHEMA#{collection_id}",
                    "condition": {"revision": collection["revision"]},
                },
                {"kind": "put", "item": updated, "condition": {"revision": expected_revision}},
                {"kind": "put", "item": immutable, "condition": "absent"},
                {"kind": "put", "item": self._audit(scope, request, receipt, now_epoch, collectionId=collection_id, recordId=record_id)},
                {"kind": "put", "item": self._receipt(scope, receipt, result, now_epoch), "condition": "absent"},
            ]
        )
        return result

    def publish_record(
        self,
        scope: Scope,
        collection_id: str,
        record_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
        actor_hash: str,
        now_epoch: int,
    ) -> dict[str, Any]:
        return self._set_publication(
            scope,
            collection_id,
            record_id,
            True,
            expected_revision,
            idempotency_key,
            actor_hash,
            now_epoch,
        )

    def unpublish_record(
        self,
        scope: Scope,
        collection_id: str,
        record_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
        actor_hash: str,
        now_epoch: int,
    ) -> dict[str, Any]:
        return self._set_publication(
            scope,
            collection_id,
            record_id,
            False,
            expected_revision,
            idempotency_key,
            actor_hash,
            now_epoch,
        )

    def get_collection(self, scope: Scope, collection_id: str) -> dict[str, Any]:
        return _external(self._get(scope, f"SCHEMA#{_safe_id(collection_id)}"))

    def get_record(self, scope: Scope, collection_id: str, record_id: str) -> dict[str, Any]:
        return _external(self._get(scope, f"RECORD#{_safe_id(collection_id)}#{_safe_id(record_id)}"))

    def get_record_revision(
        self,
        scope: Scope,
        collection_id: str,
        record_id: str,
        revision: int,
    ) -> dict[str, Any]:
        return _external(
            self._get(
                scope,
                f"RECORD_REV#{_safe_id(collection_id)}#{_safe_id(record_id)}#{_revision(revision):010d}",
            )
        )

    def get_public_record(self, scope: Scope, collection_id: str, record_id: str) -> dict[str, Any]:
        return _public_external(self._get(scope, f"PUBLIC#{_safe_id(collection_id)}#{_safe_id(record_id)}"))

    def list_collections(self, scope: Scope, limit: int = 25, cursor: str | None = None):
        return self._list(scope, "SCHEMA#", limit, cursor)

    def list_records(self, scope: Scope, collection_id: str, limit: int = 25, cursor: str | None = None):
        return self._list(scope, f"RECORD#{_safe_id(collection_id)}#", limit, cursor)

    def list_public_records(self, scope: Scope, collection_id: str, limit: int = 25, cursor: str | None = None):
        return self._list(scope, f"PUBLIC#{_safe_id(collection_id)}#", limit, cursor, public=True)

    def _set_publication(
        self,
        scope: Scope,
        collection_id: str,
        record_id: str,
        publish: bool,
        expected_revision: int,
        idempotency_key: str,
        actor_hash: str,
        now_epoch: int,
    ) -> dict[str, Any]:
        collection_id, record_id = _safe_id(collection_id), _safe_id(record_id)
        expected_revision = _revision(expected_revision)
        action = "publishRecord" if publish else "unpublishRecord"
        request = {
            "action": action,
            "collectionId": collection_id,
            "recordId": record_id,
            "expectedRevision": expected_revision,
            "actorHash": _actor_hash(actor_hash),
        }
        replay, receipt = self._replay(scope, idempotency_key, request)
        if replay is not None:
            return replay
        current = self._get(scope, f"RECORD#{collection_id}#{record_id}")
        collection = self._get(scope, f"SCHEMA#{collection_id}")
        if current["revision"] != expected_revision:
            raise StorageConflict("record revision is stale")

        next_revision = expected_revision + 1
        timestamp = _timestamp(now_epoch)
        updated = {
            **current,
            "revision": next_revision,
            "status": "published" if publish else "draft",
            "updatedAt": timestamp,
        }
        if publish:
            updated["publishedRevision"] = next_revision
        else:
            updated.pop("publishedRevision", None)
        immutable = {
            **updated,
            "sk": f"RECORD_REV#{collection_id}#{record_id}#{next_revision:010d}",
            "itemType": "RecordRevision",
        }
        result = {
            "collectionId": collection_id,
            "recordId": record_id,
            "revision": next_revision,
            "status": updated["status"],
        }
        public_key = f"PUBLIC#{collection_id}#{record_id}"
        public_operation: dict[str, Any]
        if publish:
            checked_data = validate_record(collection["schema"], current["data"])
            projection = public_projection(collection["schema"], checked_data)
            if not projection:
                raise StorageConflict("record has no public fields")
            public_operation = {
                "kind": "put",
                "item": {
                    "pk": scope.partition_key,
                    "sk": public_key,
                    "itemType": "PublishedRecord",
                    "collectionId": collection_id,
                    "recordId": record_id,
                    "revision": next_revision,
                    "sourceRevision": expected_revision,
                    "schemaRevision": collection["revision"],
                    "data": projection,
                    "publishedAt": timestamp,
                },
            }
        else:
            public_operation = {"kind": "delete", "pk": scope.partition_key, "sk": public_key}
        self._transact(
            [
                {
                    "kind": "condition",
                    "pk": scope.partition_key,
                    "sk": f"SCHEMA#{collection_id}",
                    "condition": {"revision": collection["revision"]},
                },
                {"kind": "put", "item": updated, "condition": {"revision": expected_revision}},
                {"kind": "put", "item": immutable, "condition": "absent"},
                public_operation,
                {"kind": "put", "item": self._audit(scope, request, receipt, now_epoch, collectionId=collection_id, recordId=record_id)},
                {"kind": "put", "item": self._receipt(scope, receipt, result, now_epoch), "condition": "absent"},
            ]
        )
        return result

    def _get(self, scope: Scope, sk: str) -> dict[str, Any]:
        item = self.backend.get(self.table_name, scope.partition_key, sk)
        if not item:
            raise StorageNotFound("item not found")
        return item

    def _list(self, scope: Scope, prefix: str, limit: int, cursor: str | None, public: bool = False):
        bounded = max(1, min(_integer(limit, "limit"), MAX_PAGE_SIZE))
        if cursor is not None and (
            not isinstance(cursor, str)
            or not cursor.startswith(prefix)
            or len(cursor) > 256
            or any(ord(character) < 32 for character in cursor)
        ):
            raise ValueError("cursor is invalid for this collection")
        items, next_cursor = self.backend.query(
            self.table_name,
            scope.partition_key,
            prefix,
            bounded,
            cursor,
        )
        project = _public_external if public else _external
        return [project(item) for item in items], next_cursor

    def _replay(self, scope: Scope, idempotency_key: str, request: Mapping[str, Any]):
        digest = _idempotency_digest(idempotency_key)
        request_hash = _hash_json(request)
        sk = f"IDEMPOTENCY#{digest}"
        existing = self.backend.get(self.table_name, scope.partition_key, sk)
        if existing:
            if existing.get("requestHash") != request_hash:
                raise StorageConflict("idempotency key was already used")
            return copy.deepcopy(existing["result"]), {"sk": sk, "requestHash": request_hash, "requestId": digest[:32]}
        return None, {"sk": sk, "requestHash": request_hash, "requestId": digest[:32]}

    def _receipt(self, scope: Scope, receipt: Mapping[str, str], result: Mapping[str, Any], now_epoch: int):
        return {
            "pk": scope.partition_key,
            "sk": receipt["sk"],
            "itemType": "IdempotencyReceipt",
            "requestHash": receipt["requestHash"],
            "result": copy.deepcopy(result),
            "createdAt": _timestamp(now_epoch),
            "expiresAt": _epoch(now_epoch) + IDEMPOTENCY_TTL_SECONDS,
        }

    def _audit(
        self,
        scope: Scope,
        request: Mapping[str, Any],
        receipt: Mapping[str, str],
        now_epoch: int,
        **entity_ids: str,
    ) -> dict[str, Any]:
        item = {
            "pk": scope.partition_key,
            "sk": f"AUDIT#{_timestamp(now_epoch)}#{receipt['requestId']}",
            "itemType": "Audit",
            "action": request["action"],
            "actorHash": request["actorHash"],
            "requestId": receipt["requestId"],
            "correlationId": receipt["requestId"],
            "occurredAt": _timestamp(now_epoch),
        }
        item.update(entity_ids)
        return item

    def _transact(self, operations: list[dict[str, Any]]) -> None:
        try:
            self.backend.transact(self.table_name, operations)
        except ConditionalWriteFailed as exc:
            raise StorageConflict("conditional write failed") from None


class _DynamoBackend:
    """Small boto3 adapter; domain tests use a deterministic fake."""

    def __init__(self, client: Any) -> None:
        self.client = client

    def get(self, table_name: str, pk: str, sk: str):
        response = self.client.get_item(
            TableName=table_name,
            Key={"pk": {"S": pk}, "sk": {"S": sk}},
            ConsistentRead=True,
        )
        item = response.get("Item")
        return _from_item(item) if item else None

    def query(self, table_name: str, pk: str, sk_prefix: str, limit: int, cursor: str | None = None):
        params = {
            "TableName": table_name,
            "KeyConditionExpression": "#pk = :pk AND begins_with(#sk, :prefix)",
            "ExpressionAttributeNames": {"#pk": "pk", "#sk": "sk"},
            "ExpressionAttributeValues": {":pk": {"S": pk}, ":prefix": {"S": sk_prefix}},
            "Limit": limit,
            "ConsistentRead": True,
        }
        if cursor:
            params["ExclusiveStartKey"] = {"pk": {"S": pk}, "sk": {"S": cursor}}
        response = self.client.query(**params)
        last_key = response.get("LastEvaluatedKey")
        return [_from_item(item) for item in response.get("Items", [])], last_key["sk"]["S"] if last_key else None

    def transact(self, table_name: str, operations: list[dict[str, Any]]) -> None:
        transact_items = []
        for operation in operations:
            if operation["kind"] == "put":
                put = {"TableName": table_name, "Item": _to_item(operation["item"])}
                _apply_condition(put, operation.get("condition"))
                transact_items.append({"Put": put})
            elif operation["kind"] == "delete":
                delete = {
                    "TableName": table_name,
                    "Key": {"pk": {"S": operation["pk"]}, "sk": {"S": operation["sk"]}},
                }
                _apply_condition(delete, operation.get("condition"))
                transact_items.append({"Delete": delete})
            elif operation["kind"] == "condition":
                check = {
                    "TableName": table_name,
                    "Key": {"pk": {"S": operation["pk"]}, "sk": {"S": operation["sk"]}},
                }
                _apply_condition(check, operation.get("condition"))
                transact_items.append({"ConditionCheck": check})
            else:
                raise ValueError("unsupported transaction operation")
        try:
            self.client.transact_write_items(TransactItems=transact_items)
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            reasons = getattr(exc, "response", {}).get("CancellationReasons", [])
            if code == "ConditionalCheckFailedException" or (
                code == "TransactionCanceledException"
                and any(reason.get("Code") == "ConditionalCheckFailed" for reason in reasons if isinstance(reason, Mapping))
            ):
                raise ConditionalWriteFailed() from None
            raise


def _apply_condition(operation: dict[str, Any], condition: Any) -> None:
    if condition == "absent":
        operation["ConditionExpression"] = "attribute_not_exists(#pk) AND attribute_not_exists(#sk)"
        operation["ExpressionAttributeNames"] = {"#pk": "pk", "#sk": "sk"}
    elif isinstance(condition, Mapping):
        names = {}
        values = {}
        clauses = []
        for index, (field, expected) in enumerate(condition.items()):
            name, value = f"#field{index}", f":expected{index}"
            names[name] = field
            values[value] = _to_attribute(expected)
            clauses.append(f"{name} = {value}")
        operation["ConditionExpression"] = " AND ".join(clauses)
        operation["ExpressionAttributeNames"] = names
        operation["ExpressionAttributeValues"] = values


def _to_item(item: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): _to_attribute(value) for key, value in item.items()}


def _to_attribute(value: Any) -> dict[str, Any]:
    if value is None:
        return {"NULL": True}
    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, str):
        return {"S": value}
    if isinstance(value, int):
        return {"N": str(value)}
    if isinstance(value, (float, Decimal)) and math.isfinite(value):
        return {"N": str(Decimal(str(value)))}
    if isinstance(value, list):
        return {"L": [_to_attribute(item) for item in value]}
    if isinstance(value, Mapping):
        return {"M": {str(key): _to_attribute(item) for key, item in value.items()}}
    raise TypeError(f"unsupported DynamoDB value: {type(value).__name__}")


def _from_item(item: Mapping[str, Any]) -> dict[str, Any]:
    return {key: _from_attribute(value) for key, value in item.items()}


def _from_attribute(value: Mapping[str, Any]) -> Any:
    if "NULL" in value:
        return None
    if "BOOL" in value:
        return value["BOOL"]
    if "S" in value:
        return value["S"]
    if "N" in value:
        number = Decimal(value["N"])
        return int(number) if number == number.to_integral_value() else float(number)
    if "L" in value:
        return [_from_attribute(item) for item in value["L"]]
    if "M" in value:
        return {key: _from_attribute(item) for key, item in value["M"].items()}
    raise ValueError("unsupported DynamoDB attribute")


def _external(item: Mapping[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(value) for key, value in item.items() if key not in {"pk", "sk", "itemType"}}


def _public_external(item: Mapping[str, Any]) -> dict[str, Any]:
    keys = {"collectionId", "recordId", "revision", "data", "publishedAt"}
    return {key: copy.deepcopy(value) for key, value in item.items() if key in keys}


def _safe_id(value: Any) -> str:
    if not isinstance(value, str) or not SAFE_ID_RE.fullmatch(value):
        raise ValueError("id must be a lowercase safe id")
    return value


def _actor_hash(value: Any) -> str:
    if not isinstance(value, str) or not ACTOR_HASH_RE.fullmatch(value):
        raise ValueError("actor_hash must be a lowercase SHA-256 hex digest")
    return value


def _idempotency_digest(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 256 or any(ord(character) < 32 for character in value):
        raise ValueError("idempotency_key is invalid")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _hash_json(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _schema_preserves_existing_fields(current: Mapping[str, Any], updated: Mapping[str, Any]) -> bool:
    current_fields = current.get("fields")
    updated_fields = updated.get("fields")
    if not isinstance(current_fields, list) or not isinstance(updated_fields, list):
        return False
    updated_by_id = {
        field.get("id"): field
        for field in updated_fields
        if isinstance(field, Mapping) and isinstance(field.get("id"), str)
    }
    return all(
        isinstance(field, Mapping)
        and isinstance(field.get("id"), str)
        and updated_by_id.get(field["id"]) == field
        for field in current_fields
    )


def _limits(value: Mapping[str, Any]) -> dict[str, int]:
    keys = {"maxCollections", "maxFieldsPerCollection", "maxRecordsPerCollection", "maxRecordBytes"}
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError("limits are invalid")
    limits = {key: _integer(value[key], key) for key in keys}
    if not 1 <= limits["maxCollections"] <= 100:
        raise ValueError("maxCollections is invalid")
    if not 1 <= limits["maxFieldsPerCollection"] <= 200:
        raise ValueError("maxFieldsPerCollection is invalid")
    if not 1 <= limits["maxRecordsPerCollection"] <= 1_000_000:
        raise ValueError("maxRecordsPerCollection is invalid")
    if not 1_024 <= limits["maxRecordBytes"] <= 400_000:
        raise ValueError("maxRecordBytes is invalid")
    return limits


def _integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    return value


def _revision(value: Any) -> int:
    revision = _integer(value, "revision")
    if revision < 1:
        raise ValueError("revision must be positive")
    return revision


def _epoch(value: Any) -> int:
    epoch = _integer(value, "now_epoch")
    if epoch < 0:
        raise ValueError("now_epoch must be non-negative")
    return epoch


def _timestamp(value: Any) -> str:
    return dt.datetime.fromtimestamp(_epoch(value), tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
