import copy
import os
import subprocess
import sys
import unittest
from pathlib import Path

from src.storage import (
    ConditionalWriteFailed,
    DataSpaceStore,
    Scope,
    StorageConflict,
    StorageLimitExceeded,
    StorageNotFound,
    _DynamoBackend,
)
from src.domain.schema_policy import SchemaPolicyError


SCHEMA = {
    "fields": [
        {"id": "title", "type": "string", "classification": "public", "required": True},
        {"id": "note", "type": "string", "classification": "internal"},
    ]
}
LIMITS = {
    "maxCollections": 3,
    "maxFieldsPerCollection": 10,
    "maxRecordsPerCollection": 5,
    "maxRecordBytes": 10_000,
}
ACTOR_HASH = "a" * 64


class FakeBackend:
    def __init__(self):
        self.items = {}
        self.transactions = []
        self.queries = []
        self.before_transact = None

    def get(self, table_name, pk, sk):
        return copy.deepcopy(self.items.get((table_name, pk, sk)))

    def query(self, table_name, pk, sk_prefix, limit, cursor=None):
        self.queries.append((table_name, pk, sk_prefix, limit, cursor))
        items = [
            copy.deepcopy(item)
            for (table, item_pk, sk), item in sorted(self.items.items())
            if table == table_name and item_pk == pk and sk.startswith(sk_prefix)
            and (cursor is None or sk > cursor)
        ]
        page = items[:limit]
        next_cursor = page[-1]["sk"] if len(items) > limit else None
        return page, next_cursor

    def transact(self, table_name, operations):
        if self.before_transact:
            callback, self.before_transact = self.before_transact, None
            callback()
        candidate = copy.deepcopy(self.items)
        for operation in operations:
            kind = operation["kind"]
            item = operation.get("item", {})
            key = (table_name, operation.get("pk") or item.get("pk"), operation.get("sk") or item.get("sk"))
            current = candidate.get(key)
            condition = operation.get("condition")
            if condition == "absent" and current is not None:
                raise ConditionalWriteFailed()
            if isinstance(condition, dict) and current and any(current.get(field) != expected for field, expected in condition.items()):
                raise ConditionalWriteFailed()
            if isinstance(condition, dict) and current is None:
                raise ConditionalWriteFailed()
            if kind == "put":
                candidate[key] = copy.deepcopy(operation["item"])
            elif kind == "delete":
                candidate.pop(key, None)
            elif kind == "condition":
                pass
            else:
                raise AssertionError(f"unknown operation {kind}")
        self.items = candidate
        self.transactions.append(copy.deepcopy(operations))


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.backend = FakeBackend()
        self.store = DataSpaceStore(self.backend, "data-table")
        self.scope = Scope("test", "tenant-a", "draft-a", "content")

    def _create_collection(self):
        return self.store.create_collection(
            self.scope,
            "articles",
            SCHEMA,
            LIMITS,
            idempotency_key="create-articles",
            actor_hash=ACTOR_HASH,
            now_epoch=1_721_173_200,
        )

    def _create_record(self):
        self._create_collection()
        return self.store.create_record(
            self.scope,
            "articles",
            "welcome",
            {"title": "Welcome", "note": "internal"},
            LIMITS,
            idempotency_key="create-welcome",
            actor_hash=ACTOR_HASH,
            now_epoch=1_721_173_300,
        )

    def test_scope_derives_isolated_partition_and_rejects_untrusted_key_parts(self):
        self.assertEqual(
            self.scope.partition_key,
            "ENV#test#TENANT#tenant-a#DRAFT#draft-a#SPACE#content",
        )
        self.assertNotEqual(
            self.scope.partition_key,
            Scope("test", "tenant-a", "draft-b", "content").partition_key,
        )
        for value in ["../draft", "x#y", "", "UPPER"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                Scope("test", "tenant-a", value, "content")

    def test_create_collection_writes_current_revision_audit_and_expiring_receipt_atomically(self):
        result = self._create_collection()

        self.assertEqual(result["collectionId"], "articles")
        self.assertEqual(result["revision"], 1)
        operations = self.backend.transactions[-1]
        keys = [operation["item"]["sk"] for operation in operations]
        self.assertIn("SCHEMA#articles", keys)
        self.assertIn("SCHEMA_REV#articles#0000000001", keys)
        self.assertTrue(any(key.startswith("AUDIT#") for key in keys))
        receipt = next(operation["item"] for operation in operations if operation["item"]["sk"].startswith("IDEMPOTENCY#"))
        self.assertEqual(receipt["expiresAt"], 1_721_173_200 + 90 * 24 * 60 * 60)
        self.assertFalse(any("expiresAt" in operation["item"] for operation in operations if operation["item"] is not receipt))
        self.assertTrue(all(operation["item"]["pk"] == self.scope.partition_key for operation in operations))
        audit = next(operation["item"] for operation in operations if operation["item"]["sk"].startswith("AUDIT#"))
        self.assertEqual(audit["actorHash"], ACTOR_HASH)
        self.assertNotIn("schema", audit)
        self.assertNotIn("data", audit)
        space = self.backend.get("data-table", self.scope.partition_key, "SPACE")
        self.assertEqual(
            space,
            {
                "pk": self.scope.partition_key,
                "sk": "SPACE",
                "itemType": "DataSpace",
                "spaceId": "content",
                "collectionCount": 1,
                "createdAt": "2024-07-16T23:40:00Z",
            },
        )

    def test_idempotency_replays_same_request_and_rejects_key_reuse(self):
        first = self._create_collection()
        transaction_count = len(self.backend.transactions)

        second = self._create_collection()

        self.assertEqual(second, first)
        self.assertEqual(len(self.backend.transactions), transaction_count)
        with self.assertRaises(StorageConflict):
            self.store.create_collection(
                self.scope,
                "different",
                SCHEMA,
                LIMITS,
                idempotency_key="create-articles",
                actor_hash=ACTOR_HASH,
                now_epoch=1_721_173_200,
            )

    def test_idempotent_record_replay_survives_a_later_schema_change(self):
        created = self._create_record()
        changed_schema = {
            "fields": SCHEMA["fields"]
            + [{"id": "slug", "type": "string", "classification": "public", "required": True}]
        }
        self.store.update_collection(
            self.scope,
            "articles",
            changed_schema,
            LIMITS,
            expected_revision=1,
            idempotency_key="change-schema",
            actor_hash=ACTOR_HASH,
            now_epoch=1_721_173_400,
        )

        replay = self.store.create_record(
            self.scope,
            "articles",
            "welcome",
            {"title": "Welcome", "note": "internal"},
            LIMITS,
            idempotency_key="create-welcome",
            actor_hash=ACTOR_HASH,
            now_epoch=1_721_173_900,
        )

        self.assertEqual(replay, created)

    def test_publish_revalidates_old_record_against_current_schema(self):
        self._create_record()
        changed_schema = {
            "fields": SCHEMA["fields"]
            + [{"id": "slug", "type": "string", "classification": "public", "required": True}]
        }
        self.store.update_collection(
            self.scope,
            "articles",
            changed_schema,
            LIMITS,
            expected_revision=1,
            idempotency_key="require-slug",
            actor_hash=ACTOR_HASH,
            now_epoch=1_721_173_400,
        )

        with self.assertRaises(SchemaPolicyError):
            self.store.publish_record(
                self.scope,
                "articles",
                "welcome",
                expected_revision=1,
                idempotency_key="publish-invalid-old-record",
                actor_hash=ACTOR_HASH,
                now_epoch=1_721_173_600,
            )

    def test_update_collection_uses_expected_revision_and_keeps_immutable_revision(self):
        self._create_collection()
        updated_schema = {"fields": SCHEMA["fields"] + [{"id": "slug", "type": "string", "classification": "public"}]}

        result = self.store.update_collection(
            self.scope,
            "articles",
            updated_schema,
            LIMITS,
            expected_revision=1,
            idempotency_key="update-articles-2",
            actor_hash=ACTOR_HASH,
            now_epoch=1_721_173_400,
        )

        self.assertEqual(result["revision"], 2)
        self.assertIsNotNone(self.backend.get("data-table", self.scope.partition_key, "SCHEMA_REV#articles#0000000001"))
        self.assertIsNotNone(self.backend.get("data-table", self.scope.partition_key, "SCHEMA_REV#articles#0000000002"))
        with self.assertRaises(StorageConflict):
            self.store.update_collection(
                self.scope,
                "articles",
                updated_schema,
                LIMITS,
                expected_revision=1,
                idempotency_key="stale-update",
                actor_hash=ACTOR_HASH,
                now_epoch=1_721_173_500,
            )

    def test_create_and_update_record_validate_against_server_schema_and_revision(self):
        created = self._create_record()
        self.assertEqual(created["revision"], 1)

        updated = self.store.update_record(
            self.scope,
            "articles",
            "welcome",
            {"title": "Updated", "note": "still internal"},
            LIMITS,
            expected_revision=1,
            idempotency_key="update-welcome",
            actor_hash=ACTOR_HASH,
            now_epoch=1_721_173_500,
        )

        self.assertEqual(updated["revision"], 2)
        self.assertIsNotNone(self.backend.get("data-table", self.scope.partition_key, "RECORD_REV#articles#welcome#0000000001"))
        self.assertIsNotNone(self.backend.get("data-table", self.scope.partition_key, "RECORD_REV#articles#welcome#0000000002"))
        snapshot = self.store.get_record_revision(self.scope, "articles", "welcome", 1)
        self.assertEqual(snapshot["data"], {"title": "Welcome", "note": "internal"})
        self.assertNotIn("pk", snapshot)
        self.assertNotIn("sk", snapshot)
        self.assertNotIn("tenantId", snapshot)
        self.assertNotIn("actorHash", snapshot)
        collection = self.store.get_collection(self.scope, "articles")
        self.assertEqual(collection["recordCount"], 1)
        with self.assertRaises(StorageConflict):
            self.store.update_record(
                self.scope,
                "articles",
                "welcome",
                {"title": "Stale"},
                LIMITS,
                expected_revision=1,
                idempotency_key="stale-record",
                actor_hash=ACTOR_HASH,
                now_epoch=1_721_173_600,
            )

    def test_publish_stores_only_public_projection_and_unpublish_removes_it(self):
        self._create_record()

        published = self.store.publish_record(
            self.scope,
            "articles",
            "welcome",
            expected_revision=1,
            idempotency_key="publish-welcome",
            actor_hash=ACTOR_HASH,
            now_epoch=1_721_173_600,
        )

        self.assertEqual(published["revision"], 2)
        public = self.store.get_public_record(self.scope, "articles", "welcome")
        self.assertEqual(public["data"], {"title": "Welcome"})
        self.assertNotIn("note", repr(public))
        self.assertNotIn("tenantId", public)
        self.assertNotIn("sourceRevision", public)
        self.assertNotIn("schemaRevision", public)
        self.store.unpublish_record(
            self.scope,
            "articles",
            "welcome",
            expected_revision=2,
            idempotency_key="unpublish-welcome",
            actor_hash=ACTOR_HASH,
            now_epoch=1_721_173_700,
        )
        with self.assertRaises(StorageNotFound):
            self.store.get_public_record(self.scope, "articles", "welcome")

    def test_schema_with_records_cannot_remove_or_reclassify_existing_fields(self):
        self._create_record()
        self.store.publish_record(
            self.scope,
            "articles",
            "welcome",
            expected_revision=1,
            idempotency_key="publish-before-schema-change",
            actor_hash=ACTOR_HASH,
            now_epoch=1_721_173_600,
        )

        unsafe_changes = (
            {"fields": [SCHEMA["fields"][1]]},
            {"fields": [{**SCHEMA["fields"][0], "classification": "internal"}, SCHEMA["fields"][1]]},
            {"fields": [{**SCHEMA["fields"][0], "type": "enum", "values": ["Welcome"]}, SCHEMA["fields"][1]]},
        )
        for index, changed_schema in enumerate(unsafe_changes):
            with self.subTest(index=index), self.assertRaises(StorageConflict):
                self.store.update_collection(
                    self.scope,
                    "articles",
                    changed_schema,
                    LIMITS,
                    expected_revision=1,
                    idempotency_key=f"unsafe-schema-change-{index}",
                    actor_hash=ACTOR_HASH,
                    now_epoch=1_721_173_700 + index,
                )

        public = self.store.get_public_record(self.scope, "articles", "welcome")
        self.assertEqual(public["data"], {"title": "Welcome"})

    def test_reads_use_only_fixed_prefixes_and_bounded_limits(self):
        self._create_record()
        self.assertEqual(self.backend.queries, [])

        schemas, _ = self.store.list_collections(self.scope, limit=500)
        records, _ = self.store.list_records(self.scope, "articles", limit=500)
        public, _ = self.store.list_public_records(self.scope, "articles", limit=500)

        self.assertEqual(len(schemas), 1)
        self.assertEqual(len(records), 1)
        self.assertEqual(public, [])
        prefixes = [query[2] for query in self.backend.queries[-3:]]
        self.assertEqual(prefixes, ["SCHEMA#", "RECORD#articles#", "PUBLIC#articles#"])
        self.assertTrue(all(query[3] == 100 for query in self.backend.queries[-3:]))
        with self.assertRaises(ValueError):
            self.store.list_records(self.scope, "articles", cursor="RECORD#articles#" + "x" * 300)

    def test_scope_partition_prevents_cross_draft_reads(self):
        self._create_record()
        other_draft = Scope("test", "tenant-a", "draft-b", "content")

        with self.assertRaises(StorageNotFound):
            self.store.get_collection(other_draft, "articles")
        with self.assertRaises(StorageNotFound):
            self.store.get_record(other_draft, "articles", "welcome")
        with self.assertRaises(StorageNotFound):
            self.store.get_public_record(other_draft, "articles", "welcome")

    def test_counter_conditions_close_concurrent_collection_creation_race(self):
        self._create_collection()

        def competing_write():
            key = ("data-table", self.scope.partition_key, "SPACE")
            self.backend.items[key]["collectionCount"] = 2

        self.backend.before_transact = competing_write
        with self.assertRaises(StorageConflict):
            self.store.create_collection(
                self.scope,
                "pages",
                SCHEMA,
                LIMITS,
                idempotency_key="create-pages",
                actor_hash=ACTOR_HASH,
                now_epoch=1_721_173_800,
            )
        self.assertIsNone(self.backend.get("data-table", self.scope.partition_key, "SCHEMA#pages"))

    def test_schema_update_does_not_overwrite_a_concurrent_record_counter(self):
        self._create_collection()

        def competing_record_counter():
            key = ("data-table", self.scope.partition_key, "SCHEMA#articles")
            self.backend.items[key]["recordCount"] = 1

        self.backend.before_transact = competing_record_counter
        with self.assertRaises(StorageConflict):
            self.store.update_collection(
                self.scope,
                "articles",
                SCHEMA,
                LIMITS,
                expected_revision=1,
                idempotency_key="schema-counter-race",
                actor_hash=ACTOR_HASH,
                now_epoch=1_721_173_800,
            )
        self.assertEqual(self.store.get_collection(self.scope, "articles")["recordCount"], 1)

    def test_record_update_fails_if_schema_changes_after_validation(self):
        self._create_record()

        def competing_schema_update():
            key = ("data-table", self.scope.partition_key, "SCHEMA#articles")
            self.backend.items[key]["revision"] = 2

        self.backend.before_transact = competing_schema_update
        with self.assertRaises(StorageConflict):
            self.store.update_record(
                self.scope,
                "articles",
                "welcome",
                {"title": "Validated against revision one"},
                LIMITS,
                expected_revision=1,
                idempotency_key="record-schema-race",
                actor_hash=ACTOR_HASH,
                now_epoch=1_721_173_800,
            )
        self.assertEqual(self.store.get_record(self.scope, "articles", "welcome")["revision"], 1)

    def test_publish_fails_if_schema_classification_changes_during_transaction(self):
        self._create_record()

        def competing_schema_update():
            key = ("data-table", self.scope.partition_key, "SCHEMA#articles")
            self.backend.items[key]["revision"] = 2
            self.backend.items[key]["schema"]["fields"][0]["classification"] = "internal"

        self.backend.before_transact = competing_schema_update
        with self.assertRaises(StorageConflict):
            self.store.publish_record(
                self.scope,
                "articles",
                "welcome",
                expected_revision=1,
                idempotency_key="publish-schema-race",
                actor_hash=ACTOR_HASH,
                now_epoch=1_721_173_800,
            )
        with self.assertRaises(StorageNotFound):
            self.store.get_public_record(self.scope, "articles", "welcome")

    def test_counters_enforce_collection_and_record_limits_without_scanning(self):
        one_collection = {**LIMITS, "maxCollections": 1}
        self.store.create_collection(
            self.scope,
            "articles",
            SCHEMA,
            one_collection,
            idempotency_key="only-collection",
            actor_hash=ACTOR_HASH,
            now_epoch=1_721_173_200,
        )
        with self.assertRaises(StorageLimitExceeded):
            self.store.create_collection(
                self.scope,
                "pages",
                SCHEMA,
                one_collection,
                idempotency_key="too-many-collections",
                actor_hash=ACTOR_HASH,
                now_epoch=1_721_173_300,
            )
        one_record = {**LIMITS, "maxRecordsPerCollection": 1}
        self.store.create_record(
            self.scope,
            "articles",
            "first",
            {"title": "First"},
            one_record,
            idempotency_key="first-record",
            actor_hash=ACTOR_HASH,
            now_epoch=1_721_173_400,
        )
        with self.assertRaises(StorageLimitExceeded):
            self.store.create_record(
                self.scope,
                "articles",
                "second",
                {"title": "Second"},
                one_record,
                idempotency_key="too-many-records",
                actor_hash=ACTOR_HASH,
                now_epoch=1_721_173_500,
            )
        self.assertEqual(self.backend.queries, [])

    def test_storage_imports_from_lambda_code_uri(self):
        repository = Path(__file__).resolve().parents[1]
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(repository / "src")

        completed = subprocess.run(
            [sys.executable, "-c", "import storage; print(storage.Scope('test','tenant','draft','space').partition_key)"],
            cwd=repository.parent,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ENV#test#TENANT#tenant#DRAFT#draft#SPACE#space", completed.stdout)

    def test_dynamo_adapter_maps_only_confirmed_conditional_cancellations_to_conflict(self):
        class ProviderError(RuntimeError):
            def __init__(self, reasons):
                self.response = {
                    "Error": {"Code": "TransactionCanceledException"},
                    "CancellationReasons": reasons,
                }

        class Client:
            reasons = []

            def transact_write_items(self, **_kwargs):
                raise ProviderError(self.reasons)

        client = Client()
        backend = _DynamoBackend(client)
        operation = [{"kind": "put", "item": {"pk": "p", "sk": "s"}}]

        client.reasons = [{"Code": "ConditionalCheckFailed"}]
        with self.assertRaises(ConditionalWriteFailed) as conflict:
            backend.transact("table", operation)
        self.assertIsNone(conflict.exception.__cause__)
        client.reasons = [{"Code": "ProvisionedThroughputExceeded"}]
        with self.assertRaises(ProviderError):
            backend.transact("table", operation)

    def test_dynamo_adapter_emits_condition_check_without_a_write(self):
        class Client:
            request = None

            def transact_write_items(self, **kwargs):
                self.request = kwargs

        client = Client()
        _DynamoBackend(client).transact(
            "table",
            [
                {
                    "kind": "condition",
                    "pk": "partition",
                    "sk": "SCHEMA#articles",
                    "condition": {"revision": 2},
                }
            ],
        )

        check = client.request["TransactItems"][0]["ConditionCheck"]
        self.assertEqual(check["Key"], {"pk": {"S": "partition"}, "sk": {"S": "SCHEMA#articles"}})
        self.assertEqual(check["ConditionExpression"], "#field0 = :expected0")
        self.assertEqual(check["ExpressionAttributeValues"], {":expected0": {"N": "2"}})


if __name__ == "__main__":
    unittest.main()
