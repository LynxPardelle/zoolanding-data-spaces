import base64
import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import src.common.http as http
from src.common.auth_admin import AuthenticationError, AuthorizationError, AuthorizedContext
from src.common.published_policy import PolicyResolutionError, ResolvedPolicies
from src.handlers import internal_snapshot_read, protected_action, protected_read, public_read
from src.storage import StorageConflict, StorageNotFound


DOMAIN = "example.com"
TENANT_ID = "tenant-example"
DRAFT_ID = "draft-example"
SPACE_ID = "catalog-content"
ROOT = Path(__file__).resolve().parents[1]
INTERNAL_CALLER_ROLE_ARN = "arn:aws:iam::123456789012:role/zoolanding-commerce-test"
INTERNAL_CALLER_SESSION_ARN = "arn:aws:sts::123456789012:assumed-role/zoolanding-commerce-test/request-1"


def policies(*, environment="test", public_enabled=True):
    space = {
        "id": SPACE_ID,
        "status": "active",
        "access": {
            "mode": "auth-profile",
            "authProfileId": "staff",
            "capabilities": [
                "data-space:record:read",
                "data-space:record:write",
                "data-space:schema:write",
                "data-space:publish",
            ],
        },
        "publicRead": {"enabled": public_enabled, "maxPageSize": 2},
        "allowedClassifications": ["public", "internal"],
        "limits": {
            "maxCollections": 20,
            "maxFieldsPerCollection": 50,
            "maxRecordsPerCollection": 10_000,
            "maxRecordBytes": 65_536,
        },
    }
    return ResolvedPolicies(
        environment=environment,
        tenant_id=TENANT_ID,
        draft_id=DRAFT_ID,
        domain=DOMAIN,
        version_id="version-1",
        prefix=f"sites/{DOMAIN}/versions/version-1/",
        data_spaces={
            "version": 1,
            "scope": {
                "environment": environment,
                "tenantId": TENANT_ID,
                "draftId": DRAFT_ID,
                "domain": DOMAIN,
            },
            "spaces": [space],
        },
        auth_registry={"version": 1, "profiles": []},
    )


def auth_context(resolved):
    space = resolved.data_spaces["spaces"][0]
    return AuthorizedContext(
        environment=resolved.environment,
        tenant_id=resolved.tenant_id,
        draft_id=resolved.draft_id,
        domain=resolved.domain,
        subject="operator-subject",
        roles=("site-admin",),
        profile={"authProfileId": "staff"},
        space=space,
        session={"subject": "operator-subject"},
    )


def api_event(path, payload=None, *, method="POST", headers=None, raw_body=None, base64_encoded=False):
    request_headers = {
        "X-ZLP-Domain": DOMAIN,
        "X-ZLP-Auth-Profile-Id": "staff",
        **(headers or {}),
    }
    body = raw_body if raw_body is not None else json.dumps(payload, separators=(",", ":"))
    return {
        "httpMethod": method,
        "path": path,
        "headers": request_headers,
        "body": body,
        "isBase64Encoded": base64_encoded,
        "requestContext": {"requestId": "request-test-1"},
    }


def response_body(response):
    return json.loads(response["body"])


class FakeStore:
    def __init__(self):
        self.calls = []
        self.failure = None

    def _call(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        if self.failure:
            raise self.failure

    def list_collections(self, scope, limit=25, cursor=None):
        self._call("list_collections", scope, limit, cursor)
        return ([{"collectionId": "articles", "revision": 1}], "SCHEMA#articles")

    def get_collection(self, scope, collection_id):
        self._call("get_collection", scope, collection_id)
        return {"collectionId": collection_id, "revision": 1, "schema": {"fields": []}}

    def list_records(self, scope, collection_id, limit=25, cursor=None):
        self._call("list_records", scope, collection_id, limit, cursor)
        return ([{"collectionId": collection_id, "recordId": "first", "revision": 1}], f"RECORD#{collection_id}#first")

    def get_record(self, scope, collection_id, record_id):
        self._call("get_record", scope, collection_id, record_id)
        return {"collectionId": collection_id, "recordId": record_id, "revision": 1, "data": {"title": "Draft"}}

    def list_public_records(self, scope, collection_id, limit=25, cursor=None):
        self._call("list_public_records", scope, collection_id, limit, cursor)
        return ([{"collectionId": collection_id, "recordId": "first", "data": {"title": "Public"}}], f"PUBLIC#{collection_id}#first")

    def get_public_record(self, scope, collection_id, record_id):
        self._call("get_public_record", scope, collection_id, record_id)
        return {"collectionId": collection_id, "recordId": record_id, "revision": 2, "data": {"title": "Public"}}

    def get_record_revision(self, scope, collection_id, record_id, revision):
        self._call("get_record_revision", scope, collection_id, record_id, revision)
        return {
            "collectionId": collection_id,
            "recordId": record_id,
            "revision": revision,
            "schemaRevision": 3,
            "status": "draft",
            "data": {"title": "Snapshot", "internalNote": "Internal"},
            "createdAt": "2026-01-01T00:00:00Z",
        }

    def create_collection(self, scope, collection_id, schema, limits, **kwargs):
        self._call("create_collection", scope, collection_id, schema, limits, **kwargs)
        return {"collectionId": collection_id, "revision": 1}

    def update_collection(self, scope, collection_id, schema, limits, **kwargs):
        self._call("update_collection", scope, collection_id, schema, limits, **kwargs)
        return {"collectionId": collection_id, "revision": kwargs["expected_revision"] + 1}

    def create_record(self, scope, collection_id, record_id, data, limits, **kwargs):
        self._call("create_record", scope, collection_id, record_id, data, limits, **kwargs)
        return {"collectionId": collection_id, "recordId": record_id, "revision": 1, "status": "draft"}

    def update_record(self, scope, collection_id, record_id, data, limits, **kwargs):
        self._call("update_record", scope, collection_id, record_id, data, limits, **kwargs)
        return {"collectionId": collection_id, "recordId": record_id, "revision": kwargs["expected_revision"] + 1}

    def publish_record(self, scope, collection_id, record_id, **kwargs):
        self._call("publish_record", scope, collection_id, record_id, **kwargs)
        return {"collectionId": collection_id, "recordId": record_id, "revision": kwargs["expected_revision"] + 1, "status": "published"}

    def unpublish_record(self, scope, collection_id, record_id, **kwargs):
        self._call("unpublish_record", scope, collection_id, record_id, **kwargs)
        return {"collectionId": collection_id, "recordId": record_id, "revision": kwargs["expected_revision"] + 1, "status": "draft"}


class HandlerTests(unittest.TestCase):
    def setUp(self):
        self.resolved = policies()
        self.context = auth_context(self.resolved)
        self.store = FakeStore()

    def protected_read(self, payload, **event_overrides):
        event = api_event("/features/data-spaces/read", payload, **event_overrides)
        with (
            patch.object(protected_read, "resolve_policies", return_value=self.resolved) as resolver,
            patch.object(protected_read, "authorize_request", return_value=self.context) as authorize,
            patch.object(protected_read, "_store", return_value=self.store),
        ):
            return protected_read.lambda_handler(event, None), resolver, authorize

    def protected_action(self, payload, *, headers=None):
        event = api_event(
            "/features/data-spaces/action",
            payload,
            headers={"Idempotency-Key": "operation-key", **(headers or {})},
        )
        with (
            patch.object(protected_action, "resolve_policies", return_value=self.resolved) as resolver,
            patch.object(protected_action, "authorize_request", return_value=self.context) as authorize,
            patch.object(protected_action, "_store", return_value=self.store),
            patch.object(protected_action.time, "time", return_value=1_800_000_000),
        ):
            return protected_action.lambda_handler(event, None), resolver, authorize

    def public_read(self, payload):
        event = api_event("/features/data-spaces/public-read", payload)
        with (
            patch.object(public_read, "resolve_data_spaces_policy", return_value=self.resolved) as resolver,
            patch.object(public_read, "_store", return_value=self.store),
        ):
            return public_read.lambda_handler(event, None), resolver

    def internal_read(
        self,
        payload,
        *,
        principal_arn=INTERNAL_CALLER_SESSION_ARN,
        configured_role_arn=INTERNAL_CALLER_ROLE_ARN,
    ):
        event = api_event("/internal/v1/data-spaces/record-snapshot", payload)
        if principal_arn is not None:
            event["requestContext"]["identity"] = {"userArn": principal_arn}
        with (
            patch.dict(
                os.environ,
                {"INTERNAL_SNAPSHOT_CALLER_ROLE_ARN": configured_role_arn},
            ),
            patch.object(internal_snapshot_read, "resolve_data_spaces_policy", return_value=self.resolved) as resolver,
            patch.object(internal_snapshot_read, "_store", return_value=self.store),
        ):
            return internal_snapshot_read.lambda_handler(event, None), resolver

    def test_transport_rejects_duplicate_json_oversize_invalid_base64_and_wrong_route(self):
        duplicate = '{"operation":"collectionList","operation":"recordList","spaceId":"catalog-content","input":{}}'
        oversized_base64 = base64.b64encode(b" " * (256 * 1024 + 1)).decode("ascii")
        cases = (
            api_event("/features/data-spaces/read", raw_body=duplicate),
            api_event("/features/data-spaces/read", raw_body=" " * (256 * 1024 + 1)),
            api_event("/features/data-spaces/read", raw_body=oversized_base64, base64_encoded=True),
            api_event("/features/data-spaces/read", raw_body="%%%", base64_encoded=True),
            api_event("/features/data-spaces/other", {"operation": "collectionList", "spaceId": SPACE_ID, "input": {}}),
            api_event("/features/data-spaces/read", {"operation": "collectionList", "spaceId": SPACE_ID, "input": {}}, method="GET"),
        )
        for event in cases:
            with self.subTest(event=event):
                with (
                    patch.object(protected_read, "resolve_policies", return_value=self.resolved) as resolver,
                    patch.object(protected_read, "_store", return_value=self.store),
                ):
                    response = protected_read.lambda_handler(event, None)
                self.assertIn(response["statusCode"], {400, 404})
                self.assertEqual(response_body(response)["requestId"], "request-test-1")
                resolver.assert_not_called()
        self.assertEqual(self.store.calls, [])

    def test_oversized_base64_body_is_rejected_before_decode(self):
        event = api_event(
            "/features/data-spaces/read",
            raw_body="A" * (http.MAX_ENCODED_BODY_CHARS + 1),
            base64_encoded=True,
        )
        with patch.object(http.base64, "b64decode") as decode:
            response = protected_read.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 400)
        decode.assert_not_called()

    def test_base64_json_body_is_decoded_strictly(self):
        raw = json.dumps({"operation": "collectionList", "spaceId": SPACE_ID, "input": {}}).encode("utf-8")
        encoded = base64.b64encode(raw).decode("ascii")
        response, _, _ = self.protected_read(None, raw_body=encoded, base64_encoded=True)

        self.assertEqual(response["statusCode"], 200)

    def test_protected_read_derives_scope_and_uses_read_capability(self):
        response, resolver, authorize = self.protected_read({
            "operation": "recordDetail",
            "spaceId": SPACE_ID,
            "input": {"collectionId": "articles", "recordId": "welcome"},
        })

        self.assertEqual(response["statusCode"], 200)
        resolver.assert_called_once_with(DOMAIN)
        self.assertEqual(authorize.call_args.kwargs["capability"], "data-space:record:read")
        self.assertFalse(authorize.call_args.kwargs["mutation"])
        scope = self.store.calls[0][1][0]
        self.assertEqual((scope.environment, scope.tenant_id, scope.draft_id, scope.space_id), ("test", TENANT_ID, DRAFT_ID, SPACE_ID))
        self.assertNotIn("tenant", response["body"].lower())

    def test_request_cannot_supply_tenant_draft_or_storage_coordinates(self):
        response, resolver, _ = self.protected_read({
            "operation": "collectionList",
            "spaceId": SPACE_ID,
            "tenantId": "other",
            "draftId": "other",
            "pk": "other",
            "input": {},
        })

        self.assertEqual(response["statusCode"], 400)
        resolver.assert_not_called()
        self.assertEqual(self.store.calls, [])

    def test_non_string_operation_is_validation_error_not_internal_error(self):
        response, resolver, _ = self.protected_read({
            "operation": {"unexpected": True},
            "spaceId": SPACE_ID,
            "input": {},
        })

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(response_body(response)["code"], "validation_error")
        resolver.assert_not_called()

    def test_admin_cursor_is_opaque_scope_bound_and_round_trips_to_fixed_storage_prefix(self):
        first, _, _ = self.protected_read({
            "operation": "recordList",
            "spaceId": SPACE_ID,
            "input": {"collectionId": "articles", "limit": 99},
        })
        token = response_body(first)["data"]["cursor"]
        decoded = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode("utf-8")
        self.assertNotIn(TENANT_ID, decoded)
        self.assertNotIn(DRAFT_ID, decoded)
        self.assertNotIn("ENV#", decoded)
        self.assertEqual(self.store.calls[0][1][2], 2)

        self.store.calls.clear()
        second, _, _ = self.protected_read({
            "operation": "recordList",
            "spaceId": SPACE_ID,
            "input": {"collectionId": "articles", "limit": 2, "cursor": token},
        })

        self.assertEqual(second["statusCode"], 200)
        self.assertEqual(self.store.calls[0][1][3], "RECORD#articles#first")
        other = policies()
        other.data_spaces["spaces"][0]["id"] = "other-space"
        self.resolved = other
        self.context = auth_context(other)
        self.store.calls.clear()
        rejected, _, _ = self.protected_read({
            "operation": "recordList",
            "spaceId": "other-space",
            "input": {"collectionId": "articles", "cursor": token},
        })
        self.assertEqual(rejected["statusCode"], 400)
        self.assertEqual(self.store.calls, [])

    def test_action_registry_maps_capabilities_csrf_idempotency_revision_limits_and_actor_hash(self):
        schema = {"fields": [{"id": "title", "type": "string", "classification": "public"}]}
        cases = (
            ("createCollection", {"collectionId": "articles", "schema": schema}, "data-space:schema:write", "create_collection", False),
            ("updateCollection", {"collectionId": "articles", "schema": schema, "expectedRevision": 1}, "data-space:schema:write", "update_collection", True),
            ("createRecord", {"collectionId": "articles", "recordId": "welcome", "data": {"title": "Welcome"}}, "data-space:record:write", "create_record", False),
            ("updateRecord", {"collectionId": "articles", "recordId": "welcome", "data": {"title": "Updated"}, "expectedRevision": 1}, "data-space:record:write", "update_record", True),
            ("publishRecord", {"collectionId": "articles", "recordId": "welcome", "expectedRevision": 1}, "data-space:publish", "publish_record", True),
            ("unpublishRecord", {"collectionId": "articles", "recordId": "welcome", "expectedRevision": 2}, "data-space:publish", "unpublish_record", True),
        )
        for operation, input_value, capability, method, has_revision in cases:
            with self.subTest(operation=operation):
                self.store.calls.clear()
                response, _, authorize = self.protected_action({
                    "operation": operation,
                    "spaceId": SPACE_ID,
                    "input": input_value,
                })
                self.assertEqual(response["statusCode"], 200)
                self.assertEqual(authorize.call_args.kwargs["capability"], capability)
                self.assertTrue(authorize.call_args.kwargs["mutation"])
                name, _, kwargs = self.store.calls[0]
                self.assertEqual(name, method)
                self.assertEqual(kwargs["idempotency_key"], "operation-key")
                self.assertEqual(kwargs["actor_hash"], hashlib.sha256(b"operator-subject").hexdigest())
                self.assertEqual(kwargs["now_epoch"], 1_800_000_000)
                self.assertEqual("expected_revision" in kwargs, has_revision)
                if method in {"create_collection", "update_collection"}:
                    self.assertEqual(kwargs["allowed_classifications"], ("public", "internal"))

    def test_action_requires_idempotency_and_expected_revision_before_storage(self):
        missing_idempotency = api_event(
            "/features/data-spaces/action",
            {"operation": "createRecord", "spaceId": SPACE_ID, "input": {"collectionId": "articles", "recordId": "one", "data": {}}},
        )
        missing_revision = api_event(
            "/features/data-spaces/action",
            {"operation": "updateRecord", "spaceId": SPACE_ID, "input": {"collectionId": "articles", "recordId": "one", "data": {}}},
            headers={"Idempotency-Key": "operation-key"},
        )
        for event in (missing_idempotency, missing_revision):
            with self.subTest(event=event), patch.object(protected_action, "resolve_policies", return_value=self.resolved) as resolver, patch.object(protected_action, "_store", return_value=self.store):
                response = protected_action.lambda_handler(event, None)
                self.assertEqual(response["statusCode"], 400)
                resolver.assert_not_called()
        self.assertEqual(self.store.calls, [])

    def test_public_read_uses_data_only_policy_public_items_and_descriptor_page_limit(self):
        response, resolver = self.public_read({
            "operation": "recordList",
            "spaceId": SPACE_ID,
            "input": {"collectionId": "articles", "limit": 50},
        })

        self.assertEqual(response["statusCode"], 200)
        resolver.assert_called_once_with(DOMAIN)
        self.assertEqual(self.store.calls[0][0], "list_public_records")
        self.assertEqual(self.store.calls[0][1][2], 2)
        self.assertNotIn("internal", response["body"].lower())

        self.store.calls.clear()
        detail, _ = self.public_read({
            "operation": "recordDetail",
            "spaceId": SPACE_ID,
            "input": {"collectionId": "articles", "recordId": "welcome"},
        })
        self.assertEqual(detail["statusCode"], 200)
        self.assertEqual(self.store.calls[0][0], "get_public_record")

    def test_public_read_rejects_admin_operations_disabled_policy_and_cross_scope_cursor(self):
        admin, _ = self.public_read({"operation": "collectionList", "spaceId": SPACE_ID, "input": {}})
        self.assertEqual(admin["statusCode"], 400)
        self.assertEqual(self.store.calls, [])

        self.resolved = policies(public_enabled=False)
        disabled, _ = self.public_read({
            "operation": "recordList",
            "spaceId": SPACE_ID,
            "input": {"collectionId": "articles"},
        })
        self.assertEqual(disabled["statusCode"], 404)
        self.assertEqual(self.store.calls, [])

    def test_any_malformed_or_duplicate_space_fails_the_descriptor_closed(self):
        malformed = policies()
        malformed.data_spaces["spaces"].append({
            **malformed.data_spaces["spaces"][0],
            "access": {
                "mode": "auth-profile",
                "authProfileId": "staff",
                "capabilities": ["data-space:record:read", {"invalid": True}],
            },
        })
        self.resolved = malformed

        response, _ = self.public_read({
            "operation": "recordList",
            "spaceId": SPACE_ID,
            "input": {"collectionId": "articles"},
        })

        self.assertEqual(response["statusCode"], 503)
        self.assertEqual(response_body(response)["code"], "upstream_unavailable")
        self.assertEqual(self.store.calls, [])

    def test_non_string_status_or_access_mode_is_controlled_policy_failure(self):
        for field in ("status", "mode"):
            with self.subTest(field=field):
                self.resolved = policies()
                space = self.resolved.data_spaces["spaces"][0]
                if field == "status":
                    space["status"] = {"invalid": True}
                else:
                    space["access"]["mode"] = {"invalid": True}
                response, _ = self.public_read({
                    "operation": "recordList",
                    "spaceId": SPACE_ID,
                    "input": {"collectionId": "articles"},
                })
                self.assertEqual(response["statusCode"], 503)
                self.assertEqual(response_body(response)["code"], "upstream_unavailable")

    def test_internal_snapshot_resolves_policy_reads_exact_revision_and_projects_allowlist(self):
        response, resolver = self.internal_read({
            "spaceId": SPACE_ID,
            "collectionId": "articles",
            "recordId": "welcome",
            "revision": 4,
            "fieldIds": ["title"],
        })

        self.assertEqual(response["statusCode"], 200)
        resolver.assert_called_once_with(DOMAIN)
        self.assertEqual(self.store.calls[0][0], "get_record_revision")
        self.assertEqual(self.store.calls[0][1][3], 4)
        data = response_body(response)["data"]
        self.assertEqual(data, {
            "spaceId": SPACE_ID,
            "collectionId": "articles",
            "recordId": "welcome",
            "revision": 4,
            "schemaRevision": 3,
            "contentHash": hashlib.sha256(json.dumps({
                "collectionId": "articles",
                "recordId": "welcome",
                "revision": 4,
                "schemaRevision": 3,
                "spaceId": SPACE_ID,
                "values": {"title": "Snapshot"},
            }, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest(),
            "values": {"title": "Snapshot"},
        })
        self.assertNotIn("internalNote", response["body"])
        self.assertNotIn("createdAt", response["body"])

    def test_internal_snapshot_rejects_missing_or_wrong_iam_caller_before_policy_resolution(self):
        payload = {
            "spaceId": SPACE_ID,
            "collectionId": "articles",
            "recordId": "welcome",
            "revision": 4,
            "fieldIds": ["title"],
        }
        for principal_arn in (
            None,
            "arn:aws:sts::123456789012:assumed-role/unapproved-service/request-1",
            "arn:aws:iam::999999999999:role/zoolanding-commerce-test",
        ):
            with self.subTest(principal_arn=principal_arn):
                self.store.calls.clear()
                response, resolver = self.internal_read(payload, principal_arn=principal_arn)
                self.assertEqual(response["statusCode"], 403)
                self.assertEqual(response_body(response)["code"], "forbidden")
                resolver.assert_not_called()
                self.assertEqual(self.store.calls, [])

    def test_internal_snapshot_is_forbidden_while_caller_role_is_disabled(self):
        payload = {
            "spaceId": SPACE_ID,
            "collectionId": "articles",
            "recordId": "welcome",
            "revision": 4,
            "fieldIds": ["title"],
        }

        response, resolver = self.internal_read(payload, configured_role_arn="")

        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(response_body(response)["code"], "forbidden")
        resolver.assert_not_called()
        self.assertEqual(self.store.calls, [])

    def test_internal_snapshot_accepts_exact_configured_role_arn(self):
        response, resolver = self.internal_read({
            "spaceId": SPACE_ID,
            "collectionId": "articles",
            "recordId": "welcome",
            "revision": 4,
            "fieldIds": ["title"],
        }, principal_arn=INTERNAL_CALLER_ROLE_ARN)

        self.assertEqual(response["statusCode"], 200)
        resolver.assert_called_once_with(DOMAIN)

    def test_internal_snapshot_requires_revision_and_closed_field_allowlist(self):
        cases = (
            {"spaceId": SPACE_ID, "collectionId": "articles", "recordId": "welcome", "fieldIds": ["title"]},
            {"spaceId": SPACE_ID, "collectionId": "articles", "recordId": "welcome", "revision": 1, "fieldIds": []},
            {"spaceId": SPACE_ID, "collectionId": "articles", "recordId": "welcome", "revision": 1, "fieldIds": ["missing"]},
        )
        for payload in cases:
            with self.subTest(payload=payload):
                self.store.calls.clear()
                response, _ = self.internal_read(payload)
                self.assertEqual(response["statusCode"], 400)

    def test_internal_snapshot_field_allowlist_respects_descriptor_field_limit(self):
        self.resolved.data_spaces["spaces"][0]["limits"]["maxFieldsPerCollection"] = 1

        response, _ = self.internal_read({
            "spaceId": SPACE_ID,
            "collectionId": "articles",
            "recordId": "welcome",
            "revision": 4,
            "fieldIds": ["title", "internalNote"],
        })

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(self.store.calls, [])

    def test_errors_use_safe_contract_request_id_and_never_return_exception_details(self):
        cases = (
            (AuthenticationError(), 401, "auth_required"),
            (AuthorizationError(), 403, "forbidden"),
            (PolicyResolutionError("sensitive-provider-detail"), 503, "upstream_unavailable"),
            (StorageNotFound("sensitive-provider-detail"), 404, "not_found"),
            (StorageConflict("sensitive-provider-detail"), 409, "conflict"),
            (RuntimeError("sensitive-provider-detail"), 500, "internal_error"),
        )
        for failure, status, code in cases:
            with self.subTest(code=code):
                self.store.failure = failure
                if isinstance(failure, (AuthenticationError, AuthorizationError, PolicyResolutionError)):
                    with patch.object(protected_read, "resolve_policies", side_effect=failure), patch.object(protected_read, "_store", return_value=self.store):
                        response = protected_read.lambda_handler(api_event(
                            "/features/data-spaces/read",
                            {"operation": "recordDetail", "spaceId": SPACE_ID, "input": {"collectionId": "articles", "recordId": "welcome"}},
                        ), None)
                else:
                    response, _, _ = self.protected_read({
                        "operation": "recordDetail",
                        "spaceId": SPACE_ID,
                        "input": {"collectionId": "articles", "recordId": "welcome"},
                    })
                body = response_body(response)
                self.assertEqual(response["statusCode"], status)
                self.assertFalse(body["ok"])
                self.assertEqual(body["code"], code)
                self.assertEqual(body["error"], body["message"])
                self.assertEqual(body["requestId"], "request-test-1")
                self.assertNotIn("sensitive", response["body"])
                self.store.failure = None

    def test_handlers_import_from_sam_code_uri_root(self):
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import handlers.protected_read, handlers.protected_action, handlers.public_read, handlers.internal_snapshot_read",
            ],
            cwd=ROOT.parent,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
