import io
import json
import unittest

import src.common.published_policy as published_policy
from src.common.published_policy import (
    PolicyResolutionError,
    PublishedPolicyResolver,
    resolve_data_spaces_policy,
)


DOMAIN = "example.com"
TENANT_ID = "tenant-example"
DRAFT_ID = "draft-example"


def data_spaces_policy(environment="test", **scope_overrides):
    scope = {
        "environment": environment,
        "tenantId": TENANT_ID,
        "draftId": DRAFT_ID,
        "domain": DOMAIN,
        **scope_overrides,
    }
    return {
        "version": 1,
        "scope": scope,
        "spaces": [
            {
                "id": "catalog-content",
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
                "publicRead": {"enabled": True, "maxPageSize": 50},
                "allowedClassifications": ["public", "internal"],
                "limits": {
                    "maxCollections": 20,
                    "maxFieldsPerCollection": 50,
                    "maxRecordsPerCollection": 10_000,
                    "maxRecordBytes": 65_536,
                },
            }
        ],
    }


def auth_registry():
    return {
        "version": 1,
        "profiles": [
            {
                "authProfileId": "staff",
                "tenantId": TENANT_ID,
                "domain": DOMAIN,
                "status": "active",
                "adminGroups": ["site-admin"],
                "allowedGroups": ["site-admin", "content-editor"],
                "session": {
                    "csrfCookieName": "zlp_csrf",
                    "csrfHeaderName": "X-ZLP-CSRF",
                },
            }
        ],
    }


class FakeRegistryTable:
    def __init__(self, metadata):
        self.metadata = metadata
        self.calls = []

    def get_item(self, **request):
        self.calls.append(request)
        return {"Item": self.metadata} if self.metadata is not None else {}


class FakeS3:
    def __init__(self, objects):
        self.objects = dict(objects)
        self.calls = []

    def get_object(self, **request):
        self.calls.append(request)
        value = self.objects[request["Key"]]
        raw = value if isinstance(value, bytes) else json.dumps(value).encode("utf-8")
        return {"ContentLength": len(raw), "Body": io.BytesIO(raw)}


class FailingRegistryTable:
    def get_item(self, **_request):
        raise RuntimeError("synthetic provider detail")


class PublishedPolicyResolverTests(unittest.TestCase):
    def setUp(self):
        self.prefix = f"sites/{DOMAIN}/versions/v1/"
        self.metadata = {
            "pk": f"SITE#{DOMAIN}",
            "sk": "METADATA",
            "domain": DOMAIN,
            "serverScope": {"tenantId": TENANT_ID, "draftId": DRAFT_ID},
            "publishedEnvironments": {
                "test": {"versionId": "v1", "prefix": self.prefix},
            },
        }
        self.data_key = f"{self.prefix}{DOMAIN}/server/data-spaces.json"
        self.auth_key = f"{self.prefix}{DOMAIN}/server/auth-profile-registry.json"
        self.table = FakeRegistryTable(self.metadata)
        self.s3 = FakeS3({
            self.data_key: data_spaces_policy(),
            self.auth_key: auth_registry(),
        })
        self.resolver = PublishedPolicyResolver(self.table, self.s3, "config-bucket")

    def resolve(self, **overrides):
        request = {
            "environment": "test",
            "tenant_id": TENANT_ID,
            "draft_id": DRAFT_ID,
            "domain": DOMAIN,
            **overrides,
        }
        return self.resolver.resolve(**request)

    def test_resolves_exact_published_version_and_both_descriptors(self):
        resolved = self.resolve()

        self.assertEqual(resolved.version_id, "v1")
        self.assertEqual(resolved.scope, data_spaces_policy()["scope"])
        self.assertEqual(resolved.data_spaces["spaces"][0]["id"], "catalog-content")
        self.assertEqual(resolved.auth_registry["profiles"][0]["authProfileId"], "staff")
        self.assertEqual(
            self.table.calls,
            [{"Key": {"pk": f"SITE#{DOMAIN}", "sk": "METADATA"}, "ConsistentRead": True}],
        )
        self.assertEqual(
            [call["Key"] for call in self.s3.calls],
            [self.data_key, self.auth_key],
        )

    def test_reads_pointer_every_time_but_caches_only_immutable_descriptors(self):
        first = self.resolve()
        self.s3.objects[self.data_key] = data_spaces_policy(spaces=[])
        second = self.resolve()

        self.assertIs(first.data_spaces, second.data_spaces)
        self.assertEqual(len(self.table.calls), 2)
        self.assertEqual(len(self.s3.calls), 2)

    def test_public_resolution_never_reads_auth_registry_or_reuses_partial_as_protected(self):
        request = {
            "environment": "test",
            "tenant_id": TENANT_ID,
            "draft_id": DRAFT_ID,
            "domain": DOMAIN,
        }

        public = self.resolver.resolve_data_spaces(**request)
        protected = self.resolver.resolve(**request)

        self.assertEqual(public.auth_registry, {})
        self.assertEqual(protected.auth_registry["profiles"][0]["authProfileId"], "staff")
        self.assertEqual(
            [call["Key"] for call in self.s3.calls],
            [self.data_key, self.data_key, self.auth_key],
        )
        self.assertEqual(len(self.table.calls), 2)

    def test_public_helper_uses_data_spaces_only_resolution(self):
        previous = published_policy._DEFAULT_RESOLVER
        published_policy._DEFAULT_RESOLVER = self.resolver
        try:
            resolved = resolve_data_spaces_policy(
                DOMAIN,
                "test",
                tenant_id=TENANT_ID,
                draft_id=DRAFT_ID,
            )
        finally:
            published_policy._DEFAULT_RESOLVER = previous

        self.assertEqual(resolved.auth_registry, {})
        self.assertEqual([call["Key"] for call in self.s3.calls], [self.data_key])

    def test_pointer_change_reads_new_exact_version(self):
        self.resolve()
        prefix_v2 = f"sites/{DOMAIN}/versions/v2/"
        self.metadata["publishedEnvironments"]["test"] = {"versionId": "v2", "prefix": prefix_v2}
        self.s3.objects[f"{prefix_v2}{DOMAIN}/server/data-spaces.json"] = data_spaces_policy()
        self.s3.objects[f"{prefix_v2}{DOMAIN}/server/auth-profile-registry.json"] = auth_registry()

        resolved = self.resolve()

        self.assertEqual(resolved.version_id, "v2")
        self.assertEqual(len(self.table.calls), 2)
        self.assertEqual(len(self.s3.calls), 4)

    def test_production_uses_production_pointer_without_test_fallback(self):
        prefix = f"sites/{DOMAIN}/versions/prod-v1/"
        self.metadata["published"] = {"versionId": "prod-v1", "prefix": prefix}
        self.s3.objects[f"{prefix}{DOMAIN}/server/data-spaces.json"] = data_spaces_policy("production")
        self.s3.objects[f"{prefix}{DOMAIN}/server/auth-profile-registry.json"] = auth_registry()

        resolved = self.resolve(environment="production")

        self.assertEqual(resolved.environment, "production")
        self.assertEqual(resolved.version_id, "prod-v1")

    def test_server_stack_prod_alias_resolves_production_descriptor(self):
        prefix = f"sites/{DOMAIN}/versions/prod-v1/"
        self.metadata["published"] = {"versionId": "prod-v1", "prefix": prefix}
        self.s3.objects[f"{prefix}{DOMAIN}/server/data-spaces.json"] = data_spaces_policy("production")
        self.s3.objects[f"{prefix}{DOMAIN}/server/auth-profile-registry.json"] = auth_registry()

        resolved = self.resolve(environment="prod")

        self.assertEqual(resolved.environment, "production")
        self.assertEqual(resolved.scope["environment"], "production")

    def test_rejects_unsupported_environment_before_aws_reads(self):
        with self.assertRaises(PolicyResolutionError):
            self.resolve(environment="dev")

        self.assertEqual(self.table.calls, [])
        self.assertEqual(self.s3.calls, [])

    def test_provider_failure_does_not_chain_provider_details(self):
        resolver = PublishedPolicyResolver(FailingRegistryTable(), self.s3, "config-bucket")

        with self.assertRaises(PolicyResolutionError) as caught:
            resolver.resolve(environment="test", tenant_id=TENANT_ID, draft_id=DRAFT_ID, domain=DOMAIN)

        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn("provider", str(caught.exception))

    def test_rejects_missing_or_prefix_confusable_pointer(self):
        for pointer in (
            None,
            {"versionId": "v1", "prefix": self.prefix.removesuffix("/")},
            {"versionId": "v1", "prefix": f"sites/{DOMAIN}/versions/v10/"},
        ):
            with self.subTest(pointer=pointer):
                self.metadata["publishedEnvironments"]["test"] = pointer
                with self.assertRaises(PolicyResolutionError):
                    self.resolve()

    def test_rejects_non_string_registry_scope_and_version_ids(self):
        cases = ("scope", "version")
        for name in cases:
            with self.subTest(name=name):
                self.setUp()
                if name == "scope":
                    self.metadata["serverScope"]["tenantId"] = 123
                    self.s3.objects[self.data_key] = data_spaces_policy(tenantId="123")
                    invoke = lambda: self.resolver.resolve(environment="test", domain=DOMAIN)
                else:
                    prefix = f"sites/{DOMAIN}/versions/1/"
                    self.metadata["publishedEnvironments"]["test"] = {"versionId": 1, "prefix": prefix}
                    self.s3.objects[f"{prefix}{DOMAIN}/server/data-spaces.json"] = data_spaces_policy()
                    self.s3.objects[f"{prefix}{DOMAIN}/server/auth-profile-registry.json"] = auth_registry()
                    invoke = lambda: self.resolve()

                with self.assertRaises(PolicyResolutionError):
                    invoke()

    def test_rejects_metadata_and_descriptor_scope_mismatches(self):
        cases = (
            ("metadata tenant", lambda: self.metadata["serverScope"].update(tenantId="other")),
            ("metadata draft", lambda: self.metadata["serverScope"].update(draftId="other")),
            ("metadata domain", lambda: self.metadata.update(domain="other.example")),
            ("metadata scope extra", lambda: self.metadata["serverScope"].update(environment="test")),
            ("descriptor environment", lambda: self.s3.objects.__setitem__(self.data_key, data_spaces_policy("production"))),
            ("descriptor tenant", lambda: self.s3.objects.__setitem__(self.data_key, data_spaces_policy(tenantId="other"))),
            ("descriptor draft", lambda: self.s3.objects.__setitem__(self.data_key, data_spaces_policy(draftId="other"))),
            ("descriptor domain", lambda: self.s3.objects.__setitem__(self.data_key, data_spaces_policy(domain="other.example"))),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                self.setUp()
                mutate()
                with self.assertRaises(PolicyResolutionError):
                    self.resolve()

    def test_rejects_missing_disabled_or_invalid_policy(self):
        cases = (
            ("missing auth", lambda: self.s3.objects.pop(self.auth_key)),
            ("no spaces", lambda: self.s3.objects.__setitem__(self.data_key, {**data_spaces_policy(), "spaces": []})),
            ("duplicate space", lambda: self.s3.objects.__setitem__(self.data_key, {
                **data_spaces_policy(),
                "spaces": data_spaces_policy()["spaces"] * 2,
            })),
            ("invalid version", lambda: self.s3.objects.__setitem__(self.data_key, {**data_spaces_policy(), "version": 2})),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                self.setUp()
                mutate()
                with self.assertRaises(PolicyResolutionError):
                    self.resolve()

    def test_rejects_data_space_policy_outside_the_closed_published_contract(self):
        def policy_with_space(mutator):
            policy = data_spaces_policy()
            mutator(policy, policy["spaces"][0])
            return policy

        cases = (
            ("top-level extra", lambda policy, _space: policy.update(secret="not-allowed")),
            ("scope extra", lambda policy, _space: policy["scope"].update(tableName="unsafe")),
            ("space extra", lambda _policy, space: space.update(indexName="unsafe")),
            ("missing limits", lambda _policy, space: space.pop("limits")),
            ("boolean limit", lambda _policy, space: space["limits"].update(maxCollections=True)),
            ("oversized page", lambda _policy, space: space["publicRead"].update(maxPageSize=101)),
            ("non-boolean public", lambda _policy, space: space["publicRead"].update(enabled="true")),
            ("duplicate classification", lambda _policy, space: space.update(allowedClassifications=["public", "public"])),
            ("unknown classification", lambda _policy, space: space.update(allowedClassifications=["restricted"])),
            ("unknown capability", lambda _policy, space: space["access"].update(capabilities=["data-space:any"])),
            (
                "duplicate capability",
                lambda _policy, space: space["access"].update(
                    capabilities=["data-space:record:read", "data-space:record:read"]
                ),
            ),
            ("missing auth profile", lambda _policy, space: space["access"].pop("authProfileId")),
            ("none access extra", lambda _policy, space: space.update(access={"mode": "none", "authProfileId": "staff"})),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                self.setUp()
                self.s3.objects[self.data_key] = policy_with_space(mutate)
                with self.assertRaises(PolicyResolutionError):
                    self.resolve()

    def test_rejects_duplicate_json_keys_oversize_and_excess_depth(self):
        duplicate = b'{"version":1,"version":1,"scope":{},"spaces":[]}'
        nested = {"value": "leaf"}
        for _ in range(33):
            nested = {"next": nested}
        cases = (
            ("duplicate", duplicate),
            ("oversize", b" " * (256 * 1024 + 1)),
            ("depth", json.dumps(nested).encode("utf-8")),
        )
        for name, raw in cases:
            with self.subTest(name=name):
                self.setUp()
                self.s3.objects[self.data_key] = raw
                with self.assertRaises(PolicyResolutionError):
                    self.resolve()


if __name__ == "__main__":
    unittest.main()
