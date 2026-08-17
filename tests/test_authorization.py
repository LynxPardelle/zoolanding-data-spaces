import hashlib
import subprocess
import sys
import unittest
from pathlib import Path

from src.common.auth_admin import (
    AuthenticationError,
    AuthorizationError,
    DynamoAuthStore,
    authorize_request,
)
from src.common.published_policy import ResolvedPolicies


DOMAIN = "example.com"
TENANT_ID = "tenant-example"
DRAFT_ID = "draft-example"
SESSION_VALUE = "synthetic-session"
CSRF_VALUE = "synthetic-csrf"
ROOT = Path(__file__).resolve().parents[1]


def sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def policies(environment="test", *, capability="data-space:record:read"):
    return ResolvedPolicies(
        environment=environment,
        tenant_id=TENANT_ID,
        draft_id=DRAFT_ID,
        domain=DOMAIN,
        version_id="v1",
        prefix=f"sites/{DOMAIN}/versions/v1/",
        data_spaces={
            "version": 1,
            "scope": {
                "environment": environment,
                "tenantId": TENANT_ID,
                "draftId": DRAFT_ID,
                "domain": DOMAIN,
            },
            "spaces": [
                {
                    "id": "catalog-content",
                    "status": "active",
                    "access": {
                        "mode": "auth-profile",
                        "authProfileId": "staff",
                        "capabilities": [capability],
                    },
                    "publicRead": {"enabled": True, "maxPageSize": 50},
                }
            ],
        },
        auth_registry={
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
        },
    )


def event(*, profile_id="staff", session=SESSION_VALUE, csrf=CSRF_VALUE):
    headers = {
        "X-ZLP-Domain": DOMAIN,
        "X-ZLP-Auth-Profile-Id": profile_id,
    }
    cookies = [f"__Host-zlp_session={session}"] if session else []
    if csrf:
        headers["X-ZLP-CSRF"] = csrf
        cookies.append(f"zlp_csrf={csrf}")
    return {"headers": headers, "cookies": cookies}


class FakeAuthStore:
    def __init__(self, environment="test"):
        tenant_key = f"{DOMAIN}#staff#{'prod' if environment == 'production' else environment}"
        self.session = {
            "sessionIdHash": sha256(SESSION_VALUE),
            "tenantProfileKey": tenant_key,
            "domain": DOMAIN,
            "authProfileId": "staff",
            "environment": "prod" if environment == "production" else environment,
            "tenantId": TENANT_ID,
            "subject": "admin-sub",
            "roles": ["stale-role"],
            "sessionVersion": 3,
            "csrfHash": sha256(CSRF_VALUE),
            "expiresAt": 4_102_444_800,
        }
        self.user = {
            "roles": ["site-admin"],
            "approvalStatus": "approved",
            "enabled": True,
            "sessionVersion": 3,
        }
        self.session_keys = []
        self.user_keys = []

    def get_session(self, session_hash):
        self.session_keys.append(session_hash)
        return dict(self.session) if self.session and session_hash == self.session.get("sessionIdHash") else None

    def get_user(self, tenant_profile_key, user_key):
        self.user_keys.append((tenant_profile_key, user_key))
        return dict(self.user) if self.user else None


class FailingTable:
    def get_item(self, **_request):
        raise RuntimeError("synthetic provider detail")


class FakeDynamo:
    def Table(self, _name):
        return FailingTable()


class RecordingTable:
    def __init__(self, item):
        self.item = item
        self.calls = []

    def get_item(self, **request):
        self.calls.append(request)
        return {"Item": dict(self.item)}


class RecordingDynamo:
    def __init__(self):
        self.tables = {
            "sessions": RecordingTable({"sessionIdHash": "synthetic-hash"}),
            "users": RecordingTable({"enabled": True}),
        }

    def Table(self, name):
        return self.tables[name]


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.policies = policies()
        self.store = FakeAuthStore()

    def authorize(self, **overrides):
        request = {
            "event": event(),
            "policies": self.policies,
            "space_id": "catalog-content",
            "capability": "data-space:record:read",
            "mutation": False,
            "store": self.store,
            "now_epoch": 1_800_000_000,
            **overrides,
        }
        return authorize_request(**request)

    def test_authorizes_from_hashed_cookie_and_fresh_user_state(self):
        context = self.authorize()

        self.assertEqual(context.subject, "admin-sub")
        self.assertEqual(context.roles, ("site-admin",))
        self.assertEqual(context.space["id"], "catalog-content")
        self.assertEqual(self.store.session_keys, [sha256(SESSION_VALUE)])
        self.assertNotIn(SESSION_VALUE, self.store.session_keys)
        self.assertEqual(self.store.user_keys, [(f"{DOMAIN}#staff#test", "USER#admin-sub")])

    def test_production_maps_only_auth_tenant_profile_key_to_prod(self):
        self.policies = policies("production")
        self.store = FakeAuthStore("production")

        context = self.authorize()

        self.assertEqual(context.environment, "production")
        self.assertEqual(self.store.user_keys, [(f"{DOMAIN}#staff#prod", "USER#admin-sub")])

    def test_auth_store_failure_does_not_chain_provider_details(self):
        store = DynamoAuthStore("sessions", "users", FakeDynamo())

        with self.assertRaises(AuthenticationError) as caught:
            store.get_session("synthetic-hash")

        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn("provider", str(caught.exception))

    def test_auth_store_reads_current_session_and_user_state_consistently(self):
        dynamo = RecordingDynamo()
        store = DynamoAuthStore("sessions", "users", dynamo)

        store.get_session("synthetic-hash")
        store.get_user("tenant#profile#test", "USER#admin-sub")

        self.assertEqual(
            dynamo.tables["sessions"].calls,
            [{"Key": {"sessionIdHash": "synthetic-hash"}, "ConsistentRead": True}],
        )
        self.assertEqual(
            dynamo.tables["users"].calls,
            [
                {
                    "Key": {
                        "tenantProfileKey": "tenant#profile#test",
                        "userKey": "USER#admin-sub",
                    },
                    "ConsistentRead": True,
                }
            ],
        )

    def test_auth_module_imports_from_sam_code_uri_root(self):
        result = subprocess.run(
            [sys.executable, "-c", "import common.auth_admin"],
            cwd=ROOT / "src",
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_mutation_requires_cookie_header_and_server_hash_csrf_match(self):
        context = self.authorize(mutation=True)
        self.assertEqual(context.subject, "admin-sub")

        bad_events = (
            event(csrf=""),
            {**event(), "cookies": [f"__Host-zlp_session={SESSION_VALUE}", "zlp_csrf=other"]},
            {**event(), "headers": {**event()["headers"], "X-ZLP-CSRF": "other"}},
        )
        for bad_event in bad_events:
            with self.subTest(event=bad_event):
                with self.assertRaises(AuthorizationError):
                    self.authorize(event=bad_event, mutation=True)

    def test_rejects_missing_invalid_or_stale_session(self):
        mutations = (
            ("missing cookie", lambda: None, event(session="")),
            ("missing record", lambda: setattr(self.store, "session", {}), event()),
            ("revoked", lambda: self.store.session.update(revokedAt="2026-01-01T00:00:00Z"), event()),
            ("expired", lambda: self.store.session.update(expiresAt=1_700_000_000), event()),
            ("wrong tenant", lambda: self.store.session.update(tenantId="other"), event()),
            ("wrong environment", lambda: self.store.session.update(environment="prod"), event()),
            ("wrong profile key", lambda: self.store.session.update(tenantProfileKey="other"), event()),
            ("wrong domain", lambda: self.store.session.update(domain="other.example"), event()),
            ("wrong profile", lambda: self.store.session.update(authProfileId="other"), event()),
            ("unsafe subject", lambda: self.store.session.update(subject="../other"), event()),
            ("non-string subject", lambda: self.store.session.update(subject=123), event()),
        )
        for name, mutate, request_event in mutations:
            with self.subTest(name=name):
                self.setUp()
                mutate()
                with self.assertRaises(AuthenticationError):
                    self.authorize(event=request_event)

    def test_rejects_inactive_or_changed_fresh_user_state(self):
        mutations = (
            ("missing", lambda: setattr(self.store, "user", None)),
            ("version", lambda: self.store.user.update(sessionVersion=4)),
            ("disabled", lambda: self.store.user.update(enabled=False)),
            ("pending", lambda: self.store.user.update(approvalStatus="pending")),
            ("no current admin role", lambda: self.store.user.update(roles=["content-editor"])),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                self.setUp()
                mutate()
                with self.assertRaises((AuthenticationError, AuthorizationError)):
                    self.authorize()

    def test_rejects_header_profile_space_and_capability_mismatches(self):
        cases = (
            ("domain header", lambda: self.authorize(event={**event(), "headers": {**event()["headers"], "X-ZLP-Domain": "other.example"}})),
            ("profile header", lambda: self.authorize(event=event(profile_id="other"))),
            ("unknown space", lambda: self.authorize(space_id="other")),
            ("capability", lambda: self.authorize(capability="data-space:publish")),
            ("disabled space", lambda: (self.policies.data_spaces["spaces"][0].update(status="disabled"), self.authorize())[1]),
            ("public-only access", lambda: (self.policies.data_spaces["spaces"][0].update(access={"mode": "none"}), self.authorize())[1]),
        )
        for name, invoke in cases:
            with self.subTest(name=name):
                self.setUp()
                with self.assertRaises((AuthenticationError, AuthorizationError)):
                    invoke()

    def test_rejects_inactive_cross_scope_or_unadministered_auth_profile(self):
        profile = self.policies.auth_registry["profiles"][0]
        cases = (
            ("inactive", lambda: profile.update(status="suspended")),
            ("tenant", lambda: profile.update(tenantId="other")),
            ("domain", lambda: profile.update(domain="other.example")),
            ("no admin groups", lambda: profile.pop("adminGroups")),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                self.setUp()
                profile = self.policies.auth_registry["profiles"][0]
                mutate()
                with self.assertRaises(AuthorizationError):
                    self.authorize()

    def test_rejects_partially_malformed_capability_group_or_role_lists(self):
        cases = (
            (
                "capabilities",
                lambda: self.policies.data_spaces["spaces"][0]["access"].update(
                    capabilities=["data-space:record:read", {"invalid": True}]
                ),
            ),
            (
                "admin groups",
                lambda: self.policies.auth_registry["profiles"][0].update(
                    adminGroups=["site-admin", None]
                ),
            ),
            ("fresh roles", lambda: self.store.user.update(roles=["site-admin", {"invalid": True}])),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                self.setUp()
                mutate()
                with self.assertRaises(AuthorizationError):
                    self.authorize()


if __name__ == "__main__":
    unittest.main()
