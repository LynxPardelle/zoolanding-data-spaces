"""Resolve immutable server-only policy from the current published pointer."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any


MAX_DESCRIPTOR_BYTES = 256 * 1024
MAX_JSON_DEPTH = 32
ENVIRONMENTS = {"test", "production"}
DATA_SPACE_CAPABILITIES = {
    "data-space:record:read",
    "data-space:record:write",
    "data-space:schema:write",
    "data-space:publish",
}
DATA_SPACE_CLASSIFICATIONS = {"public", "internal"}
DATA_SPACE_LIMITS = {
    "maxCollections": (1, 100),
    "maxFieldsPerCollection": (1, 200),
    "maxRecordsPerCollection": (1, 1_000_000),
    "maxRecordBytes": (1_024, 400_000),
}
DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
VERSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class PolicyResolutionError(Exception):
    """A safe, fail-closed policy resolution failure."""


@dataclass(frozen=True)
class ResolvedPolicies:
    environment: str
    tenant_id: str
    draft_id: str
    domain: str
    version_id: str
    prefix: str
    data_spaces: dict[str, Any]
    auth_registry: dict[str, Any]

    @property
    def scope(self) -> dict[str, str]:
        return {
            "environment": self.environment,
            "tenantId": self.tenant_id,
            "draftId": self.draft_id,
            "domain": self.domain,
        }


class _DuplicateKey(ValueError):
    pass


class PublishedPolicyResolver:
    """Read a fresh pointer and cache only descriptors addressed by version."""

    def __init__(self, registry_table: Any, s3_client: Any, bucket_name: str):
        if not bucket_name:
            raise PolicyResolutionError("Policy storage is unavailable")
        self._registry_table = registry_table
        self._s3 = s3_client
        self._bucket_name = bucket_name
        self._cache: dict[tuple[str, str, str, str, str, bool], ResolvedPolicies] = {}

    def resolve(
        self,
        *,
        environment: str,
        domain: str,
        tenant_id: str | None = None,
        draft_id: str | None = None,
    ) -> ResolvedPolicies:
        return self._resolve(
            environment=environment,
            domain=domain,
            tenant_id=tenant_id,
            draft_id=draft_id,
            include_auth=True,
        )

    def resolve_data_spaces(
        self,
        *,
        environment: str,
        domain: str,
        tenant_id: str | None = None,
        draft_id: str | None = None,
    ) -> ResolvedPolicies:
        return self._resolve(
            environment=environment,
            domain=domain,
            tenant_id=tenant_id,
            draft_id=draft_id,
            include_auth=False,
        )

    def _resolve(
        self,
        *,
        environment: str,
        domain: str,
        tenant_id: str | None,
        draft_id: str | None,
        include_auth: bool,
    ) -> ResolvedPolicies:
        environment = _environment(environment)
        domain = _domain(domain)
        metadata = self._metadata(domain)
        metadata_scope = metadata.get("serverScope")
        if (
            not isinstance(metadata_scope, dict)
            or set(metadata_scope) != {"tenantId", "draftId"}
            or metadata.get("domain") != domain
        ):
            raise PolicyResolutionError("Published policy scope is invalid")

        resolved_tenant = _safe_id(metadata_scope.get("tenantId"))
        resolved_draft = _safe_id(metadata_scope.get("draftId"))
        if tenant_id is not None and _safe_id(tenant_id) != resolved_tenant:
            raise PolicyResolutionError("Published policy scope does not match")
        if draft_id is not None and _safe_id(draft_id) != resolved_draft:
            raise PolicyResolutionError("Published policy scope does not match")
        pointer = _published_pointer(metadata, environment)
        version_id = _version_id(pointer.get("versionId") if pointer else None)
        expected_prefix = f"sites/{domain}/versions/{version_id}/"
        if not pointer or pointer.get("prefix") != expected_prefix:
            raise PolicyResolutionError("Published policy pointer is invalid")

        cache_key = (environment, resolved_tenant, resolved_draft, domain, version_id, include_auth)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        base_key = f"{expected_prefix}{domain}/server"
        data_spaces = self._load_json(f"{base_key}/data-spaces.json")
        _validate_data_spaces(data_spaces, environment, resolved_tenant, resolved_draft, domain)
        auth_registry = self._load_json(f"{base_key}/auth-profile-registry.json") if include_auth else {}
        if include_auth:
            _validate_auth_registry(auth_registry)
        resolved = ResolvedPolicies(
            environment=environment,
            tenant_id=resolved_tenant,
            draft_id=resolved_draft,
            domain=domain,
            version_id=version_id,
            prefix=expected_prefix,
            data_spaces=data_spaces,
            auth_registry=auth_registry,
        )
        self._cache[cache_key] = resolved
        return resolved

    def _metadata(self, domain: str) -> dict[str, Any]:
        try:
            response = self._registry_table.get_item(
                Key={"pk": f"SITE#{domain}", "sk": "METADATA"},
                ConsistentRead=True,
            )
        except Exception:
            raise PolicyResolutionError("Published policy is unavailable") from None
        item = response.get("Item") if isinstance(response, dict) else None
        if not isinstance(item, dict):
            raise PolicyResolutionError("Published policy is unavailable")
        return item

    def _load_json(self, key: str) -> dict[str, Any]:
        try:
            response = self._s3.get_object(Bucket=self._bucket_name, Key=key)
            length = response.get("ContentLength")
            if not isinstance(length, int) or length < 0 or length > MAX_DESCRIPTOR_BYTES:
                raise PolicyResolutionError("Published policy descriptor is invalid")
            body = response.get("Body")
            raw = body.read(MAX_DESCRIPTOR_BYTES + 1)
        except PolicyResolutionError:
            raise
        except Exception:
            raise PolicyResolutionError("Published policy descriptor is unavailable") from None
        if not isinstance(raw, bytes) or len(raw) != length or len(raw) > MAX_DESCRIPTOR_BYTES:
            raise PolicyResolutionError("Published policy descriptor is invalid")
        try:
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
        except (UnicodeDecodeError, ValueError, TypeError):
            raise PolicyResolutionError("Published policy descriptor is invalid") from None
        if not isinstance(value, dict) or _json_depth(value) > MAX_JSON_DEPTH:
            raise PolicyResolutionError("Published policy descriptor is invalid")
        return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise _DuplicateKey()
        output[key] = value
    return output


def _json_depth(value: Any) -> int:
    deepest = 0
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        deepest = max(deepest, depth)
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    return deepest


def _published_pointer(metadata: dict[str, Any], environment: str) -> dict[str, Any] | None:
    published = metadata.get("publishedEnvironments")
    environments = published if isinstance(published, dict) else {}
    if environment == "test":
        pointer = environments.get("test")
    else:
        pointer = metadata.get("published") or environments.get("production")
    return pointer if isinstance(pointer, dict) else None


def _validate_data_spaces(
    policy: dict[str, Any],
    environment: str,
    tenant_id: str,
    draft_id: str,
    domain: str,
) -> None:
    scope = policy.get("scope")
    expected = {
        "environment": environment,
        "tenantId": tenant_id,
        "draftId": draft_id,
        "domain": domain,
    }
    spaces = policy.get("spaces")
    if (
        set(policy) != {"version", "scope", "spaces"}
        or policy.get("version") != 1
        or scope != expected
        or not isinstance(spaces, list)
        or not 1 <= len(spaces) <= 32
    ):
        raise PolicyResolutionError("Published data spaces policy is invalid")
    ids: set[str] = set()
    for space in spaces:
        if not isinstance(space, dict) or set(space) != {
            "id",
            "status",
            "access",
            "publicRead",
            "allowedClassifications",
            "limits",
        }:
            raise PolicyResolutionError("Published data spaces policy is invalid")
        space_id = _safe_id(space.get("id"))
        if space_id in ids or space.get("status") not in {"active", "disabled"}:
            raise PolicyResolutionError("Published data spaces policy is invalid")
        ids.add(space_id)
        _validate_data_space_access(space.get("access"))
        _validate_data_space_public_read(space.get("publicRead"))
        _validate_data_space_classifications(space.get("allowedClassifications"))
        _validate_data_space_limits(space.get("limits"))


def _validate_data_space_access(value: Any) -> None:
    if not isinstance(value, dict):
        raise PolicyResolutionError("Published data spaces policy is invalid")
    if value.get("mode") == "none":
        if set(value) != {"mode"}:
            raise PolicyResolutionError("Published data spaces policy is invalid")
        return
    if value.get("mode") != "auth-profile" or set(value) != {"mode", "authProfileId", "capabilities"}:
        raise PolicyResolutionError("Published data spaces policy is invalid")
    _safe_id(value.get("authProfileId"))
    capabilities = value.get("capabilities")
    if (
        not isinstance(capabilities, list)
        or not 1 <= len(capabilities) <= 24
        or any(not isinstance(item, str) or item not in DATA_SPACE_CAPABILITIES for item in capabilities)
        or len(set(capabilities)) != len(capabilities)
    ):
        raise PolicyResolutionError("Published data spaces policy is invalid")


def _validate_data_space_public_read(value: Any) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"enabled", "maxPageSize"}
        or not isinstance(value.get("enabled"), bool)
        or not _bounded_integer(value.get("maxPageSize"), 1, 100)
    ):
        raise PolicyResolutionError("Published data spaces policy is invalid")


def _validate_data_space_classifications(value: Any) -> None:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 2
        or any(not isinstance(item, str) or item not in DATA_SPACE_CLASSIFICATIONS for item in value)
        or len(set(value)) != len(value)
    ):
        raise PolicyResolutionError("Published data spaces policy is invalid")


def _validate_data_space_limits(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != set(DATA_SPACE_LIMITS):
        raise PolicyResolutionError("Published data spaces policy is invalid")
    if any(not _bounded_integer(value.get(key), lower, upper) for key, (lower, upper) in DATA_SPACE_LIMITS.items()):
        raise PolicyResolutionError("Published data spaces policy is invalid")


def _bounded_integer(value: Any, lower: int, upper: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and lower <= value <= upper


def _validate_auth_registry(registry: dict[str, Any]) -> None:
    profiles = registry.get("profiles")
    if registry.get("version") != 1 or not isinstance(profiles, list):
        raise PolicyResolutionError("Published auth policy is invalid")


def _environment(value: Any) -> str:
    if not isinstance(value, str):
        raise PolicyResolutionError("Policy environment is invalid")
    environment = value.strip().lower()
    if environment == "prod":
        environment = "production"
    if environment not in ENVIRONMENTS:
        raise PolicyResolutionError("Policy environment is invalid")
    return environment


def _domain(value: Any) -> str:
    if not isinstance(value, str):
        raise PolicyResolutionError("Policy domain is invalid")
    domain = value.strip().lower()
    if not DOMAIN_RE.fullmatch(domain):
        raise PolicyResolutionError("Policy domain is invalid")
    return domain


def _safe_id(value: Any) -> str:
    if not isinstance(value, str):
        raise PolicyResolutionError("Policy scope is invalid")
    safe_id = value.strip()
    if not SAFE_ID_RE.fullmatch(safe_id):
        raise PolicyResolutionError("Policy scope is invalid")
    return safe_id


def _version_id(value: Any) -> str:
    if not isinstance(value, str):
        raise PolicyResolutionError("Published policy pointer is invalid")
    version_id = value.strip()
    if not VERSION_ID_RE.fullmatch(version_id):
        raise PolicyResolutionError("Published policy pointer is invalid")
    return version_id


_DEFAULT_RESOLVER: PublishedPolicyResolver | None = None


def resolve_policies(
    domain: str,
    environment: str | None = None,
    *,
    tenant_id: str | None = None,
    draft_id: str | None = None,
) -> ResolvedPolicies:
    """Resolve policies using the service's configured read-only AWS clients."""

    resolver = _resolver_from_environment()
    return resolver.resolve(
        environment=environment or os.getenv("ENVIRONMENT_NAME", ""),
        domain=domain,
        tenant_id=tenant_id,
        draft_id=draft_id,
    )


def resolve_data_spaces_policy(
    domain: str,
    environment: str | None = None,
    *,
    tenant_id: str | None = None,
    draft_id: str | None = None,
) -> ResolvedPolicies:
    """Resolve only Data Spaces policy for the public-read handler."""

    resolver = _resolver_from_environment()
    return resolver.resolve_data_spaces(
        environment=environment or os.getenv("ENVIRONMENT_NAME", ""),
        domain=domain,
        tenant_id=tenant_id,
        draft_id=draft_id,
    )


def _resolver_from_environment() -> PublishedPolicyResolver:
    global _DEFAULT_RESOLVER
    if _DEFAULT_RESOLVER is None:
        table_name = os.getenv("CONFIG_REGISTRY_TABLE_NAME", "").strip()
        bucket_name = os.getenv("CONFIG_PAYLOADS_BUCKET_NAME", "").strip()
        if not table_name or not bucket_name:
            raise PolicyResolutionError("Published policy storage is unavailable")
        try:
            import boto3  # type: ignore

            table = boto3.resource("dynamodb").Table(table_name)
            s3_client = boto3.client("s3")
        except Exception:
            raise PolicyResolutionError("Published policy storage is unavailable") from None
        _DEFAULT_RESOLVER = PublishedPolicyResolver(table, s3_client, bucket_name)
    return _DEFAULT_RESOLVER
