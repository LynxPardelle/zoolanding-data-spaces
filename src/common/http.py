"""Strict API Gateway transport, safe envelopes, policy guards, and cursors."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import uuid
from typing import Any, Callable

from .auth_admin import AuthenticationError, AuthorizationError
from .published_policy import PolicyResolutionError, ResolvedPolicies

try:  # Lambda CodeUri is src/.
    from domain.schema_policy import SchemaPolicyError
    from storage import Scope, StorageConflict, StorageLimitExceeded, StorageNotFound
except ModuleNotFoundError:  # Repository-root tests import src.*.
    from src.domain.schema_policy import SchemaPolicyError
    from src.storage import Scope, StorageConflict, StorageLimitExceeded, StorageNotFound


MAX_BODY_BYTES = 256 * 1024
MAX_ENCODED_BODY_CHARS = ((MAX_BODY_BYTES + 2) // 3) * 4
MAX_JSON_DEPTH = 32
SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
FIELD_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
CURSOR_RE = re.compile(r"^[A-Za-z0-9_-]{1,1024}$")
CAPABILITIES = {
    "data-space:record:read",
    "data-space:record:write",
    "data-space:schema:write",
    "data-space:publish",
}


class HttpError(Exception):
    def __init__(self, status_code: int, code: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.retryable = retryable


def dispatch(event: Any, exact_path: str, callback: Callable[[dict[str, Any], str], Any]) -> dict[str, Any]:
    request_id = request_id_from(event)
    try:
        if not isinstance(event, dict) or _method(event) != "POST" or _path(event) != exact_path:
            raise HttpError(404, "not_found", "Resource not found.")
        payload = strict_json_body(event)
        return success_response(callback(payload, request_id), request_id)
    except Exception as exc:
        return error_response(exc, request_id)


def strict_json_body(event: dict[str, Any]) -> dict[str, Any]:
    body = event.get("body")
    encoded = event.get("isBase64Encoded", False)
    if not isinstance(encoded, bool) or not isinstance(body, str):
        raise validation_error()
    if (encoded and len(body) > MAX_ENCODED_BODY_CHARS) or (not encoded and len(body) > MAX_BODY_BYTES):
        raise validation_error()
    try:
        if encoded:
            raw = base64.b64decode(body.encode("ascii"), validate=True)
        else:
            raw = body.encode("utf-8")
    except (UnicodeEncodeError, ValueError):
        raise validation_error() from None
    if not raw or len(raw) > MAX_BODY_BYTES:
        raise validation_error()
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        raise validation_error() from None
    if not isinstance(value, dict) or _json_depth(value) > MAX_JSON_DEPTH:
        raise validation_error()
    return value


def closed_object(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    optional = optional or set()
    if not isinstance(value, dict) or not required.issubset(value) or not set(value).issubset(required | optional):
        raise validation_error()
    return value


def header(event: dict[str, Any], name: str) -> str:
    headers = event.get("headers") if isinstance(event.get("headers"), dict) else {}
    for key, value in headers.items():
        if str(key).lower() == name.lower() and isinstance(value, str):
            return value.strip()
    return ""


def domain_header(event: dict[str, Any]) -> str:
    domain = header(event, "x-zlp-domain").lower()
    if not DOMAIN_RE.fullmatch(domain):
        raise validation_error()
    return domain


def idempotency_header(event: dict[str, Any]) -> str:
    value = header(event, "idempotency-key")
    if not 1 <= len(value) <= 256 or any(ord(character) < 32 for character in value):
        raise validation_error()
    return value


def safe_id(value: Any) -> str:
    if not isinstance(value, str) or not SAFE_ID_RE.fullmatch(value):
        raise validation_error()
    return value


def field_ids(value: Any) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 200
        or any(not isinstance(item, str) or not FIELD_ID_RE.fullmatch(item) for item in value)
        or len(set(value)) != len(value)
    ):
        raise validation_error()
    return tuple(value)


def positive_int(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise validation_error()
    return value


def bounded_page_size(value: Any, maximum: int) -> int:
    if value is None:
        value = min(25, maximum)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise validation_error()
    return min(value, maximum)


def resolved_scope(policies: ResolvedPolicies, space_id: str) -> Scope:
    return Scope(policies.environment, policies.tenant_id, policies.draft_id, safe_id(space_id))


def validated_space(policies: ResolvedPolicies, space_id: str, *, public: bool = False) -> dict[str, Any]:
    descriptor = policies.data_spaces
    if (
        not isinstance(descriptor, dict)
        or set(descriptor) != {"version", "scope", "spaces"}
        or descriptor.get("version") != 1
        or descriptor.get("scope") != policies.scope
        or not isinstance(descriptor.get("spaces"), list)
        or not 1 <= len(descriptor["spaces"]) <= 32
    ):
        raise policy_unavailable()
    selected_id = safe_id(space_id)
    seen: set[str] = set()
    matches = []
    for space in descriptor["spaces"]:
        if not isinstance(space, dict):
            raise policy_unavailable()
        _validate_space_shape(space)
        item_id = space["id"]
        if item_id in seen:
            raise policy_unavailable()
        seen.add(item_id)
        if item_id == selected_id:
            matches.append(space)
    if len(matches) != 1:
        raise HttpError(404, "not_found", "Resource not found.")
    space = matches[0]
    if space["status"] != "active" or (public and space["publicRead"]["enabled"] is not True):
        raise HttpError(404, "not_found", "Resource not found.")
    return space


def encode_cursor(
    policies: ResolvedPolicies,
    scope: Scope,
    kind: str,
    collection_id: str,
    raw_cursor: str | None,
) -> str | None:
    if raw_cursor is None:
        return None
    last_id = _last_id(kind, collection_id, raw_cursor)
    payload = {
        "v": 1,
        "k": kind,
        "c": collection_id,
        "l": last_id,
        "s": _cursor_scope(policies, scope, kind, collection_id),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")


def decode_cursor(
    policies: ResolvedPolicies,
    scope: Scope,
    kind: str,
    collection_id: str,
    token: Any,
) -> str | None:
    if token is None:
        return None
    if not isinstance(token, str) or not CURSOR_RE.fullmatch(token):
        raise validation_error()
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, TypeError):
        raise validation_error() from None
    if not isinstance(payload, dict) or set(payload) != {"v", "k", "c", "l", "s"}:
        raise validation_error()
    expected_scope = _cursor_scope(policies, scope, kind, collection_id)
    if (
        payload.get("v") != 1
        or payload.get("k") != kind
        or payload.get("c") != collection_id
        or not isinstance(payload.get("s"), str)
        or not hmac.compare_digest(payload["s"], expected_scope)
    ):
        raise validation_error()
    last_id = safe_id(payload.get("l"))
    return _storage_cursor(kind, collection_id, last_id)


def validation_error() -> HttpError:
    return HttpError(400, "validation_error", "Request validation failed.")


def policy_unavailable() -> HttpError:
    return HttpError(503, "upstream_unavailable", "Service temporarily unavailable.", retryable=True)


def success_response(data: Any, request_id: str) -> dict[str, Any]:
    return _json_response(200, {"ok": True, "data": data, "requestId": request_id})


def error_response(exc: Exception, request_id: str) -> dict[str, Any]:
    if isinstance(exc, HttpError):
        status, code, message, retryable = exc.status_code, exc.code, exc.message, exc.retryable
    elif isinstance(exc, AuthenticationError):
        status, code, message, retryable = 401, "auth_required", "Authentication required.", False
    elif isinstance(exc, AuthorizationError):
        status, code, message, retryable = 403, "forbidden", "You do not have access to this resource.", False
    elif isinstance(exc, PolicyResolutionError):
        status, code, message, retryable = 503, "upstream_unavailable", "Service temporarily unavailable.", True
    elif isinstance(exc, StorageNotFound):
        status, code, message, retryable = 404, "not_found", "Resource not found.", False
    elif isinstance(exc, StorageConflict):
        status, code, message, retryable = 409, "conflict", "Request conflicts with current state.", False
    elif isinstance(exc, (StorageLimitExceeded, SchemaPolicyError, ValueError)):
        status, code, message, retryable = 400, "validation_error", "Request validation failed.", False
    else:
        status, code, message, retryable = 500, "internal_error", "Request failed.", True
    return _json_response(status, {
        "ok": False,
        "code": code,
        "error": message,
        "message": message,
        "requestId": request_id,
        "retryable": retryable,
    })


def request_id_from(event: Any) -> str:
    context = event.get("requestContext") if isinstance(event, dict) and isinstance(event.get("requestContext"), dict) else {}
    candidate = context.get("requestId")
    if isinstance(candidate, str) and REQUEST_ID_RE.fullmatch(candidate):
        return candidate
    return f"request-{uuid.uuid4().hex}"


def _validate_space_shape(space: dict[str, Any]) -> None:
    if set(space) != {"id", "status", "access", "publicRead", "allowedClassifications", "limits"}:
        raise policy_unavailable()
    if not isinstance(space.get("id"), str) or not SAFE_ID_RE.fullmatch(space["id"]):
        raise policy_unavailable()
    if not isinstance(space.get("status"), str) or space["status"] not in {"active", "disabled"}:
        raise policy_unavailable()
    public = space.get("publicRead")
    if (
        not isinstance(public, dict)
        or set(public) != {"enabled", "maxPageSize"}
        or not isinstance(public.get("enabled"), bool)
        or not isinstance(public.get("maxPageSize"), int)
        or isinstance(public.get("maxPageSize"), bool)
        or not 1 <= public["maxPageSize"] <= 100
    ):
        raise policy_unavailable()
    classifications = space.get("allowedClassifications")
    if (
        not isinstance(classifications, list)
        or not 1 <= len(classifications) <= 2
        or any(not isinstance(item, str) for item in classifications)
        or len(set(classifications)) != len(classifications)
        or not set(classifications).issubset({"public", "internal"})
    ):
        raise policy_unavailable()
    limits = space.get("limits")
    bounds = {
        "maxCollections": (1, 100),
        "maxFieldsPerCollection": (1, 200),
        "maxRecordsPerCollection": (1, 1_000_000),
        "maxRecordBytes": (1_024, 400_000),
    }
    if not isinstance(limits, dict) or set(limits) != set(bounds):
        raise policy_unavailable()
    for key, (minimum, maximum) in bounds.items():
        value = limits.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
            raise policy_unavailable()
    access = space.get("access")
    if (
        not isinstance(access, dict)
        or not isinstance(access.get("mode"), str)
        or access["mode"] not in {"none", "auth-profile"}
    ):
        raise policy_unavailable()
    if access["mode"] == "none":
        if set(access) != {"mode"}:
            raise policy_unavailable()
        return
    if set(access) != {"mode", "authProfileId", "capabilities"}:
        raise policy_unavailable()
    if not isinstance(access.get("authProfileId"), str) or not SAFE_ID_RE.fullmatch(access["authProfileId"]):
        raise policy_unavailable()
    capabilities = access.get("capabilities")
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or any(not isinstance(item, str) for item in capabilities)
        or len(set(capabilities)) != len(capabilities)
        or not set(capabilities).issubset(CAPABILITIES)
    ):
        raise policy_unavailable()


def _last_id(kind: str, collection_id: str, raw_cursor: str) -> str:
    prefix = _cursor_prefix(kind, collection_id)
    if not isinstance(raw_cursor, str) or not raw_cursor.startswith(prefix):
        raise validation_error()
    suffix = raw_cursor[len(prefix):]
    return safe_id(suffix)


def _storage_cursor(kind: str, collection_id: str, last_id: str) -> str:
    return f"{_cursor_prefix(kind, collection_id)}{last_id}"


def _cursor_prefix(kind: str, collection_id: str) -> str:
    if kind == "collections" and collection_id == "":
        return "SCHEMA#"
    selected_collection = safe_id(collection_id)
    if kind == "records":
        return f"RECORD#{selected_collection}#"
    if kind == "public-records":
        return f"PUBLIC#{selected_collection}#"
    raise validation_error()


def _cursor_scope(policies: ResolvedPolicies, scope: Scope, kind: str, collection_id: str) -> str:
    value = "\0".join((
        policies.environment,
        policies.tenant_id,
        policies.draft_id,
        policies.domain,
        policies.version_id,
        scope.space_id,
        kind,
        collection_id,
    ))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _method(event: dict[str, Any]) -> str:
    context = event.get("requestContext") if isinstance(event.get("requestContext"), dict) else {}
    http = context.get("http") if isinstance(context.get("http"), dict) else {}
    value = http.get("method") or event.get("httpMethod")
    return value.upper() if isinstance(value, str) else ""


def _path(event: dict[str, Any]) -> str:
    value = event.get("rawPath") or event.get("path")
    return value if isinstance(value, str) else ""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate key")
        output[key] = value
    return output


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite number")


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


def _json_response(status_code: int, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
        },
        "body": json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False),
    }
