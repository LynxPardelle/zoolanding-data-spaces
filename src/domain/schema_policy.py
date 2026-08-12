"""Closed schema and record validation for generic Data Spaces."""

from __future__ import annotations

import copy
import datetime as dt
import json
import math
import re
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable, Mapping


FIELD_TYPES = frozenset(
    {
        "string",
        "integer",
        "decimal",
        "boolean",
        "enum",
        "object",
        "array",
        "date",
        "money-display",
        "asset-reference",
        "relation-id",
    }
)
CLASSIFICATIONS = frozenset({"public", "internal"})
SAFE_FIELD_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
SAFE_REFERENCE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SAFE_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
URL_RE = re.compile(
    r"(?:\b[a-z][a-z0-9+.-]*://|(?:^|\s)//|\bwww\.|\bmailto:|\bdata:)",
    re.IGNORECASE,
)
HTML_RE = re.compile(r"<\s*/?\s*[a-z][^>]*>", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d .()-]{8,}\d)(?!\w)")
PAYMENT_NUMBER_RE = re.compile(r"(?<!\d)\d{13,19}(?!\d)")
RFC_RE = re.compile(r"\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}\b", re.IGNORECASE)
CURP_RE = re.compile(r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(
    r"(?:\bBearer\s+[A-Za-z0-9._~-]+|\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]+|"
    r"\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}\b|"
    r"\b(?:smtp[_ -]?)?(?:password|passwd|pwd)\s*[:=]\s*\S+|"
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b)",
    re.IGNORECASE,
)
EXECUTABLE_RE = re.compile(
    r"(?:^\s*(?:[=+@]|-[A-Za-z]+\s*\()|javascript\s*:|\$\{|\{\{|"
    r"^\s*SET\s+(?:#[A-Za-z0-9_]+|[A-Za-z][A-Za-z0-9_.-]*)\s*=|"
    r"^\s*(?:ADD|DELETE)\s+(?:#[A-Za-z0-9_]+|[A-Za-z][A-Za-z0-9_.-]*)\s+:[A-Za-z0-9_]+|"
    r"^\s*REMOVE\s+#[A-Za-z0-9_]+)",
    re.IGNORECASE,
)
PROVIDER_RESOURCE_ID_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"(?:acct|cus|sub|price|prod|pm|pi|evt)_[A-Za-z0-9]{12,}|"
    r"cs_(?:(?:test|live)_)?[A-Za-z0-9]{12,}|"
    r"in_(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{12,}"
    r")(?![A-Za-z0-9])",
    re.IGNORECASE,
)
INFRA_REFERENCE_RE = re.compile(
    r"(?:\{\{\s*resolve:(?:ssm(?:-secure)?|secretsmanager):|"
    r"\barn:aws(?:-us-gov|-cn)?:[a-z0-9-]+:|"
    r"(?<![a-z0-9])(?:ssm|ssm-secure|secretsmanager|secrets-manager|aws-secretsmanager):(?://|/)|"
    r"(?<![A-Za-z0-9])/(?:zoolanding|zoolandingpage)/(?:test|production)/)",
    re.IGNORECASE,
)

_COMMON_KEYS = frozenset({"id", "type", "classification", "required", "label"})
_TYPE_KEYS = {
    "string": frozenset({"minLength", "maxLength"}),
    "integer": frozenset({"minimum", "maximum"}),
    "decimal": frozenset({"minimum", "maximum"}),
    "boolean": frozenset(),
    "enum": frozenset({"values"}),
    "object": frozenset({"fields"}),
    "array": frozenset({"items", "maxItems"}),
    "date": frozenset(),
    "money-display": frozenset({"presentationOnly"}),
    "asset-reference": frozenset(),
    "relation-id": frozenset(),
}
_ITEM_COMMON_KEYS = frozenset({"type"})

_RESTRICTED_SINGLE_TOKENS = frozenset(
    {
        "password",
        "passphrase",
        "secret",
        "token",
        "credential",
        "credentials",
        "email",
        "phone",
        "telephone",
        "telefono",
        "address",
        "direccion",
        "passport",
        "curp",
        "rfc",
        "clabe",
        "iban",
        "swift",
        "ssn",
        "cvv",
        "cvc",
        "payment",
        "fiscal",
        "tax",
        "bank",
        "card",
        "identity",
        "inventory",
        "stock",
        "order",
        "subscription",
        "table",
        "index",
        "expression",
        "pii",
        "dob",
        "birthdate",
        "birthday",
        "biometric",
        "medical",
        "health",
    }
)
_RESTRICTED_PAIRS = frozenset(
    {
        "api_key",
        "access_key",
        "private_key",
        "customer_name",
        "full_name",
        "first_name",
        "last_name",
        "identity_document",
        "account_number",
        "routing_number",
        "partition_key",
        "sort_key",
        "condition_expression",
        "update_expression",
        "filter_expression",
        "projection_expression",
        "price_in_cents",
        "private_data",
        "personal_data",
        "date_of_birth",
        "ip_address",
        "nombre_completo",
        "razon_social",
    }
)
_COMMERCIAL_TOKENS = frozenset({"price", "cost", "amount"})
_PROVIDER_OR_INFRA_FIELD_IDS = frozenset(
    {
        "account_id",
        "connected_account",
        "external_account",
        "provider_account",
        "provider_account_id",
        "provider_id",
        "resource_arn",
        "resource_id",
        "secrets_manager_ref",
        "ssm_parameter",
        "stripe_account",
    }
)


class SchemaPolicyError(ValueError):
    """Raised when a schema or record is outside the closed policy."""

    def __init__(self, message: str, code: str = "invalid_schema") -> None:
        super().__init__(message)
        self.code = code


def validate_schema(
    schema: Mapping[str, Any],
    max_fields: int,
    allowed_classifications: Iterable[str] = CLASSIFICATIONS,
) -> dict[str, Any]:
    """Validate and copy a closed collection schema."""

    if not isinstance(max_fields, int) or isinstance(max_fields, bool) or not 1 <= max_fields <= 200:
        raise SchemaPolicyError("max_fields must be between 1 and 200")
    if not isinstance(schema, Mapping) or set(schema) != {"fields"}:
        raise SchemaPolicyError("schema must contain only fields")
    allowed = frozenset(allowed_classifications)
    if not allowed or not allowed.issubset(CLASSIFICATIONS):
        raise SchemaPolicyError("allowed classifications are invalid")

    state = {"count": 0, "active": set()}
    fields = _validate_fields(schema["fields"], 1, max_fields, allowed, state)
    return {"fields": fields}


def validate_record(
    schema: Mapping[str, Any],
    values: Mapping[str, Any],
    max_record_bytes: int = 400_000,
) -> dict[str, Any]:
    """Validate record values against an already validated schema."""

    if not isinstance(values, Mapping):
        raise SchemaPolicyError("record data must be an object", "invalid_record")
    if not isinstance(max_record_bytes, int) or isinstance(max_record_bytes, bool) or not 1 <= max_record_bytes <= 400_000:
        raise SchemaPolicyError("max_record_bytes is invalid", "invalid_record")
    fields = schema.get("fields") if isinstance(schema, Mapping) else None
    checked = _validate_object_values(fields, values)
    try:
        encoded = json.dumps(checked, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise SchemaPolicyError("record data is not valid JSON", "invalid_record") from exc
    if len(encoded) > max_record_bytes:
        raise SchemaPolicyError("record exceeds maxRecordBytes", "record_too_large")
    return checked


def _validate_fields(
    fields: Any,
    depth: int,
    max_fields: int,
    allowed: frozenset[str],
    state: dict[str, Any],
) -> list[dict[str, Any]]:
    if depth > 4:
        raise SchemaPolicyError("schema depth exceeds four")
    if not isinstance(fields, list) or not fields:
        raise SchemaPolicyError("fields must be a non-empty array")
    marker = id(fields)
    if marker in state["active"]:
        raise SchemaPolicyError("recursive schemas are not allowed")
    state["active"].add(marker)
    try:
        result = []
        seen = set()
        for field in fields:
            if not isinstance(field, Mapping):
                raise SchemaPolicyError("field definitions must be objects")
            field_id = field.get("id")
            if not isinstance(field_id, str) or not SAFE_FIELD_ID_RE.fullmatch(field_id):
                raise SchemaPolicyError("field id is invalid")
            normalized_id = field_id.casefold()
            if normalized_id in seen:
                raise SchemaPolicyError("field ids must be unique")
            seen.add(normalized_id)
            state["count"] += 1
            if state["count"] > max_fields:
                raise SchemaPolicyError("schema exceeds maxFieldsPerCollection")
            result.append(_validate_field(field, depth, max_fields, allowed, state, require_identity=True))
        return result
    finally:
        state["active"].remove(marker)


def _validate_field(
    field: Mapping[str, Any],
    depth: int,
    max_fields: int,
    allowed: frozenset[str],
    state: dict[str, Any],
    require_identity: bool,
) -> dict[str, Any]:
    field_type = field.get("type")
    if field_type not in FIELD_TYPES:
        raise SchemaPolicyError("field type is not supported")
    allowed_keys = (_COMMON_KEYS if require_identity else _ITEM_COMMON_KEYS) | _TYPE_KEYS[field_type]
    if not set(field).issubset(allowed_keys):
        raise SchemaPolicyError("field contains unsupported properties")
    if require_identity:
        classification = field.get("classification")
        if classification not in allowed:
            raise SchemaPolicyError("field classification is not allowed")
        required = field.get("required", False)
        if not isinstance(required, bool):
            raise SchemaPolicyError("required must be boolean")
        _validate_field_name(field["id"], field_type, field.get("presentationOnly") is True)
        if "label" in field:
            _validate_plain_text(field["label"], 120, "label")

    _validate_type_options(field, field_type)
    result = dict(field)
    if field_type == "object":
        result["fields"] = _validate_fields(field.get("fields"), depth + 1, max_fields, allowed, state)
    elif field_type == "array":
        items = field.get("items")
        if not isinstance(items, Mapping):
            raise SchemaPolicyError("array items must be a field definition")
        marker = id(items)
        if marker in state["active"]:
            raise SchemaPolicyError("recursive schemas are not allowed")
        state["active"].add(marker)
        try:
            result["items"] = _validate_field(items, depth + 1, max_fields, allowed, state, require_identity=False)
        finally:
            state["active"].remove(marker)
    return result


def _validate_type_options(field: Mapping[str, Any], field_type: str) -> None:
    if field_type in {"string"}:
        _validate_length_bounds(field)
    elif field_type in {"integer", "decimal"}:
        minimum = field.get("minimum")
        maximum = field.get("maximum")
        if minimum is not None and not _is_number(minimum):
            raise SchemaPolicyError("minimum must be numeric")
        if maximum is not None and not _is_number(maximum):
            raise SchemaPolicyError("maximum must be numeric")
        if minimum is not None and maximum is not None and minimum > maximum:
            raise SchemaPolicyError("minimum cannot exceed maximum")
    elif field_type == "enum":
        values = field.get("values")
        if not isinstance(values, list) or not 1 <= len(values) <= 100 or len(set(map(repr, values))) != len(values):
            raise SchemaPolicyError("enum values must be a unique non-empty array")
        for value in values:
            _validate_plain_text(value, 120, "enum value")
    elif field_type == "array":
        max_items = field.get("maxItems")
        if not isinstance(max_items, int) or isinstance(max_items, bool) or not 1 <= max_items <= 1_000:
            raise SchemaPolicyError("array maxItems must be between 1 and 1000")
    elif field_type == "money-display" and field.get("presentationOnly") is not True:
        raise SchemaPolicyError("money-display must set presentationOnly true")


def _validate_length_bounds(field: Mapping[str, Any]) -> None:
    minimum = field.get("minLength", 0)
    maximum = field.get("maxLength", 10_000)
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 0:
        raise SchemaPolicyError("minLength is invalid")
    if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 10_000:
        raise SchemaPolicyError("maxLength is invalid")
    if minimum > maximum:
        raise SchemaPolicyError("minLength cannot exceed maxLength")


def _validate_field_name(field_id: str, field_type: str, presentation_only: bool) -> None:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", field_id)
    tokens = [token for token in re.sub(r"[^a-z0-9]+", "_", normalized.lower()).split("_") if token]
    joined = "_".join(tokens)
    if (
        joined in _PROVIDER_OR_INFRA_FIELD_IDS
        or any(token in {"arn", "aws", "ssm"} for token in tokens)
        or ("secrets" in tokens and "manager" in tokens)
        or ("parameter" in tokens and "store" in tokens)
        or (
            "provider" in tokens
            and any(token in {"account", "id", "mapping", "ref", "reference", "resource"} for token in tokens)
        )
        or (
            any(token in {"connected", "external", "stripe"} for token in tokens)
            and any(token in {"account", "customer", "id", "mapping", "ref", "reference", "resource"} for token in tokens)
        )
    ):
        raise SchemaPolicyError("provider or infrastructure field is not allowed")
    if any(token in _RESTRICTED_SINGLE_TOKENS for token in tokens) or any(pair in joined for pair in _RESTRICTED_PAIRS):
        raise SchemaPolicyError("restricted field class is not allowed")
    if any(token in _COMMERCIAL_TOKENS for token in tokens) and not (field_type == "money-display" and presentation_only):
        raise SchemaPolicyError("commercial state is not allowed")


def _validate_object_values(fields: Any, values: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(fields, list):
        raise SchemaPolicyError("schema fields are invalid", "invalid_record")
    definitions = {field["id"]: field for field in fields}
    unknown = set(values) - set(definitions)
    if unknown:
        raise SchemaPolicyError("record contains unknown fields", "invalid_record")
    for field_id, field in definitions.items():
        if field.get("required") is True and field_id not in values:
            raise SchemaPolicyError("record is missing a required field", "invalid_record")
    return {field_id: _validate_value(definitions[field_id], value) for field_id, value in values.items()}


def _validate_value(field: Mapping[str, Any], value: Any) -> Any:
    field_type = field["type"]
    if field_type == "string":
        if not isinstance(value, str):
            raise SchemaPolicyError("string field has the wrong type", "invalid_record")
        minimum = field.get("minLength", 0)
        maximum = field.get("maxLength", 10_000)
        if not minimum <= len(value) <= maximum:
            raise SchemaPolicyError("string field is outside its length bounds", "invalid_record")
        _reject_unsafe_value(value)
        return value
    if field_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool) or not _is_number(value):
            raise SchemaPolicyError("integer field has the wrong type", "invalid_record")
        _check_number_bounds(field, value)
        return value
    if field_type == "decimal":
        if not _is_number(value):
            raise SchemaPolicyError("decimal field has the wrong type", "invalid_record")
        _check_number_bounds(field, value)
        return value
    if field_type == "boolean":
        if not isinstance(value, bool):
            raise SchemaPolicyError("boolean field has the wrong type", "invalid_record")
        return value
    if field_type == "enum":
        if value not in field["values"]:
            raise SchemaPolicyError("enum field has an unknown value", "invalid_record")
        return copy.deepcopy(value)
    if field_type == "object":
        if not isinstance(value, Mapping):
            raise SchemaPolicyError("object field has the wrong type", "invalid_record")
        return _validate_object_values(field["fields"], value)
    if field_type == "array":
        if not isinstance(value, list) or len(value) > field["maxItems"]:
            raise SchemaPolicyError("array field is invalid", "invalid_record")
        return [_validate_value(field["items"], item) for item in value]
    if field_type == "date":
        if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            raise SchemaPolicyError("date field must use YYYY-MM-DD", "invalid_record")
        try:
            dt.date.fromisoformat(value)
        except ValueError as exc:
            raise SchemaPolicyError("date field is invalid", "invalid_record") from exc
        return value
    if field_type == "money-display":
        if not isinstance(value, Mapping) or set(value) != {"amountMinor", "currency"}:
            raise SchemaPolicyError("money-display value is invalid", "invalid_record")
        amount = value["amountMinor"]
        currency = value["currency"]
        if not isinstance(amount, int) or isinstance(amount, bool) or abs(amount) > 9_000_000_000_000_000:
            raise SchemaPolicyError("money-display amountMinor is invalid", "invalid_record")
        if not isinstance(currency, str) or not SAFE_CURRENCY_RE.fullmatch(currency):
            raise SchemaPolicyError("money-display currency is invalid", "invalid_record")
        return {"amountMinor": amount, "currency": currency}
    if field_type in {"asset-reference", "relation-id"}:
        if isinstance(value, str):
            _reject_provider_or_infra_reference(value)
        if not isinstance(value, str) or not SAFE_REFERENCE_RE.fullmatch(value):
            raise SchemaPolicyError(f"{field_type} must be a same-space safe id", "invalid_record")
        return value
    raise SchemaPolicyError("field type is not supported", "invalid_record")


def _check_number_bounds(field: Mapping[str, Any], value: int | float) -> None:
    if "minimum" in field and value < field["minimum"]:
        raise SchemaPolicyError("number is below minimum", "invalid_record")
    if "maximum" in field and value > field["maximum"]:
        raise SchemaPolicyError("number exceeds maximum", "invalid_record")


def _is_number(value: Any) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    if isinstance(value, float) and not math.isfinite(value):
        return False
    try:
        number = Decimal(value) if isinstance(value, int) else Decimal(str(value))
    except (InvalidOperation, ValueError):
        return False
    if not number.is_finite() or len(number.as_tuple().digits) > 38:
        return False
    return number.is_zero() or -130 <= number.adjusted() <= 125


def _validate_plain_text(value: Any, max_length: int, label: str) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= max_length:
        raise SchemaPolicyError(f"{label} is invalid")
    _reject_unsafe_value(value)


def _reject_unsafe_value(value: str) -> None:
    _reject_provider_or_infra_reference(value)
    if any(
        pattern.search(value)
        for pattern in (URL_RE, HTML_RE, EMAIL_RE, PHONE_RE, PAYMENT_NUMBER_RE, RFC_RE, CURP_RE, SECRET_VALUE_RE, EXECUTABLE_RE)
    ):
        raise SchemaPolicyError("restricted or executable text is not allowed", "invalid_record")


def _reject_provider_or_infra_reference(value: str) -> None:
    if PROVIDER_RESOURCE_ID_RE.search(value) or INFRA_REFERENCE_RE.search(value):
        raise SchemaPolicyError("provider or infrastructure reference is not allowed", "invalid_record")
