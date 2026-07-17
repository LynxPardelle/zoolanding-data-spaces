"""Record projections kept independent from persistence and transport."""

from __future__ import annotations

import copy
from typing import Any, Mapping


def public_projection(schema: Mapping[str, Any], values: Mapping[str, Any]) -> dict[str, Any]:
    """Return only values explicitly classified public by the server schema."""

    return _project_fields(schema.get("fields", []), values)


def _project_fields(fields: list[Mapping[str, Any]], values: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field in fields:
        field_id = field["id"]
        if field.get("classification") != "public" or field_id not in values:
            continue
        result[field_id] = _project_value(field, values[field_id])
    return result


def _project_value(field: Mapping[str, Any], value: Any) -> Any:
    if field["type"] == "object":
        return _project_fields(field["fields"], value)
    if field["type"] == "array" and field["items"]["type"] == "object":
        return [_project_fields(field["items"]["fields"], item) for item in value]
    return copy.deepcopy(value)
