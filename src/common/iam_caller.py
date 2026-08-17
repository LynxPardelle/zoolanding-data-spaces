"""Fail-closed authorization for the one internal service caller role."""

from __future__ import annotations

import os
import re
from typing import Any

from .auth_admin import AuthorizationError


ROLE_ARN_RE = re.compile(
    r"^arn:(aws(?:-us-gov|-cn)?):iam::([0-9]{12}):role/(?:[A-Za-z0-9+=,.@_-]+/)*([A-Za-z0-9+=,.@_-]{1,64})$"
)
ASSUMED_ROLE_ARN_RE = re.compile(
    r"^arn:(aws(?:-us-gov|-cn)?):sts::([0-9]{12}):assumed-role/([A-Za-z0-9+=,.@_-]{1,64})/[A-Za-z0-9+=,.@_-]{1,128}$"
)


def require_internal_snapshot_caller(event: Any) -> None:
    expected = _role_identity(os.environ.get("INTERNAL_SNAPSHOT_CALLER_ROLE_ARN", ""), expected=True)
    if expected is None:
        raise AuthorizationError()

    identities = {
        identity
        for candidate in _caller_arns(event)
        if (identity := _role_identity(candidate, expected=False)) is not None
    }
    if identities != {expected}:
        raise AuthorizationError()


def _caller_arns(event: Any) -> tuple[str, ...]:
    if not isinstance(event, dict):
        return ()
    context = event.get("requestContext")
    if not isinstance(context, dict):
        return ()
    identity = context.get("identity") if isinstance(context.get("identity"), dict) else {}
    authorizer = context.get("authorizer") if isinstance(context.get("authorizer"), dict) else {}
    iam = authorizer.get("iam") if isinstance(authorizer.get("iam"), dict) else {}
    candidates = (identity.get("userArn"), authorizer.get("userArn"), iam.get("userArn"))
    return tuple(candidate for candidate in candidates if isinstance(candidate, str))


def _role_identity(value: str, *, expected: bool) -> tuple[str, str, str] | None:
    match = ROLE_ARN_RE.fullmatch(value)
    if match:
        return match.group(1), match.group(2), match.group(3)
    if expected:
        return None
    match = ASSUMED_ROLE_ARN_RE.fullmatch(value)
    if match:
        return match.group(1), match.group(2), match.group(3)
    return None
