"""Redacted AWS_IAM readiness smoke for the Data Spaces internal API."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import sys
import time
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


_SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}", re.ASCII)
_FIELD_ID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}", re.ASCII)
_DOMAIN = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
    re.ASCII,
)
_REGION = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*", re.ASCII)
_API_HOST = re.compile(
    r"[a-z0-9]{10}\.execute-api\.(?P<region>[a-z0-9-]+)\.amazonaws\.com(?:\.cn)?",
    re.ASCII,
)
_REQUIRED = (
    "ZLP_DATA_SPACES_SMOKE_API_URL",
    "ZLP_DATA_SPACES_SMOKE_DOMAIN",
    "ZLP_DATA_SPACES_SMOKE_SPACE_ID",
    "ZLP_DATA_SPACES_SMOKE_COLLECTION_ID",
    "ZLP_DATA_SPACES_SMOKE_RECORD_ID",
    "ZLP_DATA_SPACES_SMOKE_REVISION",
    "ZLP_DATA_SPACES_SMOKE_FIELD_IDS",
    "AWS_REGION",
)


@dataclass(frozen=True, slots=True)
class SmokeRequest:
    url: str
    region: str
    environment: str
    headers: dict[str, str]
    payload: dict[str, Any]


@dataclass(frozen=True, slots=True)
class SmokeResponse:
    status: int


def run(
    environment: Mapping[str, str],
    *,
    sender: Callable[[SmokeRequest], SmokeResponse] | None = None,
    now_epoch: Callable[[], int] | None = None,
) -> dict[str, Any]:
    observed_at = _observation_epoch(now_epoch)
    values = {name: environment.get(name, "").strip() for name in _REQUIRED}
    if any(not values[name] for name in _REQUIRED):
        return _result(False, "missing_input", None, observed_at, attempts=0)
    try:
        request = _request(values)
    except (UnicodeError, ValueError):
        request = None
    if request is None:
        return _result(False, "missing_input", None, observed_at, attempts=0)
    transport = sender or _send
    try:
        response = transport(request)
        status = response.status
    except Exception:
        return _result(
            False,
            "provider_failure",
            request.environment,
            observed_at,
            attempts=1,
        )
    if type(status) is not int or not 100 <= status <= 599:
        return _result(
            False,
            "provider_failure",
            request.environment,
            observed_at,
            attempts=1,
        )
    if 200 <= status <= 299:
        return _result(
            True,
            "ready",
            request.environment,
            observed_at,
            status=status,
            attempts=1,
        )
    if status in {401, 403}:
        return _result(
            False,
            "auth_failure",
            request.environment,
            observed_at,
            status=status,
            attempts=1,
        )
    if status == 404 and _before_propagation_deadline(
        environment, observed_at
    ):
        return _result(
            False,
            "propagation_delay",
            request.environment,
            observed_at,
            status=status,
            attempts=1,
        )
    if 400 <= status <= 499:
        return _result(
            False,
            "configuration_failure",
            request.environment,
            observed_at,
            status=status,
            attempts=1,
        )
    return _result(
        False,
        "provider_failure",
        request.environment,
        observed_at,
        status=status,
        attempts=1,
    )


def _request(values: Mapping[str, str]) -> SmokeRequest | None:
    parsed = urlsplit(values["ZLP_DATA_SPACES_SMOKE_API_URL"])
    host = parsed.hostname or ""
    host_match = _API_HOST.fullmatch(host)
    region = values["AWS_REGION"]
    stage = parsed.path.strip("/")
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or host_match is None
        or host_match["region"] != region
        or _REGION.fullmatch(region) is None
        or stage not in {"test", "production"}
    ):
        return None

    domain = values["ZLP_DATA_SPACES_SMOKE_DOMAIN"].lower()
    safe_ids = (
        values["ZLP_DATA_SPACES_SMOKE_SPACE_ID"],
        values["ZLP_DATA_SPACES_SMOKE_COLLECTION_ID"],
        values["ZLP_DATA_SPACES_SMOKE_RECORD_ID"],
    )
    revision_raw = values["ZLP_DATA_SPACES_SMOKE_REVISION"]
    field_ids = [item.strip() for item in values["ZLP_DATA_SPACES_SMOKE_FIELD_IDS"].split(",")]
    if (
        _DOMAIN.fullmatch(domain) is None
        or any(_SAFE_ID.fullmatch(item) is None for item in safe_ids)
        or re.fullmatch(r"[1-9][0-9]{0,17}", revision_raw, re.ASCII) is None
        or not 1 <= len(field_ids) <= 200
        or any(_FIELD_ID.fullmatch(item) is None for item in field_ids)
        or len(set(field_ids)) != len(field_ids)
    ):
        return None

    return SmokeRequest(
        url=(
            f"{values['ZLP_DATA_SPACES_SMOKE_API_URL'].rstrip('/')}"
            "/internal/v1/data-spaces/record-snapshot"
        ),
        region=region,
        environment=stage,
        headers={"X-ZLP-Domain": domain},
        payload={
            "spaceId": safe_ids[0],
            "collectionId": safe_ids[1],
            "recordId": safe_ids[2],
            "revision": int(revision_raw),
            "fieldIds": field_ids,
        },
    )


def _send(smoke_request: SmokeRequest) -> SmokeResponse:
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.session import get_session

    body = json.dumps(
        smoke_request.payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    credentials = get_session().get_credentials()
    if credentials is None:
        raise RuntimeError("AWS credentials unavailable")
    headers = {"Content-Type": "application/json", **smoke_request.headers}
    aws_request = AWSRequest(
        method="POST",
        url=smoke_request.url,
        data=body,
        headers=headers,
    )
    SigV4Auth(
        credentials.get_frozen_credentials(), "execute-api", smoke_request.region
    ).add_auth(aws_request)
    outgoing = Request(
        smoke_request.url,
        data=body,
        headers=dict(aws_request.headers.items()),
        method="POST",
    )
    try:
        with urlopen(outgoing, timeout=10) as response:
            return SmokeResponse(response.status)
    except HTTPError as error:
        return SmokeResponse(error.code)
    except URLError as error:
        raise RuntimeError("Readiness transport unavailable") from error


def _before_propagation_deadline(
    environment: Mapping[str, str], now_epoch: int
) -> bool:
    raw = environment.get(
        "ZLP_DATA_SPACES_SMOKE_PROPAGATION_UNTIL_EPOCH", ""
    ).strip()
    if type(now_epoch) is not int or re.fullmatch(r"[0-9]{1,10}", raw, re.ASCII) is None:
        return False
    deadline = int(raw)
    return 0 <= now_epoch < deadline <= now_epoch + 900


def _result(
    ok: bool,
    classification: str,
    environment: str | None,
    observed_at: int,
    *,
    status: int | None = None,
    attempts: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ok": ok,
        "classification": classification,
        "environment": environment,
        "observedAtEpoch": observed_at,
        "attempts": attempts,
    }
    if status is not None:
        result["httpStatus"] = status
    return result


def _observation_epoch(now_epoch: Callable[[], int] | None) -> int:
    try:
        observed_at = (now_epoch or (lambda: int(time.time())))()
    except Exception:
        return 0
    return observed_at if type(observed_at) is int and 0 <= observed_at <= 9_999_999_999 else 0


def main() -> int:
    import os

    result = run(os.environ)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
