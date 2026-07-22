from pathlib import Path
import unittest

try:
    from tools import data_spaces_readiness_smoke as smoke
except ImportError:
    smoke = None


ROOT = Path(__file__).resolve().parents[1]
BASE_ENVIRONMENT = {
    "ZLP_DATA_SPACES_SMOKE_API_URL": "https://abcdefghij.execute-api.us-east-1.amazonaws.com/test",
    "ZLP_DATA_SPACES_SMOKE_DOMAIN": "example.com",
    "ZLP_DATA_SPACES_SMOKE_SPACE_ID": "catalog-content",
    "ZLP_DATA_SPACES_SMOKE_COLLECTION_ID": "articles",
    "ZLP_DATA_SPACES_SMOKE_RECORD_ID": "readiness-record",
    "ZLP_DATA_SPACES_SMOKE_REVISION": "1",
    "ZLP_DATA_SPACES_SMOKE_FIELD_IDS": "title",
    "AWS_REGION": "us-east-1",
}


class ReadinessSmokeTests(unittest.TestCase):
    def setUp(self):
        if smoke is None:
            self.fail("readiness smoke module is missing")

    def test_ready_request_is_exact_signed_snapshot_shape(self):
        captured = []

        def sender(request):
            captured.append(request)
            return smoke.SmokeResponse(200)

        result = smoke.run(BASE_ENVIRONMENT, sender=sender)

        self.assertEqual(
            result,
            {"ok": True, "classification": "ready", "httpStatus": 200, "attempts": 1},
        )
        self.assertEqual(len(captured), 1)
        request = captured[0]
        self.assertEqual(
            request.url,
            "https://abcdefghij.execute-api.us-east-1.amazonaws.com/test/internal/v1/data-spaces/record-snapshot",
        )
        self.assertEqual(request.region, "us-east-1")
        self.assertEqual(request.headers, {"X-ZLP-Domain": "example.com"})
        self.assertEqual(
            request.payload,
            {
                "spaceId": "catalog-content",
                "collectionId": "articles",
                "recordId": "readiness-record",
                "revision": 1,
                "fieldIds": ["title"],
            },
        )

    def test_five_failure_categories_are_closed_and_redacted(self):
        cases = (
            ({}, None, None, "missing_input", 0),
            (BASE_ENVIRONMENT, lambda _request: smoke.SmokeResponse(403), None, "auth_failure", 1),
            (BASE_ENVIRONMENT, lambda _request: smoke.SmokeResponse(400), None, "configuration_failure", 1),
            (BASE_ENVIRONMENT, lambda _request: smoke.SmokeResponse(500), None, "provider_failure", 1),
            (
                {
                    **BASE_ENVIRONMENT,
                    "ZLP_DATA_SPACES_SMOKE_PROPAGATION_UNTIL_EPOCH": "130",
                },
                lambda _request: smoke.SmokeResponse(404),
                lambda: 100,
                "propagation_delay",
                1,
            ),
        )
        for environment, sender, now_epoch, classification, attempts in cases:
            with self.subTest(classification=classification):
                kwargs = {}
                if sender is not None:
                    kwargs["sender"] = sender
                if now_epoch is not None:
                    kwargs["now_epoch"] = now_epoch
                result = smoke.run(environment, **kwargs)
                self.assertFalse(result["ok"])
                self.assertEqual(result["classification"], classification)
                self.assertEqual(result["attempts"], attempts)
                self.assertTrue(
                    set(result).issubset({"ok", "classification", "httpStatus", "attempts"})
                )

    def test_transport_failure_and_non_propagating_not_found_are_distinct(self):
        def unavailable(_request):
            raise RuntimeError("synthetic credential detail")

        self.assertEqual(
            smoke.run(BASE_ENVIRONMENT, sender=unavailable),
            {"ok": False, "classification": "provider_failure", "attempts": 1},
        )
        self.assertEqual(
            smoke.run(
                BASE_ENVIRONMENT,
                sender=lambda _request: smoke.SmokeResponse(404),
                now_epoch=lambda: 100,
            ),
            {
                "ok": False,
                "classification": "configuration_failure",
                "httpStatus": 404,
                "attempts": 1,
            },
        )

    def test_invalid_url_environment_revision_or_fields_never_reach_transport(self):
        cases = (
            {**BASE_ENVIRONMENT, "ZLP_DATA_SPACES_SMOKE_API_URL": "http://example.com/test"},
            {
                **BASE_ENVIRONMENT,
                "ZLP_DATA_SPACES_SMOKE_API_URL": "https://abcdefghij.execute-api.us-east-1.amazonaws.com/prod",
            },
            {**BASE_ENVIRONMENT, "ZLP_DATA_SPACES_SMOKE_REVISION": "0"},
            {**BASE_ENVIRONMENT, "ZLP_DATA_SPACES_SMOKE_FIELD_IDS": "title,title"},
            {**BASE_ENVIRONMENT, "ZLP_DATA_SPACES_SMOKE_FIELD_IDS": "title,not valid"},
        )
        for environment in cases:
            with self.subTest(environment=environment):
                result = smoke.run(
                    environment,
                    sender=lambda _request: self.fail("transport must not run"),
                )
                self.assertEqual(
                    result,
                    {"ok": False, "classification": "missing_input", "attempts": 0},
                )

    def test_script_has_no_cli_credential_or_raw_transport_output(self):
        text = (ROOT / "tools" / "data_spaces_readiness_smoke.py").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "--token",
            "--secret",
            "--password",
            "print(request",
            "print(response",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
