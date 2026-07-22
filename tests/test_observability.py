from contextlib import redirect_stdout
from io import StringIO
import json
import unittest
from unittest.mock import patch

from src.common import published_policy
from src.common.published_policy import PolicyResolutionError

try:
    from src.common.metrics import emit_metric
except ModuleNotFoundError:
    emit_metric = None


class ObservabilityTests(unittest.TestCase):
    def test_emf_metric_is_closed_and_pii_free(self):
        if emit_metric is None:
            self.fail("closed metric helper is missing")
        output = StringIO()
        with redirect_stdout(output):
            emit_metric("TestLiveMismatch", 1, environment="test")
        payload = json.loads(output.getvalue())
        self.assertEqual(set(payload), {"_aws", "Environment", "TestLiveMismatch"})
        self.assertEqual(payload["Environment"], "test")
        self.assertEqual(payload["TestLiveMismatch"], 1)
        metric = payload["_aws"]["CloudWatchMetrics"][0]
        self.assertEqual(metric["Namespace"], "Zoolanding/DataSpaces")
        self.assertEqual(metric["Dimensions"], [["Environment"]])
        rendered = output.getvalue().lower()
        for forbidden in ("email", "domain", "tenant", "draft", "payload", "secret", "token"):
            self.assertNotIn(forbidden, rendered)

    def test_metric_rejects_unknown_or_unbounded_values(self):
        if emit_metric is None:
            self.fail("closed metric helper is missing")
        for args in (
            ("UnknownMetric", 1, "test"),
            ("TestLiveMismatch", -1, "test"),
            ("TestLiveMismatch", 1.5, "test"),
            ("TestLiveMismatch", 1, "dev"),
            ("TestLiveMismatch", 1, "prod"),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                emit_metric(args[0], args[1], environment=args[2])

    def test_prod_runtime_alias_is_rejected(self):
        with self.assertRaises(PolicyResolutionError):
            published_policy._environment("prod")

    def test_descriptor_environment_mismatch_emits_metric_and_stays_fail_closed(self):
        self.assertTrue(hasattr(published_policy, "emit_metric"))
        policy = {
            "version": 1,
            "scope": {
                "environment": "production",
                "tenantId": "tenant-example",
                "draftId": "draft-example",
                "domain": "example.com",
            },
            "spaces": [],
        }
        with patch.object(published_policy, "emit_metric") as metric:
            with self.assertRaises(PolicyResolutionError):
                published_policy._validate_data_spaces(
                    policy,
                    "test",
                    "tenant-example",
                    "draft-example",
                    "example.com",
                )
        metric.assert_called_once_with("TestLiveMismatch", 1, environment="test")

        with patch.object(
            published_policy, "emit_metric", side_effect=RuntimeError("metric unavailable")
        ) as metric:
            with self.assertRaises(PolicyResolutionError):
                published_policy._validate_data_spaces(
                    policy,
                    "test",
                    "tenant-example",
                    "draft-example",
                    "example.com",
                )
        metric.assert_called_once()


if __name__ == "__main__":
    unittest.main()
