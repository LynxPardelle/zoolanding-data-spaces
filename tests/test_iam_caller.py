import os
import unittest
from unittest.mock import patch

from src.common.auth_admin import AuthorizationError
from src.common.iam_caller import require_internal_snapshot_caller


ROLE_ARN = "arn:aws:iam::123456789012:role/zoolanding-commerce-test"
SESSION_ARN = (
    "arn:aws:sts::123456789012:assumed-role/zoolanding-commerce-test/request-1"
)


def event(principal=SESSION_ARN):
    return {"requestContext": {"identity": {"userArn": principal}}}


class InternalCallerTests(unittest.TestCase):
    def test_empty_or_malformed_configuration_is_forbidden(self):
        for configured in (
            "",
            " ",
            "arn:aws:iam::123456789012:role/*",
            "arn:aws:iam::123456789012:user/not-a-role",
        ):
            with self.subTest(configured=configured):
                with patch.dict(
                    os.environ,
                    {"INTERNAL_SNAPSHOT_CALLER_ROLE_ARN": configured},
                    clear=True,
                ):
                    with self.assertRaises(Exception) as caught:
                        require_internal_snapshot_caller(event())
                self.assertIsInstance(caught.exception, AuthorizationError)

    def test_only_the_exact_configured_role_is_enabled(self):
        with patch.dict(
            os.environ,
            {"INTERNAL_SNAPSHOT_CALLER_ROLE_ARN": ROLE_ARN},
            clear=True,
        ):
            require_internal_snapshot_caller(event())
            with self.assertRaises(AuthorizationError):
                require_internal_snapshot_caller(
                    event(
                        "arn:aws:sts::123456789012:assumed-role/other-commerce/request-1"
                    )
                )


if __name__ == "__main__":
    unittest.main()
