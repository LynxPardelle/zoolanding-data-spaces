from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

from tools import verify_sam_build


class BuildVerifierTests(unittest.TestCase):
    def test_handler_import_strips_credentials_and_cannot_write_bytecode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build_root = root / ".aws-sam" / "build"
            function_root = build_root / "ExampleFunction"
            function_root.mkdir(parents=True)
            template = {
                "Resources": {
                    "ExampleFunction": {
                        "Type": "AWS::Serverless::Function",
                        "Properties": {"Handler": "handlers.example.lambda_handler"},
                    }
                }
            }
            (root / "template.yaml").write_text(
                yaml.safe_dump(template), encoding="utf-8"
            )
            (build_root / "template.yaml").write_text("Resources: {}\n", encoding="utf-8")
            completed = subprocess.CompletedProcess([], 0, b"", b"")
            with (
                patch.object(verify_sam_build, "ROOT", root),
                patch.dict(
                    verify_sam_build.os.environ,
                    {
                        "AWS_ACCESS_KEY_ID": "synthetic",
                        "AWS_SECRET_ACCESS_KEY": "synthetic",
                        "PYTHONDONTWRITEBYTECODE": "0",
                    },
                    clear=True,
                ),
                patch.object(
                    verify_sam_build.subprocess, "run", return_value=completed
                ) as process,
            ):
                self.assertEqual(verify_sam_build.verify(), 1)

        environment = process.call_args.kwargs["env"]
        self.assertNotIn("AWS_ACCESS_KEY_ID", environment)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
        self.assertEqual(environment["AWS_EC2_METADATA_DISABLED"], "true")
        self.assertEqual(environment["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertEqual(environment["PYTHONPATH"], str(function_root))


if __name__ == "__main__":
    unittest.main()
