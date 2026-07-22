from pathlib import Path
import re
import tomllib
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
FUNCTIONS = (
    "ProtectedReadFunction",
    "ProtectedActionFunction",
    "PublicReadFunction",
    "InternalSnapshotReadFunction",
)


class Phase8InfrastructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template_text = (ROOT / "template.yaml").read_text(encoding="utf-8")
        cls.template = yaml.safe_load(cls.template_text)
        cls.resources = cls.template["Resources"]

    def test_environment_and_cross_service_inputs_are_closed(self):
        parameters = self.template["Parameters"]
        self.assertEqual(
            parameters["EnvironmentName"],
            {"Type": "String", "AllowedValues": ["test", "production"]},
        )
        for name in (
            "ConfigRegistryTableName",
            "ConfigPayloadsBucketName",
            "AuthSessionTableName",
            "AuthUserStateTableName",
        ):
            self.assertEqual(
                parameters[name]["Type"], "AWS::SSM::Parameter::Value<String>"
            )
            self.assertNotIn("Default", parameters[name])

        role_pattern = (
            r"^$|^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/"
            r"[A-Za-z0-9+=,.@_/-]+$"
        )
        self.assertEqual(
            parameters["InternalSnapshotCallerRoleArn"]["AllowedPattern"],
            role_pattern,
        )
        self.assertIn("Default", parameters["InternalSnapshotCallerRoleArn"])
        self.assertEqual(parameters["InternalSnapshotCallerRoleArn"]["Default"], "")
        self.assertEqual(
            parameters["AlarmTopicArn"]["AllowedPattern"],
            r"^arn:(aws|aws-us-gov|aws-cn):sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_.-]+$",
        )
        self.assertNotIn("Default", parameters["AlarmTopicArn"])

    def test_stack_publishes_only_the_exact_safe_api_identifier(self):
        self.assertIn("DataSpacesApiIdParameter", self.resources)
        parameter = self.resources["DataSpacesApiIdParameter"]
        self.assertEqual(parameter["Type"], "AWS::SSM::Parameter")
        self.assertEqual(
            parameter["Properties"],
            {
                "Name": {
                    "Fn::Sub": "/zoolanding/${EnvironmentName}/services/data-spaces/api-id"
                },
                "Type": "String",
                "Value": {"Ref": "DataSpacesApi"},
            },
        )
        outputs = self.template["Outputs"]
        self.assertEqual(outputs["DataSpacesApiId"]["Value"], {"Ref": "DataSpacesApi"})
        self.assertEqual(
            outputs["DataSpacesApiIdParameterName"]["Value"],
            {"Ref": "DataSpacesApiIdParameter"},
        )
        rendered = yaml.safe_dump(outputs, sort_keys=True).lower()
        for forbidden in ("secret", "credential", "token", "password"):
            self.assertNotIn(forbidden, rendered)

    def test_runtime_iam_is_read_only_for_inherited_state_and_exact_for_own_data(self):
        forbidden_actions = {
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:DeleteItem",
            "dynamodb:BatchWriteItem",
            "s3:PutObject",
            "s3:DeleteObject",
            "secretsmanager:GetSecretValue",
            "secretsmanager:PutSecretValue",
        }
        rendered = yaml.safe_dump(self.resources, sort_keys=True)
        self.assertNotIn("Resource: '*'", rendered)
        self.assertNotIn("Action: '*'", rendered)

        for logical_id in FUNCTIONS:
            statements = []
            for policy in self.resources[logical_id]["Properties"]["Policies"]:
                statements.extend(policy.get("Statement", []))
            actions = {
                action
                for statement in statements
                for action in statement.get("Action", [])
            }
            self.assertTrue(forbidden_actions.isdisjoint(actions))

        data_descriptor = (
            "arn:${AWS::Partition}:s3:::${ConfigPayloadsBucketName}/"
            "sites/*/versions/*/*/server/data-spaces.json"
        )
        auth_descriptor = (
            "arn:${AWS::Partition}:s3:::${ConfigPayloadsBucketName}/"
            "sites/*/versions/*/*/server/auth-profile-registry.json"
        )
        self.assertEqual(
            self._s3_resources("ProtectedReadFunction"),
            {data_descriptor, auth_descriptor},
        )
        self.assertEqual(
            self._s3_resources("ProtectedActionFunction"),
            {data_descriptor, auth_descriptor},
        )
        self.assertEqual(self._s3_resources("PublicReadFunction"), {data_descriptor})
        self.assertEqual(
            self._s3_resources("InternalSnapshotReadFunction"), {data_descriptor}
        )

        internal_event = self.resources["InternalSnapshotReadFunction"]["Properties"][
            "Events"
        ]["InternalSnapshotRead"]["Properties"]
        self.assertEqual(internal_event["Auth"], {"Authorizer": "AWS_IAM"})
        self.assertEqual(
            self.resources["InternalSnapshotReadFunction"]["Properties"]["Environment"][
                "Variables"
            ]["INTERNAL_SNAPSHOT_CALLER_ROLE_ARN"],
            {"Ref": "InternalSnapshotCallerRoleArn"},
        )

    def test_alarms_cover_api_and_every_lambda_without_inventing_queues_or_streams(self):
        required = {
            "Api5xxAlarm",
            "ApiLatencyAlarm",
            "PublicRead4xxAlarm",
            "TestLiveMismatchAlarm",
        }
        for prefix in (
            "ProtectedRead",
            "ProtectedAction",
            "PublicRead",
            "InternalSnapshotRead",
        ):
            required.update(
                {
                    f"{prefix}ErrorsAlarm",
                    f"{prefix}DurationAlarm",
                    f"{prefix}ThrottlesAlarm",
                }
            )
        self.assertTrue(required.issubset(self.resources))
        for logical_id in required:
            alarm = self.resources[logical_id]
            self.assertEqual(alarm["Type"], "AWS::CloudWatch::Alarm")
            self.assertEqual(alarm["Properties"]["AlarmActions"], [{"Ref": "AlarmTopicArn"}])
            self.assertEqual(alarm["Properties"]["TreatMissingData"], "notBreaching")

        self.assertEqual(
            self.resources["Api5xxAlarm"]["Properties"]["MetricName"], "5XXError"
        )
        self.assertEqual(
            self.resources["ApiLatencyAlarm"]["Properties"]["MetricName"], "Latency"
        )
        for prefix, function in zip(
            ("ProtectedRead", "ProtectedAction", "PublicRead", "InternalSnapshotRead"),
            FUNCTIONS,
        ):
            for suffix, metric in (
                ("ErrorsAlarm", "Errors"),
                ("DurationAlarm", "Duration"),
                ("ThrottlesAlarm", "Throttles"),
            ):
                alarm = self.resources[f"{prefix}{suffix}"]["Properties"]
                self.assertEqual(alarm["Namespace"], "AWS/Lambda")
                self.assertEqual(alarm["MetricName"], metric)
                self.assertEqual(
                    alarm["Dimensions"],
                    [{"Name": "FunctionName", "Value": {"Ref": function}}],
                )

        mismatch = self.resources["TestLiveMismatchAlarm"]["Properties"]
        self.assertEqual(mismatch["Namespace"], "Zoolanding/DataSpaces")
        self.assertEqual(mismatch["MetricName"], "TestLiveMismatch")
        self.assertFalse(
            any(resource["Type"] == "AWS::SQS::Queue" for resource in self.resources.values())
        )
        table = self.resources["DataSpacesTable"]["Properties"]
        self.assertNotIn("StreamSpecification", table)

    def test_public_read_throttle_has_detailed_metrics_and_a_method_scoped_alarm(self):
        self.assertEqual(
            self.resources["DataSpacesApi"]["Properties"]["MethodSettings"],
            [
                {
                    "HttpMethod": "POST",
                    "ResourcePath": "/~1features~1data-spaces~1public-read",
                    "MetricsEnabled": True,
                    "ThrottlingRateLimit": 25,
                    "ThrottlingBurstLimit": 50,
                }
            ],
        )
        alarm = self.resources["PublicRead4xxAlarm"]["Properties"]
        self.assertEqual(alarm["Namespace"], "AWS/ApiGateway")
        self.assertEqual(alarm["MetricName"], "4XXError")
        self.assertEqual(alarm["Statistic"], "Sum")
        self.assertEqual(alarm["Period"], 60)
        self.assertEqual(alarm["EvaluationPeriods"], 1)
        self.assertEqual(alarm["DatapointsToAlarm"], 1)
        self.assertEqual(alarm["Threshold"], 1)
        self.assertEqual(
            alarm["ComparisonOperator"], "GreaterThanOrEqualToThreshold"
        )
        self.assertEqual(
            alarm["Dimensions"],
            [
                {"Name": "ApiName", "Value": {"Fn::Sub": "${AWS::StackName}-api"}},
                {"Name": "Stage", "Value": {"Ref": "EnvironmentName"}},
                {"Name": "Resource", "Value": "/features/data-spaces/public-read"},
                {"Name": "Method", "Value": "POST"},
            ],
        )

    def test_ci_runs_on_all_branches_and_deploys_reuse_only_the_validated_artifact(self):
        ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        self.assertRegex(ci, r"(?m)^on:\n  push:\s*$\n  pull_request:\s*$")
        self.assertNotIn("id-token: write", ci)
        self.assertIn("python tools/verify_sam_build.py", ci)

        for filename, branch, source, environment in (
            ("deploy-test.yml", "test", "dev", "test"),
            ("deploy-production.yml", "main", "test", "production"),
        ):
            text = (WORKFLOWS / filename).read_text(encoding="utf-8")
            self.assertIn(f"branches: [{branch}]", text)
            self.assertIn(f"SOURCE_BRANCH: {source}", text)
            self.assertIn(f"TARGET_BRANCH: {branch}", text)
            self.assertIn(f"environment: {environment}", text)
            self.assertEqual(text.count("id-token: write"), 1)
            self.assertIn("artifact-ids:", text)
            self.assertIn("build-manifest.sha256", text)
            self.assertIn("sha256sum --check --strict", text)
            self.assertGreaterEqual(text.count("find .aws-sam/build -type l -print -quit"), 2)
            self.assertIn("python tools/verify_sam_build.py", text)
            self.assertNotIn("sam build", text.split("  deploy:", 1)[1])
            self.assertIn("Validate exact cross-service SSM values", text)
            self.assertIn("aws ssm get-parameter", text)
            self.assertLess(
                text.index("configure-aws-credentials@"),
                text.index("Validate exact cross-service SSM values"),
            )
            self.assertLess(
                text.index("Validate exact cross-service SSM values"),
                text.index("sam deploy"),
            )
            self.assertIn(f'"EnvironmentName={environment}"', text)
            for suffix, variable in (
                ("config/registry-table-name", "ConfigRegistryTableName"),
                ("config/payload-bucket-name", "ConfigPayloadsBucketName"),
                ("auth/session-table-name", "AuthSessionTableName"),
                ("auth/user-state-table-name", "AuthUserStateTableName"),
            ):
                self.assertIn(
                    f'"{variable}=/zoolanding/{environment}/{suffix}"', text
                )
            self.assertIn("ALARM_TOPIC_ARN: ${{ vars.ALARM_TOPIC_ARN }}", text)
            self.assertIn('"AlarmTopicArn=$ALARM_TOPIC_ARN"', text)
            self.assertIn('if [[ -n "$INTERNAL_SNAPSHOT_CALLER_ROLE_ARN" ]]; then', text)
            self.assertIn(
                'parameter_overrides+=("InternalSnapshotCallerRoleArn=$INTERNAL_SNAPSHOT_CALLER_ROLE_ARN")',
                text,
            )
            self.assertIn('--parameter-overrides "${parameter_overrides[@]}"', text)
            self.assertNotIn('"EnvironmentName=prod"', text)
            self._assert_actions_are_pinned(text)

    def test_samconfig_has_only_test_and_production_profiles(self):
        with (ROOT / "samconfig.toml").open("rb") as handle:
            config = tomllib.load(handle)
        self.assertEqual(set(config), {"version", "test", "production"})
        self.assertEqual(
            config["test"]["deploy"]["parameters"]["parameter_overrides"],
            ["EnvironmentName=test"],
        )
        self.assertEqual(
            config["production"]["deploy"]["parameters"]["parameter_overrides"],
            ["EnvironmentName=production"],
        )
        text = (ROOT / "samconfig.toml").read_text(encoding="utf-8")
        self.assertNotRegex(text, r"(?m)^\[prod\.")
        self.assertNotIn('"EnvironmentName=prod"', text)
        self.assertNotIn("dev", text.lower())

    def test_release_helpers_and_bootstrap_contract_are_documented(self):
        self.assertTrue((ROOT / "tools" / "verify_sam_build.py").is_file())
        self.assertTrue((ROOT / "tools" / "data_spaces_readiness_smoke.py").is_file())
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for required in (
            "/zoolanding/{environment}/config/registry-table-name",
            "/zoolanding/{environment}/config/payload-bucket-name",
            "/zoolanding/{environment}/auth/session-table-name",
            "/zoolanding/{environment}/auth/user-state-table-name",
            "/zoolanding/{environment}/services/data-spaces/api-id",
            "INTERNAL_SNAPSHOT_CALLER_ROLE_ARN",
            "ALARM_TOPIC_ARN",
            "ZLP_DATA_SPACES_SMOKE_API_URL",
            "No AWS deployment was performed",
            "initial deployment leaves the internal snapshot route disabled",
            "may remain empty in later deployments",
            "not ready to enable until Commerce implements a dedicated caller",
            "publishes its exact role ARN",
            "403 `forbidden`",
            "exact caller ARN",
            "combines 400, 403, and 429 responses",
            "does not replace controlled load evidence",
        ):
            self.assertIn(required, readme)
        self.assertIn("dev -> test -> main", readme)

    def _s3_resources(self, logical_id):
        result = set()
        for policy in self.resources[logical_id]["Properties"]["Policies"]:
            for statement in policy.get("Statement", []):
                if "s3:GetObject" not in statement.get("Action", []):
                    continue
                resources = statement["Resource"]
                if not isinstance(resources, list):
                    resources = [resources]
                result.update(item["Fn::Sub"] for item in resources)
        return result

    def _assert_actions_are_pinned(self, text):
        actions = re.findall(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)", text)
        self.assertTrue(actions)
        for action in actions:
            if not action.startswith("./"):
                self.assertRegex(action, r"^[^@]+@[a-f0-9]{40}$")


if __name__ == "__main__":
    unittest.main()
