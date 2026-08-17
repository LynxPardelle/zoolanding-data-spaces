import re
import tomllib
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
ACTION_SHA = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def load_yaml(path: Path):
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


class RepositoryContractTests(unittest.TestCase):
    def test_template_exposes_only_the_four_approved_post_routes(self):
        template = load_yaml(ROOT / "template.yaml")
        resources = template["Resources"]
        functions = {
            name: resource
            for name, resource in resources.items()
            if resource["Type"] == "AWS::Serverless::Function"
        }
        self.assertEqual(
            set(functions),
            {
                "ProtectedReadFunction",
                "ProtectedActionFunction",
                "PublicReadFunction",
                "InternalSnapshotReadFunction",
            },
        )
        self.assertEqual(
            {function["Properties"]["Handler"] for function in functions.values()},
            {
                "handlers.protected_read.lambda_handler",
                "handlers.protected_action.lambda_handler",
                "handlers.public_read.lambda_handler",
                "handlers.internal_snapshot_read.lambda_handler",
            },
        )

        events = []
        for logical_id, function in functions.items():
            for event in function["Properties"]["Events"].values():
                if event["Type"] == "Api":
                    events.append((logical_id, event["Properties"]))

        self.assertEqual(
            {(logical_id, event["Path"], event["Method"]) for logical_id, event in events},
            {
                ("ProtectedReadFunction", "/features/data-spaces/read", "POST"),
                ("ProtectedActionFunction", "/features/data-spaces/action", "POST"),
                ("PublicReadFunction", "/features/data-spaces/public-read", "POST"),
                (
                    "InternalSnapshotReadFunction",
                    "/internal/v1/data-spaces/record-snapshot",
                    "POST",
                ),
            },
        )
        internal = next(event for logical_id, event in events if logical_id == "InternalSnapshotReadFunction")
        self.assertEqual(internal["Auth"]["Authorizer"], "AWS_IAM")
        for logical_id, event in events:
            if logical_id != "InternalSnapshotReadFunction":
                self.assertNotIn("Auth", event)

        method_settings = resources["DataSpacesApi"]["Properties"]["MethodSettings"]
        self.assertEqual(method_settings, [{
            "HttpMethod": "POST",
            "ResourcePath": "/~1features~1data-spaces~1public-read",
            "MetricsEnabled": "true",
            "ThrottlingRateLimit": "25",
            "ThrottlingBurstLimit": "50",
        }])

    def test_template_uses_separate_python_313_lambdas_and_safe_environment_parameters(self):
        template = load_yaml(ROOT / "template.yaml")
        self.assertEqual(template["Globals"]["Function"]["Runtime"], "python3.13")
        environment = template["Parameters"]["EnvironmentName"]
        self.assertEqual(environment["AllowedValues"], ["test", "production"])
        self.assertNotIn("Default", environment)

        functions = [
            resource
            for resource in template["Resources"].values()
            if resource["Type"] == "AWS::Serverless::Function"
        ]
        self.assertEqual(len(functions), 4)
        for function in functions:
            properties = function["Properties"]
            self.assertEqual(properties["CodeUri"], "src/")
            variables = properties["Environment"]["Variables"]
            self.assertIn("DATA_SPACES_TABLE_NAME", variables)
            self.assertIn("ENVIRONMENT_NAME", variables)

        for logical_id in (
            "ProtectedReadFunction",
            "ProtectedActionFunction",
            "PublicReadFunction",
            "InternalSnapshotReadFunction",
        ):
            variables = template["Resources"][logical_id]["Properties"]["Environment"]["Variables"]
            self.assertIn("CONFIG_REGISTRY_TABLE_NAME", variables)
            self.assertIn("CONFIG_PAYLOADS_BUCKET_NAME", variables)

        protected = [
            template["Resources"]["ProtectedReadFunction"],
            template["Resources"]["ProtectedActionFunction"],
        ]
        for function in protected:
            variables = function["Properties"]["Environment"]["Variables"]
            self.assertIn("AUTH_SESSION_TABLE_NAME", variables)
            self.assertIn("AUTH_USER_STATE_TABLE_NAME", variables)

        for logical_id in ("PublicReadFunction", "InternalSnapshotReadFunction"):
            variables = template["Resources"][logical_id]["Properties"]["Environment"]["Variables"]
            self.assertNotIn("AUTH_SESSION_TABLE_NAME", variables)
            self.assertNotIn("AUTH_USER_STATE_TABLE_NAME", variables)

        internal_variables = template["Resources"]["InternalSnapshotReadFunction"]["Properties"]["Environment"]["Variables"]
        self.assertEqual(internal_variables["INTERNAL_SNAPSHOT_CALLER_ROLE_ARN"], {"Ref": "InternalSnapshotCallerRoleArn"})
        caller_parameter = template["Parameters"]["InternalSnapshotCallerRoleArn"]
        self.assertEqual(caller_parameter["Type"], "String")
        self.assertIn("Default", caller_parameter)
        self.assertEqual(caller_parameter["Default"], "")
        self.assertEqual(
            caller_parameter["AllowedPattern"],
            r"^$|^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$",
        )

    def test_template_owns_one_on_demand_encrypted_recoverable_ttl_table_without_indexes(self):
        template = load_yaml(ROOT / "template.yaml")
        tables = [
            resource
            for resource in template["Resources"].values()
            if resource["Type"] == "AWS::DynamoDB::Table"
        ]
        self.assertEqual(len(tables), 1)
        properties = tables[0]["Properties"]
        self.assertEqual(properties["BillingMode"], "PAY_PER_REQUEST")
        self.assertEqual(properties["SSESpecification"]["SSEEnabled"], "true")
        self.assertEqual(
            properties["PointInTimeRecoverySpecification"]["PointInTimeRecoveryEnabled"],
            "true",
        )
        self.assertEqual(
            properties["TimeToLiveSpecification"],
            {"AttributeName": "expiresAt", "Enabled": "true"},
        )
        self.assertEqual(properties["KeySchema"], [
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ])
        self.assertNotIn("GlobalSecondaryIndexes", properties)
        self.assertNotIn("LocalSecondaryIndexes", properties)

    def test_s3_policy_exposes_only_the_descriptors_each_handler_reads(self):
        template = load_yaml(ROOT / "template.yaml")

        def s3_resources(logical_id):
            result = set()
            for policy in template["Resources"][logical_id]["Properties"]["Policies"]:
                for statement in policy.get("Statement", []):
                    actions = statement.get("Action", [])
                    if "s3:GetObject" not in actions:
                        continue
                    resources = statement["Resource"]
                    if not isinstance(resources, list):
                        resources = [resources]
                    result.update(resource["Fn::Sub"] for resource in resources)
            return result

        data_descriptor = "arn:${AWS::Partition}:s3:::${ConfigPayloadsBucketName}/sites/*/versions/*/*/server/data-spaces.json"
        auth_descriptor = "arn:${AWS::Partition}:s3:::${ConfigPayloadsBucketName}/sites/*/versions/*/*/server/auth-profile-registry.json"
        self.assertEqual(s3_resources("ProtectedReadFunction"), {data_descriptor, auth_descriptor})
        self.assertEqual(s3_resources("ProtectedActionFunction"), {data_descriptor, auth_descriptor})
        self.assertEqual(s3_resources("PublicReadFunction"), {data_descriptor})
        self.assertEqual(s3_resources("InternalSnapshotReadFunction"), {data_descriptor})

    def test_dependency_and_sam_configs_are_closed_to_test_and_production(self):
        requirements = [
            line.strip()
            for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(requirements, ["boto3==1.39.13"])

        config = tomllib.loads((ROOT / "samconfig.toml").read_text(encoding="utf-8"))
        self.assertEqual(set(config), {"version", "test", "production"})
        self.assertNotIn("default", config)
        self.assertNotIn("dev", config)
        for environment, expected_name in (
            ("test", "EnvironmentName=test"),
            ("production", "EnvironmentName=production"),
        ):
            parameters = config[environment]["deploy"]["parameters"]
            self.assertIn(expected_name, parameters["parameter_overrides"])
            self.assertFalse(parameters["confirm_changeset"])

    def test_workflows_are_pinned_branch_scoped_and_reuse_only_the_validated_artifact(self):
        ci_text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        self.assertNotIn("id-token: write", ci_text)
        self.assertIn("version: 1.163.0", ci_text)
        self.assertIn("pip-audit==2.10.1", ci_text)
        self.assertIn("python -m pip_audit -r requirements.txt", ci_text)
        self.assertIn("PYTHONDONTWRITEBYTECODE: 1", ci_text)
        self.assertIn(
            "gitleaks/gitleaks-action@ff98106e4c7b2bc287b24eaf42907196329070c7",
            ci_text,
        )
        self.assertIn("fetch-depth: 0", ci_text)

        expected_artifact_paths = {
            ".aws-sam/build/template.yaml",
            ".aws-sam/build/ProtectedReadFunction",
            ".aws-sam/build/ProtectedActionFunction",
            ".aws-sam/build/PublicReadFunction",
            ".aws-sam/build/InternalSnapshotReadFunction",
            ".aws-sam/build-manifest.sha256",
        }
        for filename, branch, environment in (
            ("deploy-test.yml", "test", "test"),
            ("deploy-production.yml", "main", "production"),
        ):
            path = WORKFLOWS / filename
            text = path.read_text(encoding="utf-8")
            workflow = load_yaml(path)
            self.assertEqual(workflow["on"]["push"]["branches"], [branch])
            self.assertEqual(workflow["concurrency"]["cancel-in-progress"], "false")
            self.assertEqual(workflow["jobs"]["deploy"]["environment"], environment)
            self.assertEqual(workflow["jobs"]["deploy"]["needs"], "validate")
            self.assertEqual(workflow["permissions"]["pull-requests"], "read")
            self.assertEqual(workflow["jobs"]["deploy"]["permissions"]["pull-requests"], "read")
            self.assertIn("version: 1.163.0", text)
            self.assertIn("pip-audit==2.10.1", text)
            self.assertIn("python -m pip_audit -r requirements.txt", text)
            self.assertIn("PYTHONDONTWRITEBYTECODE: 1", text)
            self.assertIn("ref: ${{ github.sha }}", text)
            self.assertIn("persist-credentials: false", text)
            self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"', text)
            self.assertIn("test -z \"$(git status --porcelain)\"", text)
            self.assertIn("artifact-ids:", text)
            self.assertNotIn("sam build", text.split("  deploy:", 1)[1])
            self.assertEqual(text.count("actions/github-script@"), 2)
            self.assertEqual(text.count("promotion_target_tip_mismatch"), 2)
            self.assertEqual(text.count("promotion_pr_not_found"), 2)
            self.assertIn("AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}", text)
            self.assertIn(
                "role_pattern='^arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/",
                text,
            )
            self.assertIn('[[ "$AWS_ROLE_ARN" =~ $role_pattern ]]', text)
            self.assertIn('deployment_account="${BASH_REMATCH[2]}"', text)
            self.assertIn(
                f"/zoolanding/{environment}/auth/user-state-table-name", text
            )
            self.assertIn("aws ssm get-parameter", text)
            self.assertIn("INTERNAL_SNAPSHOT_CALLER_ROLE_ARN: ${{ secrets.INTERNAL_SNAPSHOT_CALLER_ROLE_ARN }}", text)
            self.assertIn('if [[ -n "$INTERNAL_SNAPSHOT_CALLER_ROLE_ARN" ]]; then', text)
            self.assertIn(
                'parameter_overrides+=("InternalSnapshotCallerRoleArn=$INTERNAL_SNAPSHOT_CALLER_ROLE_ARN")',
                text,
            )
            self.assertIn("ALARM_TOPIC_ARN: ${{ secrets.ALARM_TOPIC_ARN }}", text)
            self.assertNotIn("${{ vars.", text)
            self.assertIn('"AlarmTopicArn=$ALARM_TOPIC_ARN"', text)
            second_provenance = text.rfind("actions/github-script@")
            credentials = text.index("aws-actions/configure-aws-credentials@")
            self.assertLess(second_provenance, credentials)
            self.assertIn("mask-aws-account-id: true", text)
            upload = next(
                step
                for step in workflow["jobs"]["validate"]["steps"]
                if str(step.get("uses", "")).startswith("actions/upload-artifact@")
            )
            self.assertEqual(set(upload["with"]["path"].splitlines()), expected_artifact_paths)

        for path in WORKFLOWS.glob("*.yml"):
            workflow = load_yaml(path)
            for job in workflow["jobs"].values():
                for step in job.get("steps", []):
                    if "uses" in step:
                        self.assertRegex(step["uses"], ACTION_SHA, f"unpinned action in {path.name}")


if __name__ == "__main__":
    unittest.main()
