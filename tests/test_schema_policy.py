import unittest

from src.domain.records import public_projection
from src.domain.schema_policy import SchemaPolicyError, validate_record, validate_schema


def valid_schema():
    return {
        "fields": [
            {
                "id": "title",
                "type": "string",
                "classification": "public",
                "required": True,
                "maxLength": 80,
            },
            {
                "id": "count",
                "type": "integer",
                "classification": "internal",
                "minimum": 0,
                "maximum": 100,
            },
            {
                "id": "ratio",
                "type": "decimal",
                "classification": "internal",
            },
            {"id": "active", "type": "boolean", "classification": "public"},
            {
                "id": "category",
                "type": "enum",
                "classification": "public",
                "values": ["news", "guide"],
            },
            {
                "id": "details",
                "type": "object",
                "classification": "public",
                "fields": [
                    {
                        "id": "summary",
                        "type": "string",
                        "classification": "public",
                        "maxLength": 200,
                    },
                    {
                        "id": "editorNote",
                        "type": "string",
                        "classification": "internal",
                    },
                ],
            },
            {
                "id": "tags",
                "type": "array",
                "classification": "public",
                "maxItems": 10,
                "items": {"type": "string", "maxLength": 40},
            },
            {"id": "publishedOn", "type": "date", "classification": "public"},
            {
                "id": "displayPrice",
                "type": "money-display",
                "classification": "public",
                "presentationOnly": True,
            },
            {"id": "heroAsset", "type": "asset-reference", "classification": "public"},
            {"id": "relatedRecord", "type": "relation-id", "classification": "internal"},
        ]
    }


class SchemaPolicyTests(unittest.TestCase):
    def test_accepts_closed_supported_types_and_returns_a_copy(self):
        source = valid_schema()

        result = validate_schema(source, max_fields=20)

        self.assertEqual(result, source)
        self.assertIsNot(result, source)
        self.assertIsNot(result["fields"], source["fields"])

    def test_rejects_unknown_type_classification_and_properties(self):
        cases = [
            {"fields": [{"id": "x", "type": "url", "classification": "public"}]},
            {"fields": [{"id": "x", "type": "string", "classification": "restricted"}]},
            {
                "fields": [
                    {
                        "id": "x",
                        "type": "string",
                        "classification": "public",
                        "regex": ".*",
                    }
                ]
            },
        ]

        for schema in cases:
            with self.subTest(schema=schema), self.assertRaises(SchemaPolicyError):
                validate_schema(schema, max_fields=10)

    def test_rejects_restricted_and_database_field_names(self):
        names = [
            "password",
            "customerEmail",
            "cardNumber",
            "bankAccount",
            "rfc",
            "identityDocument",
            "tableName",
            "conditionExpression",
            "priceInCents",
            "personalData",
            "dateOfBirth",
            "birthday",
            "ipAddress",
            "razonSocial",
        ]

        for name in names:
            schema = {"fields": [{"id": name, "type": "string", "classification": "internal"}]}
            with self.subTest(name=name), self.assertRaises(SchemaPolicyError):
                validate_schema(schema, max_fields=10)

    def test_rejects_provider_mapping_resource_and_infrastructure_field_ids(self):
        names = [
            "providerAccountId",
            "connectedAccount",
            "stripeAccount",
            "providerId",
            "externalAccount",
            "externalResourceId",
            "stripeCustomerId",
            "resourceArn",
            "ssmParameter",
            "parameterStoreRef",
            "secretsManagerRef",
        ]

        for name in names:
            schema = {"fields": [{"id": name, "type": "string", "classification": "internal"}]}
            with self.subTest(name=name), self.assertRaisesRegex(
                SchemaPolicyError,
                "provider or infrastructure field is not allowed",
            ):
                validate_schema(schema, max_fields=10)

    def test_keeps_innocuous_generic_field_ids_available(self):
        names = ["provider", "domain", "environment", "access", "role", "policy", "groups", "account"]
        schema = {
            "fields": [
                {"id": name, "type": "string", "classification": "internal"}
                for name in names
            ]
        }

        checked = validate_schema(schema, max_fields=10)

        self.assertEqual([field["id"] for field in checked["fields"]], names)

    def test_rejects_case_confusable_duplicate_field_ids(self):
        schema = {
            "fields": [
                {"id": "title", "type": "string", "classification": "public"},
                {"id": "Title", "type": "string", "classification": "internal"},
            ]
        }

        with self.assertRaises(SchemaPolicyError):
            validate_schema(schema, max_fields=10)

    def test_money_display_must_be_explicitly_non_authoritative(self):
        schema = {
            "fields": [
                {"id": "displayPrice", "type": "money-display", "classification": "public"}
            ]
        }

        with self.assertRaises(SchemaPolicyError):
            validate_schema(schema, max_fields=10)

    def test_enforces_total_field_count_and_depth_four(self):
        with self.assertRaises(SchemaPolicyError):
            validate_schema(valid_schema(), max_fields=5)

        too_deep = {
            "fields": [
                {
                    "id": "a",
                    "type": "object",
                    "classification": "public",
                    "fields": [
                        {
                            "id": "b",
                            "type": "object",
                            "classification": "public",
                            "fields": [
                                {
                                    "id": "c",
                                    "type": "object",
                                    "classification": "public",
                                    "fields": [
                                        {
                                            "id": "d",
                                            "type": "object",
                                            "classification": "public",
                                            "fields": [
                                                {
                                                    "id": "e",
                                                    "type": "string",
                                                    "classification": "public",
                                                }
                                            ],
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        with self.assertRaises(SchemaPolicyError):
            validate_schema(too_deep, max_fields=20)

    def test_rejects_recursive_python_schema(self):
        recursive = {"fields": []}
        field = {"id": "loop", "type": "object", "classification": "public"}
        field["fields"] = recursive["fields"]
        recursive["fields"].append(field)

        with self.assertRaises(SchemaPolicyError):
            validate_schema(recursive, max_fields=20)

    def test_validates_records_and_projects_only_public_fields_recursively(self):
        schema = validate_schema(valid_schema(), max_fields=20)
        values = {
            "title": "A safe guide",
            "count": 3,
            "ratio": 1.25,
            "active": True,
            "category": "guide",
            "details": {"summary": "Short", "editorNote": "Review later"},
            "tags": ["aws", "landing"],
            "publishedOn": "2026-07-16",
            "displayPrice": {"amountMinor": 90000, "currency": "MXN"},
            "heroAsset": "asset.hero-1",
            "relatedRecord": "record.related-1",
        }

        checked = validate_record(schema, values, max_record_bytes=10_000)

        self.assertEqual(checked, values)
        self.assertEqual(
            public_projection(schema, checked),
            {
                "title": "A safe guide",
                "active": True,
                "category": "guide",
                "details": {"summary": "Short"},
                "tags": ["aws", "landing"],
                "publishedOn": "2026-07-16",
                "displayPrice": {"amountMinor": 90000, "currency": "MXN"},
                "heroAsset": "asset.hero-1",
            },
        )

    def test_rejects_missing_unknown_mistyped_and_oversized_record_values(self):
        schema = validate_schema(valid_schema(), max_fields=20)
        cases = [
            {},
            {"title": "ok", "unknown": "value"},
            {"title": "ok", "count": True},
            {"title": "ok", "category": "other"},
            {"title": "x" * 81},
        ]

        for values in cases:
            with self.subTest(values=values), self.assertRaises(SchemaPolicyError):
                validate_record(schema, values, max_record_bytes=10_000)

        with self.assertRaises(SchemaPolicyError):
            validate_record(schema, {"title": "bounded"}, max_record_bytes=10)

    def test_rejects_urls_html_executable_content_and_restricted_values(self):
        schema = validate_schema(valid_schema(), max_fields=20)
        unsafe_values = [
            "https://attacker.invalid/x",
            "ftp://attacker.invalid/x",
            "data:text/html,boom",
            "<script>alert(1)</script>",
            "=IMPORTXML(A1)",
            "+SUM(A1:A2)",
            "@SUM(A1:A2)",
            "-HYPERLINK(A1)",
            "person@example.com",
            "4242424242424242",
            "ABCD010101ABC",
            "gh" + "p_" + "A" * 36,
            "github" + "_pat_" + "A" * 30,
            "smtpPassword=synthetic-value",
        ]

        for value in unsafe_values:
            with self.subTest(value=value), self.assertRaises(SchemaPolicyError):
                validate_record(schema, {"title": value}, max_record_bytes=10_000)

    def test_rejects_provider_resource_ids_and_infrastructure_references_as_values(self):
        schema = validate_schema(valid_schema(), max_fields=20)
        unsafe_values = [
            "acct_1SyntheticAccount",
            "cus_1SyntheticCustomer",
            "sub_1SyntheticSubscription",
            "price_1SyntheticPrice",
            "prod_1SyntheticProduct",
            "pm_1SyntheticMethod",
            "pi_1SyntheticIntent",
            "cs_1SyntheticSession",
            "cs_test_1SyntheticSession",
            "in_1SyntheticInvoice",
            "evt_1SyntheticEvent",
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:synthetic",
            "ssm:/zoolanding/test/services/data-spaces/api-id",
            "secretsmanager:/zoolanding/test/tenant/draft/notifications/smtp/example",
            "/zoolanding/test/services/data-spaces/api-id",
            "{{resolve:ssm:/zoolanding/test/services/data-spaces/api-id}}",
            "{{resolve:secretsmanager:/synthetic}}",
        ]

        for value in unsafe_values:
            with self.subTest(value=value), self.assertRaisesRegex(
                SchemaPolicyError,
                "provider or infrastructure reference is not allowed",
            ):
                validate_record(schema, {"title": value}, max_record_bytes=10_000)

        for field_id in ("heroAsset", "relatedRecord"):
            with self.subTest(field_id=field_id), self.assertRaisesRegex(
                SchemaPolicyError,
                "provider or infrastructure reference is not allowed",
            ):
                validate_record(
                    schema,
                    {"title": "safe", field_id: "acct_1syntheticaccount"},
                    max_record_bytes=10_000,
                )

    def test_plain_generic_in_progress_value_is_not_treated_as_a_stripe_invoice_id(self):
        schema = validate_schema(valid_schema(), max_fields=20)

        checked = validate_record(schema, {"title": "in_progress"}, max_record_bytes=10_000)

        self.assertEqual(checked["title"], "in_progress")

    def test_short_editorial_tokens_are_not_treated_as_provider_resource_ids(self):
        schema = validate_schema(valid_schema(), max_fields=20)

        for value in ("sub_heading", "price_medium", "prod_gallery", "evt_summary"):
            with self.subTest(value=value):
                checked = validate_record(schema, {"title": value}, max_record_bytes=10_000)
                self.assertEqual(checked["title"], value)

    def test_plain_text_starting_with_set_is_not_mistaken_for_a_database_expression(self):
        schema = validate_schema(valid_schema(), max_fields=20)

        record = validate_record(schema, {"title": "Set goals for launch"}, max_record_bytes=10_000)

        self.assertEqual(record["title"], "Set goals for launch")

    def test_rejects_numbers_outside_dynamodb_precision_and_exponent_bounds(self):
        integer_schema = {
            "fields": [{"id": "count", "type": "integer", "classification": "internal"}]
        }
        decimal_schema = {
            "fields": [{"id": "ratio", "type": "decimal", "classification": "internal"}]
        }

        with self.assertRaises(SchemaPolicyError):
            validate_schema(
                {"fields": [{"id": "count", "type": "integer", "classification": "internal", "maximum": 10**40}]},
                max_fields=10,
            )
        with self.assertRaises(SchemaPolicyError):
            validate_record(validate_schema(integer_schema, 10), {"count": 10**40})
        with self.assertRaises(SchemaPolicyError):
            validate_record(validate_schema(integer_schema, 10), {"count": 10**400})
        with self.assertRaises(SchemaPolicyError):
            validate_record(validate_schema(decimal_schema, 10), {"ratio": 1e200})

    def test_money_display_and_relation_id_have_closed_non_authoritative_values(self):
        schema = validate_schema(valid_schema(), max_fields=20)

        with self.assertRaises(SchemaPolicyError):
            validate_record(
                schema,
                {"title": "x", "displayPrice": {"amountMinor": 90000, "currency": "MXN", "tax": 0}},
                max_record_bytes=10_000,
            )
        with self.assertRaises(SchemaPolicyError):
            validate_record(
                schema,
                {"title": "x", "displayPrice": {"amountMinor": 900.5, "currency": "MXN"}},
                max_record_bytes=10_000,
            )
        with self.assertRaises(SchemaPolicyError):
            validate_record(
                schema,
                {"title": "x", "relatedRecord": "other-space/record"},
                max_record_bytes=10_000,
            )


if __name__ == "__main__":
    unittest.main()
