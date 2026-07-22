# Zoolanding Data Spaces

Generic server-only storage for draft-configured collections and records. The service gives a draft bounded schema, protected administration, safe public projections, immutable revisions, and an exact internal snapshot read without turning Zoolandingpage into a central administration UI.

The service and its Phase 8 deployment-readiness controls are implemented locally. This repository contains no AWS `dev` environment, and no AWS deployment was performed or authorized by this implementation.

## Boundaries

- Each operation is scoped by published server policy to one `environment + tenantId + draftId + spaceId`.
- Browser requests cannot supply tenant IDs, draft IDs, table names, partition/sort keys, indexes, expressions, or AWS identifiers.
- Data Spaces is not authorized for secrets, credentials, payment/banking/identity/fiscal data, customer PII, or sensitive form submissions. Closed schema classes and value-pattern checks reject known unsafe inputs, executable expressions, arbitrary URLs, and untrusted HTML, but free text cannot be proven non-PII by regex; operator review and purpose-specific UI constraints remain mandatory. Data needing stronger guarantees belongs in a dedicated protected domain service.
- Commercial prices, inventory reservations, orders, subscriptions, provider mappings, and fiscal workflows belong to Commerce or Integrations, not Data Spaces. `money-display` is informational presentation only.
- Public reads expose only records explicitly published from fields classified `public`.

## Routes

All routes use `POST` and closed operation registries.

| Route | Exposure | Purpose |
| --- | --- | --- |
| `/features/data-spaces/read` | Auth Admin session | Collection/schema/record administration reads |
| `/features/data-spaces/action` | Auth Admin session + CSRF | Collection, record, publish, and unpublish mutations |
| `/features/data-spaces/public-read` | Public | Published record list/detail only |
| `/internal/v1/data-spaces/record-snapshot` | `AWS_IAM` | Exact immutable revision and field allowlist for a future owning service |

Protected reads are `collectionList`, `collectionSchema`, `recordList`, and `recordDetail`. Mutations are `createCollection`, `updateCollection`, `createRecord`, `updateRecord`, `publishRecord`, and `unpublishRecord`. Delete and arbitrary query operations are outside the MVP.

Every response uses the shared safe envelope. Successful calls return `ok`, `data`, and `requestId`; failures return only `ok`, a stable `code`, a safe `error`/`message`, `requestId`, and `retryable`. Provider, AWS, storage, policy, session, and exception details are never returned.

Capabilities are code-owned:

- `data-space:record:read`
- `data-space:record:write`
- `data-space:schema:write`
- `data-space:publish`

## Published Policy And Authorization

The service applies PAT-007. It reads the current Config Registry pointer on every resolution and derives the immutable package prefix. Protected handlers load `server/data-spaces.json` plus `server/auth-profile-registry.json` from the same version; public and internal snapshot handlers load only `server/data-spaces.json`. Only immutable descriptor bodies may be cached. Missing, disabled, oversized, malformed, duplicate-key, wrong-environment, wrong-tenant, wrong-draft, wrong-domain, or prefix-confusable policy fails closed.

Protected calls reuse Auth Admin's HttpOnly session, domain/profile headers, fresh session/user state, current `sessionVersion`, approved/enabled user status, configured `adminGroups`, code-owned capability gate, and CSRF for mutations. No draft-authored group-to-capability language is inferred.

The internal snapshot requires both API Gateway `AWS_IAM` and the exact configured Commerce caller role. An assumed-role session is normalized back to that role before any policy or record read. That role is deliberately a trusted multi-draft service principal; before deployment, its invoke policy and the Commerce-side draft/reference authorization must be reviewed together. Reassigning a domain to another draft also requires Auth Admin session revocation or a `sessionVersion` bump because the inherited session contract is domain/tenant/profile/environment-bound rather than draft-ID-bound.

## Storage

One PAY_PER_REQUEST DynamoDB table uses server-derived keys:

```text
PK = ENV#{environment}#TENANT#{tenantId}#DRAFT#{draftId}#SPACE#{spaceId}

SK = SPACE
   | SCHEMA#{collectionId}
   | SCHEMA_REV#{collectionId}#{revision}
   | RECORD#{collectionId}#{recordId}
   | RECORD_REV#{collectionId}#{recordId}#{revision}
   | PUBLIC#{collectionId}#{recordId}
   | IDEMPOTENCY#{action}#{requestHash}
   | AUDIT#{timestamp}#{requestId}
```

Mutations use conditional transactions, expected revisions, immutable revision items, compact redacted audit entries, and idempotency receipts. Only idempotency receipts receive the 90-day `expiresAt` TTL. Schemas, business records, published projections, revisions, and audit records do not inherit that TTL.

After a collection contains records, existing field definitions cannot be removed, retyped, or reclassified; schema evolution is additive. This prevents a stale `PUBLIC#` projection from retaining a field that was later changed from `public` to `internal`.

The internal snapshot response contains the resolved `spaceId`, collection and record IDs, exact record and schema revisions, the requested field allowlist under `values`, and a SHA-256 `contentHash` over that canonical response content. It never performs a current-record fallback or returns unrequested/internal storage fields.

## Schema Types

The closed field types are `string`, `integer`, `decimal`, `boolean`, `enum`, `object`, `array`, `date`, `money-display`, `asset-reference`, and `relation-id`. Fields are classified `public` or `internal`; schema depth and field count are descriptor-bounded.

## Local Verification

```powershell
python -m unittest discover -s tests -p "test_*.py"
python -m pip_audit -r requirements.txt
sam validate --lint
sam build --no-cached
python tools/verify_sam_build.py
actionlint
```

No command above deploys AWS. CI runs on every branch, while deployment remains limited to the protected `dev -> test -> main` promotion graph. Test and production workflows validate a clean two-parent promotion merge, build and hash the candidate without OIDC, reject symlinks, and give OIDC only to the dependent protected deployment job that downloads and rechecks that exact artifact. The anonymous public-read method has a native API Gateway throttle of 25 requests/second with a burst of 50; this is best-effort cost/abuse containment, not a quota or a replacement for monitoring.

The local build deliberately uses the Python Lambda runtime's AWS SDK and keeps the root `boto3` pin as the tested/audited development contract; SAM's closed `CodeUri: src/` artifact therefore contains only first-party source. Before any test or production deployment is authorized, release review must either confirm that runtime-SDK contract for the selected Lambda runtime or package an explicitly approved pinned SDK through an equally closed artifact workflow. The current local Phase 8 result does not claim that live gate is closed.

## Deployment Gates

Only the environment names `test` and `production` are accepted. The stack consumes the following non-secret identifiers through exact environment-scoped SSM parameter names:

- `/zoolanding/{environment}/config/registry-table-name`
- `/zoolanding/{environment}/config/payload-bucket-name`
- `/zoolanding/{environment}/auth/session-table-name`
- `/zoolanding/{environment}/auth/user-state-table-name`

After deployment, the stack publishes only its REST API identifier at `/zoolanding/{environment}/services/data-spaces/api-id`. It does not publish credentials, secrets, signed URLs, or raw provider/customer data.

The protected GitHub Environments must always provide `AWS_ROLE_ARN`, `AWS_CLOUDFORMATION_ROLE_ARN`, and `ALARM_TOPIC_ARN` from the owning infrastructure inventory, never from draft files. `INTERNAL_SNAPSHOT_CALLER_ROLE_ARN` may remain empty in later deployments as well as during initial bootstrap; an empty value is an explicit disabled state, so every request to the internal snapshot handler fails closed with 403 `forbidden` before policy resolution or storage access. The deploy job validates every non-empty value and reads the exact SSM dependencies after OIDC without printing their values. The Lambda roles can mutate only the Data Spaces table where required, can only read the inherited Config Registry/Auth tables and exact descriptor path patterns, cannot read Secrets Manager, and cannot mutate Auth Admin or Config Registry state.

The initial deployment leaves the internal snapshot route disabled and publishes the API ID without requiring a placeholder role. That route is not ready to enable until Commerce implements a dedicated caller, publishes its exact role ARN through the approved infrastructure inventory, and receives an `execute-api:Invoke` grant for only the exact API, stage, `POST` method, and internal snapshot route. After those prerequisites exist, configure the exact caller ARN as `INTERNAL_SNAPSHOT_CALLER_ROLE_ARN` in the protected GitHub Environment and redeploy before running cross-service smoke evidence. Until then, keep the value empty. Only a syntactically valid, exact role ARN enables the handler. Never use a wildcard API grant or a temporary placeholder ARN.

The stack alarms on API 5xx and p95 latency; errors, duration, and throttles for each of the four Lambdas; and a closed, PII-free `TestLiveMismatch` metric emitted when a valid published descriptor belongs to the other environment. Detailed API Gateway metrics are enabled only for the public-read method so its throttle has a method-scoped signal while limiting added CloudWatch cost. The method-scoped `4XXError` alarm combines 400, 403, and 429 responses, so it cannot prove that throttling occurred and does not replace controlled load evidence before release. Data Spaces has no queue or DynamoDB stream, so this stack does not invent queue/stream alarms.

The read-only smoke is `python tools/data_spaces_readiness_smoke.py`. It obtains AWS credentials only from the caller environment and requires `ZLP_DATA_SPACES_SMOKE_API_URL`, `ZLP_DATA_SPACES_SMOKE_DOMAIN`, `ZLP_DATA_SPACES_SMOKE_SPACE_ID`, `ZLP_DATA_SPACES_SMOKE_COLLECTION_ID`, `ZLP_DATA_SPACES_SMOKE_RECORD_ID`, `ZLP_DATA_SPACES_SMOKE_REVISION`, `ZLP_DATA_SPACES_SMOKE_FIELD_IDS`, and `AWS_REGION`. Its output is limited to readiness state, one of five failure classifications, HTTP status when present, and attempt count. It never prints a request, response, credential, domain, record identifier, or provider detail.

Before the first test deployment, the owner must also approve and verify API front-door routing versus the default execute-api endpoint, the Commerce role's exact `execute-api:Invoke` scope, redacted alarms/metrics, storage/write/revision quotas, the non-PII operating gate, domain-reassignment session revocation, and the runtime-SDK decision above. None of these gates is silently inferred from the local template.

No AWS deployment was performed by Phase 8 implementation or verification.
