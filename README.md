# Zoolanding Data Spaces

Generic server-only storage for draft-configured collections and records. The service gives a draft bounded schema, protected administration, safe public projections, immutable revisions, and an exact internal snapshot read without turning Zoolandingpage into a central administration UI.

Phase 2 is local-only. This repository contains no AWS `dev` environment and its existence does not authorize a test or production deployment.

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
actionlint
```

No command above deploys AWS. Deployment still requires a protected `dev -> test -> main` promotion, explicit authorization, exact environment identities (including the internal Commerce caller role), infrastructure routing, alarms, storage/write quotas, and cross-service smoke evidence in later phases. The anonymous public-read method has a native API Gateway throttle of 25 requests/second with a burst of 50; this is best-effort cost/abuse containment, not a quota or a replacement for monitoring.

The local build deliberately uses the Python Lambda runtime's AWS SDK and keeps the root `boto3` pin as the tested/audited development contract; SAM's closed `CodeUri: src/` artifact therefore contains only first-party source. Before any test or production deployment is authorized, release review must either confirm that runtime-SDK contract for the selected Lambda runtime or package an explicitly approved pinned SDK through an equally closed artifact workflow. The current local Phase 2 result does not claim that live gate is closed.

## Deployment Gates

The protected GitHub Environments must obtain these values from the owning infrastructure inventory, never from draft files: `AWS_ROLE_ARN`, `AWS_CLOUDFORMATION_ROLE_ARN`, `CONFIG_REGISTRY_TABLE_NAME`, `CONFIG_PAYLOADS_BUCKET_NAME`, `AUTH_SESSION_TABLE_NAME`, `AUTH_USER_STATE_TABLE_NAME`, and `INTERNAL_SNAPSHOT_CALLER_ROLE_ARN`. Both workflows validate their shape before OIDC and pass them explicitly to SAM; no default/dev value exists.

Before the first test deployment, the owner must also approve and verify API front-door routing versus the default execute-api endpoint, the Commerce role's exact `execute-api:Invoke` scope, redacted alarms/metrics, storage/write/revision quotas, the non-PII operating gate, domain-reassignment session revocation, and the runtime-SDK decision above. None of these gates is silently inferred from the local template.
