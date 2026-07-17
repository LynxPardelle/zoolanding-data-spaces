# Zoolanding Data Spaces Agent Workflow

## Read Before Editing

1. Start with [README.md](README.md) for the service contract, limits, and verification commands.
2. Use the Zoolandingpage hub documents `docs/api-driven-config/22-server-only-integration-microservices.md` and `plan/infrastructure-server-only-integrations-1.md` as the canonical cross-repository design.
3. Verify the current branch, worktree, and repository status before editing or releasing.

## Safety And Scope

- This service is generic per draft. Do not add Zoosite-, Stripe-, product-, blog-, or customer-specific behavior to its core.
- Never store secrets, credentials, tokens, banking data, identity documents, fiscal data, payment data, customer PII, raw session cookies, or signed URLs in schemas, records, logs, fixtures, docs, or source control.
- Tenant, draft, environment, table, partition key, sort key, index, and DynamoDB expressions are server-derived. Browser input never selects them.
- `dev` is local/CI only. Do not create a dev stack, deploy workflow, SAM profile, GitHub deployment Environment, or AWS resource.
- Do not deploy or mutate AWS while Phase 2 remains local-only.
- Keep handlers separated where public exposure, IAM, authorization, or failure blast radius differs.
- Add no dependency without a documented need and a dependency audit.

## Delivery

- Work test-first and preserve fail-closed behavior.
- Before declaring a change correct, audit, fix, and rerun the audit at least three times.
- Promote only through `dev -> test -> main`; never push implementation directly to a protected release branch.
- Keep timestamps in Central Time and never write sensitive runtime values to evidence.
