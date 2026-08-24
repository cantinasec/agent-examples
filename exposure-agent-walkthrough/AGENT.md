# AGENT.md

Cloudflare Worker combining durable Workflows (`SweepWorkflow`, `TargetWorkflow`, `ExpireWorkflow`), a stateless MCP endpoint (`/mcp`), and a Durable Object agent (`TriageAgent`) to monitor external attack surfaces. Enforces strict scope decay in D1 and gates all outbound scans through a single `assertInScope` chokepoint.

## Most Critical Trap

Outbound probes and browser renderings **fail closed** if the hostname is not active and unexpired in the D1 `targets` table. Every network action calls `assertInScope(url, db)`. You cannot probe or scan a URL without first registering it via `add_target` or `put_targets`.

## Commands

- Typecheck: `npm run typecheck`
- Test suite: `npm test`
- Generate Worker types: `npm run cf-typegen`
- Apply remote D1 migrations: `npx wrangler d1 migrations apply exposure-agent-db --remote`
- Deploy Worker: `npx wrangler deploy`

## Invariants & Traps

- **Workflow instance IDs must be UUIDv4**: Passing formatted hostnames or timestamps to `env.TARGET_WORKFLOW.create({ id })` fails with `(instance.invalid_id)`. Always use `crypto.randomUUID()`.
- **Decayed scope enforcement**: Targets expire automatically after `expires_at` (default 7 days, max 30 days). Expired targets are treated as out-of-scope by `assertInScope` before `retireExpiredTargets` runs.
- **Hostname normalization**: `normalizeHost()` extracts the pure lowercase FQDN without ports or trailing dots. D1 records must always store normalized hostnames.
- **MCP authentication**: `/mcp` requires a verified Cloudflare Access assertion (`Cf-Access-Jwt-Assertion`). Human email or service-token `common_name` must match `client_id` in the D1 `principals` table.
- **MCP Host & Origin filtering**: Requests to `/mcp` must match `MCP_HOSTNAME` and `MCP_ORIGIN_HOSTNAME` configured in `wrangler.jsonc`. Mismatched hosts return `400 Bad Request: invalid MCP host`.
- **Deterministic findings diffing**: `syncDetectorFindings()` marks missing findings as `fixed` on subsequent scans and reopens fixed ones if rediscovered. Do not delete findings rows directly.
- **Read-only probes**: Probers and detectors must only issue GET/HEAD requests with manual redirect handling; never execute mutating payloads or fuzzing loops.
- **Evidence redaction happens at capture**: `step.do` results persist durably, so `probe-root` and `probe-paths` apply `redactHeaders` and (for `CREDENTIAL_PATHS`) `redactBodyValues` before returning. Never move this masking downstream into a detector, and never store `Object.fromEntries(resp.headers)` raw.
- **Workers AI advisory fallback**: In `TargetWorkflow`, `@cf/meta/llama-3.3-70b-instruct-fp8-fast` evaluates rendered markdown only when HTTP 200 returns application content with no deterministic matches. AI failures must not abort scan persistence.
- **Browser Run error handling**: `BROWSER.quickAction()` requires `"remote": true` in `wrangler.jsonc`. If browser rendering fails or is unavailable, `TargetWorkflow` falls back to raw HTTP evidence.

## Pointers

- Cloudflare product → job → principal role: `README.md` (table under **What you will build**)
- Database schema & tables: `migrations/0001_init.sql`, `migrations/0002_hardening.sql`
- MCP tools & role permissions (`read`, `scan`, `admin`): `src/mcp/tools.ts`, `src/auth/principals.ts`
- Scan workflow steps & AI classification: `src/workflows/target.ts`
- Deterministic detector rules: `src/detectors/`
- Test shims & fixtures: `test/cloudflare-workers-shim.ts`, `test/fixtures/`
