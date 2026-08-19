# Build a security exposure agent on Cloudflare

This tutorial builds a read-only agent that scans an explicitly approved set of public hosts, records exposure findings in D1, stores screenshots in R2, and exposes the result through an Access-protected MCP server. You will also connect that MCP server to an existing ticketing or security-operations workflow without putting vendor-specific connectors in the Worker.

The repository contains the finished implementation. Follow the source in the order below if you want to build it yourself; skip to [Deploy your copy](#deploy-your-copy) if you only want to run it.

Last locally verified: 2026-08-19 with Node.js 22 and the dependency versions in `package-lock.json`. Cloudflare deployment requires account-specific resources and cannot be verified by this repository's automated tests.

## What you will build

```text
scheduled trigger
      │
      ▼
SweepWorkflow ──► TargetWorkflow ──► deterministic detectors
                         │                    │
                         ├── D1 targets       ├── D1 findings
                         └── R2 screenshots   └── optional Workers AI review

Cloudflare Access ──► /mcp ──► list, scan, evidence, and triage tools
```

Roles live in D1 `principals` (`read` < `scan` < `admin`). A higher role includes the lower ones. Cloudflare Access authenticates the caller; the Worker then maps that identity onto one of these roles before any tool runs.

| Cloudflare product | Binding | Job | Principal role |
| --- | --- | --- | --- |
| Workers | `cloudflare-security-agent-walkthrough` | Serves `/health`, `/mcp`, `/agents/*`. Cron `0 3 * * *` starts expire then sweep. | Any Access identity that also exists in `principals` |
| D1 | `DB` → `exposure-agent-db` | `targets`, `principals`, `findings`, `scans` | `read` lists; `scan` inserts scan rows; `admin` mutates scope and finding disposition |
| R2 | `EVIDENCE` → `exposure-agent-evidence` | Screenshot blobs under `screenshots/{host}/…` | `read` via `get_evidence`; object writes happen inside `TargetWorkflow` |
| Workflows | `SWEEP_WORKFLOW`, `TARGET_WORKFLOW`, `EXPIRE_WORKFLOW` | Nightly fan-out, one durable scan per host, retire expired scope | `scan` starts and polls `TargetWorkflow`; cron starts sweep and expire |
| Durable Objects | `TRIAGE_AGENT` | Interactive triage agent | Same `read` / `scan` / `admin` checks as MCP |
| Workers AI | `AI` | `@cf/meta/llama-3.3-70b-instruct-fp8-fast` advisory review when detectors return nothing | Invoked only from `TargetWorkflow` (`scan` or cron). Not an MCP tool. |
| Browser Run | `BROWSER` (`remote: true`) | `quickAction` content, markdown, and screenshot | `TargetWorkflow` (`scan` or cron); TriageAgent browse (`read`) |
| Access | `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD` | Verifies `Cf-Access-Jwt-Assertion` on `/mcp` and `/agents/*` | Required for every role. Email or service-token `common_name` must match `principals.client_id`. |

D1 and R2 are not in the checked-in `wrangler.jsonc`. The deploy steps below create `exposure-agent-db` and `exposure-agent-evidence` and write those bindings.

The safety boundary is the D1 target registry. Every scan starts by checking that the exact hostname is active and its authorization has not expired. Probes use GET requests and manual HTTP redirects; the agent does not submit forms, guess credentials, fuzz inputs, or send exploit payloads.

## Before you start

You need:

- Node.js 22.
- A Cloudflare account that can create Workers, Workflows, D1 databases, R2 buckets, Browser Run bindings, Workers AI bindings, and Access applications. The Workers Free plan covers every binding this Worker uses. R2 requires completing the R2 subscription flow, which includes free monthly usage. On the Workers Free plan, Browser Run allows 10 minutes of browser time per day, which is the practical cap on how many hosts one nightly sweep can render.
- An active Cloudflare zone in that account for the custom hostname protecting `/mcp` with Cloudflare Access. `workers_dev` is `false`, so there is no `workers.dev` fallback hostname.
- Written authorization for every hostname you add to the target registry.

Install the locked dependencies and run the local checks:

```bash
npm ci
npm test
npm run typecheck
```

Verify: both commands exit with status `0`. Do not continue with a deployment if either fails.

## Build it in six passes

Each pass leaves one independently testable part of the agent. The final repository contains all six; the sequence is the useful part when recreating it in another Worker.

### 1. Make authorization part of the data model

Start with `migrations/0001_init.sql` and `src/core/scope.ts`.

The `targets` table stores the principal that added a host, an external authorization reference, and an expiry. `normalizeHost` converts URLs and hostnames to the same exact lowercase key. `assertInScope` is the only function a network-capable module should call before touching a target.

Keep hostname matching exact. Treating `example.com.evil.net` as a child of `example.com` would turn the scope registry into an SSRF primitive.

```bash
npm test -- test/scope.test.ts
```

Verify: the suite accepts active hosts and rejects missing, lookalike, retired, and expired hosts.

### 2. Keep detectors pure

`src/detectors/` receives bounded HTTP, browser, DNS, and path-probe evidence. Detectors return finding values; they do not fetch URLs or write to storage.

That separation makes the security rules testable with static fixtures and keeps all outbound traffic in one workflow. Add a detector only after adding a fixture that distinguishes the exposure from its authenticated or intentionally public equivalent.

```bash
npm test -- test/detectors.test.ts
```

Verify: each fixture produces the expected detector and authenticated/login fixtures produce no exposure finding.

### 3. Give findings a stable lifecycle

`src/core/findings.ts` derives a stable ID from the host, detector, and title. Repeated scans update the same row instead of opening duplicate incidents. A clean scan can move an open finding to `fixed`; rediscovery reopens it.

`accepted_risk` and `false_positive` remain analyst decisions. A network error must fail the scan rather than masquerade as a clean result, which is why `TargetWorkflow` does not swallow failed path probes.

```bash
npm test -- test/findings.test.ts
```

Verify: repeated observations preserve the ID, missing observations resolve open findings, and rediscovery reopens fixed findings.

### 4. Orchestrate network work with Cloudflare Workflows

`src/workflows/target.ts` runs one durable scan:

1. Recheck scope.
2. Resolve DNS through Cloudflare DNS-over-HTTPS.
3. Probe the root with manual redirects.
4. Render eligible 2xx pages with Browser Run.
5. Probe the fixed artifact paths.
6. Run deterministic detectors and optional Workers AI review.
7. Persist the finding diff and scan status.

`src/workflows/sweep.ts` fans active targets into independent target workflows. `src/workflows/expire.ts` retires expired scope entries.

```bash
npm test -- test/doh.test.ts test/workflows.test.ts
```

Verify: the target workflow persists a finding and the sweep creates one workflow request per active target.

### 5. Put identity and least privilege in front of tools

`src/auth/access-jwt.ts` verifies the assertion Cloudflare Access adds after an Allow or Service Auth policy succeeds. The JWT issuer, audience, signature, and expiry are checked before `src/auth/principals.ts` maps the identity to `read`, `scan`, or `admin`.

Do not accept an Access client ID by itself as a Bearer token. A service token is a client ID and client secret presented to Cloudflare Access; the Worker trusts the resulting signed assertion.

`src/mcp/tools.ts` exposes the operational boundary:

| Tool | Minimum role | Use |
| --- | --- | --- |
| `list_targets` | read | Inspect approved scope and expiry |
| `list_findings` | read | Export findings into a security workflow |
| `get_finding` | read | Read one finding and its evidence metadata |
| `get_evidence` | read | Retrieve a stored R2 evidence object |
| `browse_target` | read | Perform a bounded HTTP inspection |
| `scan_target` | scan | Launch a target workflow |
| `get_scan_status` | scan | Poll a scan |
| `put_targets` | admin | Replace the approved target set |
| `add_target` | admin | Add or renew one target |
| `remove_target` | admin | Retire one target |
| `triage_finding` | admin | Record analyst disposition |

```bash
npm test -- test/auth.test.ts test/mcp.test.ts
```

Verify: invalid assertions fail, registered identities receive their role, and a read-only principal cannot change scope.

### 6. Route HTTP and scheduled work

`src/index.ts` contains only the Worker entry points: health, MCP, Durable Object agent routing, and the scheduled trigger. The cron in `wrangler.jsonc` starts expiry and sweep workflows at `03:00 UTC` each day.

```bash
npm run typecheck
```

Verify: TypeScript reports no errors.

## Deploy your copy

The checked-in `wrangler.jsonc` contains visible placeholders. Replace them; do not deploy the example domain or database ID.

### 1. Choose the custom hostname

Replace `security-agent.example.com` in `routes`, `MCP_HOSTNAME`, and `MCP_ORIGIN_HOSTNAME` with the same hostname in your Cloudflare zone.

Verify:

```bash
rg "security-agent\.example\.com" wrangler.jsonc
```

Expected result after editing: no output.

### 2. Create and bind D1

Authenticate Wrangler, then create the database and let Wrangler add the `DB` binding:

```bash
npx wrangler login
npx wrangler d1 create exposure-agent-db --binding DB --update-config
```

Verify:

```bash
rg -n '"binding": "DB"|"database_name": "exposure-agent-db"' wrangler.jsonc
```

Expected result: both generated D1 binding lines appear. Keep the binding name `DB`; the source uses `env.DB`.

### 3. Create R2

```bash
npx wrangler r2 bucket create exposure-agent-evidence --binding EVIDENCE --update-config
npx wrangler r2 bucket list
```

Verify: the list includes `exposure-agent-evidence`, matching the `EVIDENCE` binding in `wrangler.jsonc`.

Regenerate the Worker environment types after both bindings exist. Running `cf-typegen` before the `DB` and `EVIDENCE` bindings are in `wrangler.jsonc` overwrites the checked-in `worker-configuration.d.ts` with a version that omits them, and `npm run typecheck` then fails on every `env.DB` reference:

```bash
npm run cf-typegen
npm run typecheck
```

Verify: both commands exit with status `0`.

### 4. Configure Cloudflare Access

In Cloudflare Zero Trust:

1. Open **Access controls → Applications** and add a self-hosted application for your custom hostname.
2. Add an Allow policy for human operators.
3. Create a service token for automation, save its Client ID and Client Secret, and add a Service Auth policy selecting that token.
4. Copy the application's Audience (AUD) tag and replace `replace-with-your-access-aud-tag` in `wrangler.jsonc`.
5. Replace `your-team.cloudflareaccess.com` with your Access team domain.

Verify:

```bash
rg "replace-with|your-team" wrangler.jsonc
```

Expected result: no output.

### 5. Apply the schema

```bash
npx wrangler d1 migrations apply exposure-agent-db --remote
npx wrangler d1 execute exposure-agent-db --remote --command="SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name"
```

Verify: the output includes `findings`, `principals`, `scans`, `settings`, and `targets`.

### 6. Bootstrap the first administrator

The application fails closed: an Access identity must also exist in `principals`. For a human Allow policy, use the email claim from the Access JWT. For a service token, use its Client ID (`common_name`).

Replace the two angle-bracket values before running:

```bash
npx wrangler d1 execute exposure-agent-db --remote --command="INSERT INTO principals (client_id, name, role, created_at) VALUES ('<YOUR_ACCESS_EMAIL>', '<YOUR_NAME>', 'admin', unixepoch() * 1000)"
```

Verify:

```bash
npx wrangler d1 execute exposure-agent-db --remote --command="SELECT client_id, name, role FROM principals"
```

Expected result: your exact Access identity appears with role `admin`. If authenticated requests still return `403`, decode the Access assertion locally and compare its `email` or `common_name` claim with this row; do not weaken authentication.

### 7. Deploy and verify health

```bash
npx wrangler deploy
curl --header "CF-Access-Client-Id: <CLIENT_ID>" \
  --header "CF-Access-Client-Secret: <CLIENT_SECRET>" \
  https://<YOUR_SECURITY_AGENT_HOST>/health
```

Expected response shape:

```json
{"status":"ok","service":"exposure-agent","timestamp":0}
```

The timestamp will be the current Unix time in milliseconds.

## Add the first authorized target

Connect an MCP client to `https://<YOUR_SECURITY_AGENT_HOST>/mcp`. For unattended clients, create a Cloudflare Access service token and configure the client to send both headers:

```text
CF-Access-Client-Id: <CLIENT_ID>
CF-Access-Client-Secret: <CLIENT_SECRET>
```

Insert the service token's Client ID into `principals` with the least role it needs. Use `scan` for automation that reads and starts scans; reserve `admin` for scope and triage changes.

Call `add_target` with a host you own or are explicitly authorized to test:

```json
{
  "host": "staging.example.com",
  "authorization_ref": "SEC-1234",
  "expiryDays": 7,
  "notes": "Owned staging service"
}
```

Verify: `list_targets` returns the normalized host, authorization reference, and a future `expires_at` value. Then call `scan_target`, poll `get_scan_status`, and inspect any result with `get_finding`.

## Connect it to an existing security workflow

Use MCP as the integration boundary. Keep ticketing, chat, and SIEM credentials out of this Worker.

Run this loop from an existing security automation or an MCP-capable agent:

1. Call `list_findings` with `state: "open"` and the last successful poll timestamp in `since`.
2. Use `finding.id` as the external system's deduplication key.
3. Map `critical` and `high` to your urgent queue; map lower severities to the normal exposure-management queue.
4. Put `title`, `description`, `target_host`, `first_seen_at`, and the authorization reference from `list_targets` into the ticket. Fetch full evidence only when an analyst needs it.
5. Store the external ticket ID in that system, keyed by `finding.id`. The current schema deliberately does not own vendor ticket state.
6. After remediation, call `scan_target`. Close the external ticket only after the finding state becomes `fixed` on a completed scan.
7. Use a separate admin identity for `accepted_risk` or `false_positive` decisions through `triage_finding`.

The important contract is state, not vendor API shape:

```text
open ──clean completed scan──► fixed
  │
  ├──analyst decision────────► accepted_risk
  └──analyst decision────────► false_positive
```

Do not close tickets from failed scans. `get_scan_status` must report `completed` before absence is treated as remediation.

## Limits you should preserve or address

- Scope is hostname-based. Browser Run can load subresources or client-side navigations outside that hostname; use deterministic manual-redirect probes for enforcement-sensitive checks.
- Artifact probing uses a fixed path list. The source-map detector only works when a `.map` response is supplied; this workflow does not discover source-map URLs.
- Workers AI is advisory. Deterministic findings and scan persistence must not depend on model availability.
- R2 evidence has no retention policy in this repository. Configure one appropriate to your incident-response and privacy requirements before production use.
- This agent finds a bounded class of accidental web exposure. It is not a vulnerability scanner or authorization to test third-party systems.

## Cleanup

These commands delete the deployed resources and their data. Run them only for the tutorial resources you created:

```bash
npx wrangler delete cloudflare-security-agent-walkthrough
npx wrangler d1 delete exposure-agent-db
npx wrangler r2 bucket delete exposure-agent-evidence
```

R2 bucket deletion fails while objects remain. Remove the tutorial evidence first, then retry. Delete the self-hosted Access application from **Access controls → Applications** after the Worker is gone.
