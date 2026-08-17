// ponytail: register MCP tools with direct D1/assertInScope calls

import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { assertInScope, listTargets, putTargets, addTarget, removeTarget, normalizeHost } from "../core/scope.js";
import { listFindings, getFinding, triageFinding, FindingState } from "../core/findings.js";
import { requirePerm, Role } from "../auth/principals.js";
import { getEvidenceBlob } from "../core/evidence.js";

export interface ToolContext {
  env: Env;
  clientId: string;
}

/**
 * Register all MCP tools on the provided server, wrapping each with
 * permission enforcement based on the caller's role.
 */
export function registerAllTools(server: McpServer, ctx: ToolContext): void {
  const { env, clientId } = ctx;
  const defaultExpiry = parseInt(env.DEFAULT_TARGET_EXPIRY_DAYS || "7", 10);
  const maxExpiry = parseInt(env.MAX_TARGET_EXPIRY_DAYS || "30", 10);

  const withPerm = (role: Role, fn: (args: any) => Promise<any>) => {
    return async (args: any) => {
      try {
        await requirePerm(env.DB, clientId, role);
        const result = await fn(args);
        return {
          content: [
            {
              type: "text" as const,
              text: typeof result === "string" ? result : JSON.stringify(result, null, 2),
            },
          ],
        };
      } catch (err: any) {
        return {
          isError: true,
          content: [
            {
              type: "text" as const,
              text: `Error: ${err.message || String(err)}`,
            },
          ],
        };
      }
    };
  };

  server.registerTool(
    "list_targets",
    {
      title: "List Scope Targets",
      description: "List all target assets registered in scope with their attestation metadata and expiry",
      inputSchema: z.object({
        status: z.enum(["active", "retired"]).optional().describe("Filter by status"),
        includeExpired: z.boolean().optional().describe("Whether to include expired targets"),
      }),
    },
    withPerm("read", async (args) => {
      return await listTargets(env.DB, args);
    })
  );

  server.registerTool(
    "list_findings",
    {
      title: "List Findings",
      description: "List exposure findings filtered by host, detector, severity, state, or timestamp",
      inputSchema: z.object({
        host: z.string().optional().describe("Filter by target hostname"),
        detector: z.string().optional().describe("Filter by detector name (unauth-admin, no-auth-gate, leaked-artifact, dev-staging-origin)"),
        severity: z.enum(["critical", "high", "medium", "low", "info"]).optional().describe("Filter by severity"),
        state: z.enum(["open", "fixed", "accepted_risk", "false_positive"]).optional().describe("Filter by state"),
        since: z.number().optional().describe("Timestamp in ms to filter findings last seen since"),
      }),
    },
    withPerm("read", async (args) => {
      return await listFindings(env.DB, args as any);
    })
  );

  server.registerTool(
    "get_finding",
    {
      title: "Get Finding Detail",
      description: "Get full details, evidence, and screenshot keys for a specific finding",
      inputSchema: z.object({
        id: z.string().describe("Finding ID (e.g. host:detector:slug)"),
      }),
    },
    withPerm("read", async (args) => {
      const finding = await getFinding(env.DB, args.id);
      if (!finding) {
        throw new Error(`Finding '${args.id}' not found`);
      }
      return finding;
    })
  );

  server.registerTool(
    "get_evidence",
    {
      title: "Get Evidence",
      description: "Read a stored evidence object for a finding",
      inputSchema: z.object({ key: z.string().min(1).max(300) }),
    },
    withPerm("read", async ({ key }) => {
      if (key.includes("..") || key.startsWith("/")) throw new Error("Invalid evidence key");
      const object = await getEvidenceBlob(env.EVIDENCE, key);
      if (!object) throw new Error("Evidence not found");
      return { key, contentType: object.httpMetadata?.contentType || "application/octet-stream", body: await object.text() };
    })
  );

  server.registerTool(
    "browse_target",
    {
      title: "Browse Target Asset",
      description: "One-shot render and inspect an in-scope URL using Browser Run or HTTP probe",
      inputSchema: z.object({
        url: z.string().describe("Target URL to browse (must be in active scope)"),
      }),
    },
    withPerm("read", async (args) => {
      const host = await assertInScope(args.url, env.DB);
      const url = args.url.startsWith("http") ? args.url : `https://${args.url}`;

      let probeStatus = 0;
      let headers: Record<string, string> = {};
      let previewText = "";

      try {
        const probeResp = await fetch(url, {
          redirect: "manual",
          headers: { "User-Agent": "Mozilla/5.0 (ExposureAgent/1.0)" },
        });
        probeStatus = probeResp.status;
        headers = Object.fromEntries(probeResp.headers);
        const text = await probeResp.text();
        previewText = text.slice(0, 5000);
      } catch (err: any) {
        previewText = `Fetch error: ${err.message}`;
      }

      return {
        host,
        url,
        probeStatus,
        headers,
        contentPreview: previewText,
      };
    })
  );

  server.registerTool(
    "scan_target",
    {
      title: "Scan Target Host",
      description: "Launch a scan workflow against an in-scope target host",
      inputSchema: z.object({
        host: z.string().describe("Target host in scope to scan"),
      }),
    },
    withPerm("scan", async (args) => {
      const host = await assertInScope(args.host, env.DB);
      const scanId = crypto.randomUUID();
      const now = Date.now();

      await env.DB.prepare(
        "INSERT INTO scans (id, target_host, status, started_at) VALUES (?, ?, 'pending', ?)"
      )
        .bind(scanId, host, now)
        .run();

      let instanceId = scanId;
      if (env.TARGET_WORKFLOW) {
        const instance = await env.TARGET_WORKFLOW.create({
          id: scanId,
          params: { host, scanId },
        });
        instanceId = instance.id;
      }

      return {
        scanId,
        instanceId,
        host,
        status: "launched",
      };
    })
  );

  server.registerTool(
    "get_scan_status",
    {
      title: "Get Scan Status",
      description: "Poll the status and progress of a scan instance",
      inputSchema: z.object({
        scanId: z.string().describe("Scan ID or workflow instance ID"),
      }),
    },
    withPerm("scan", async (args) => {
      const scanRow = await env.DB.prepare(
        "SELECT id, target_host, status, started_at, completed_at, findings_count, error FROM scans WHERE id = ?"
      )
        .bind(args.scanId)
        .first();

      let workflowStatus: unknown = null;
      if (env.TARGET_WORKFLOW) {
        try {
          const instance = await env.TARGET_WORKFLOW.get(args.scanId);
          workflowStatus = await instance.status();
        } catch {
          // not a workflow ID or already completed
        }
      }

      return {
        scan: scanRow || null,
        workflow: workflowStatus,
      };
    })
  );

  server.registerTool(
    "put_targets",
    {
      title: "Bulk Replace Scope Targets",
      description: "Atomically replace the whole set of scope targets. Missing active targets are retired.",
      inputSchema: z.object({
        targets: z.array(
          z.object({
            host: z.string().describe("Hostname or FQDN"),
            notes: z.string().optional().describe("Optional description or tag"),
            expiryDays: z.number().int().min(1).max(maxExpiry).optional().describe(`Days until expiry (1-${maxExpiry})`),
          })
        ).max(500).describe("List of target objects"),
        authorization_ref: z.string().describe("Attestation reference or ticket ID justifying scope"),
      }),
    },
    withPerm("admin", async (args) => {
      return await putTargets(
        env.DB,
        clientId,
        args.targets,
        args.authorization_ref,
        defaultExpiry,
        maxExpiry
      );
    })
  );

  server.registerTool(
    "add_target",
    {
      title: "Add Target to Scope",
      description: "Add or reactivate a single target host in the scope registry",
      inputSchema: z.object({
        host: z.string().describe("Hostname or FQDN to add"),
        notes: z.string().optional().describe("Optional note"),
        expiryDays: z.number().int().min(1).max(maxExpiry).optional().describe(`Days until expiry (1-${maxExpiry})`),
        authorization_ref: z.string().describe("Attestation reference justifying scope"),
      }),
    },
    withPerm("admin", async (args) => {
      return await addTarget(
        env.DB,
        clientId,
        args,
        args.authorization_ref,
        defaultExpiry,
        maxExpiry
      );
    })
  );

  server.registerTool(
    "remove_target",
    {
      title: "Remove Target from Scope",
      description: "Retire a target from active scope without deleting finding history",
      inputSchema: z.object({
        host: z.string().describe("Hostname to retire"),
      }),
    },
    withPerm("admin", async (args) => {
      const removed = await removeTarget(env.DB, args.host);
      return { host: normalizeHost(args.host), retired: removed };
    })
  );

  server.registerTool(
    "triage_finding",
    {
      title: "Triage Finding",
      description: "Update the state of a finding (e.g. mark fixed, accepted_risk, false_positive)",
      inputSchema: z.object({
        id: z.string().describe("Finding ID"),
        state: z.enum(["open", "fixed", "accepted_risk", "false_positive"]).describe("New state"),
        notes: z.string().optional().describe("Triage explanation notes"),
      }),
    },
    withPerm("admin", async (args) => {
      return await triageFinding(
        env.DB,
        args.id,
        args.state as FindingState,
        args.notes
      );
    })
  );
}
