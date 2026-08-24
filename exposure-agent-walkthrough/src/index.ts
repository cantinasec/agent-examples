// ponytail: unified worker router for MCP, triage agent DO, health, and crons

import { routeAgentRequest } from "agents";
import { authenticateRequest } from "./auth/authorization.js";
export { TriageAgent } from "./agent/triage.js";
export { SweepWorkflow } from "./workflows/sweep.js";
export { TargetWorkflow } from "./workflows/target.js";
export { ExpireWorkflow } from "./workflows/expire.js";

import { handleMcpRequest } from "./mcp/server.js";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health" || url.pathname === "/status") {
      return new Response(
        JSON.stringify({
          status: "ok",
          service: "exposure-agent",
          timestamp: Date.now(),
        }),
        {
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // MCP Endpoint (Cloudflare Access JWT protected)
    if (url.pathname === "/mcp" || url.pathname.startsWith("/mcp/")) {
      return await handleMcpRequest(request, env);
    }

    // Agent routing (/agents/triage/...)
    if (url.pathname.startsWith("/agents/")) {
      try {
        await authenticateRequest(env, request);
      } catch {
        return new Response("Forbidden", { status: 403 });
      }

      const agentResponse = await routeAgentRequest(request, env);
      if (agentResponse) {
        return agentResponse;
      }
    }

    return new Response("Not Found", { status: 404 });
  },

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(
      (async () => {
        try {
          if (env.EXPIRE_WORKFLOW) {
            await env.EXPIRE_WORKFLOW.create({});
          }
          if (env.SWEEP_WORKFLOW) {
            await env.SWEEP_WORKFLOW.create({
              params: { triggeredBy: `cron-${event.cron}` },
            });
          }
        } catch (err) {
          console.error("Scheduled cron error:", err);
        }
      })()
    );
  },
};
