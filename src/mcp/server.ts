// ponytail: stateless MCP handler with Cloudflare Access JWT verification

import { createMcpHandler } from "agents/mcp/server";
import { McpServer } from "@modelcontextprotocol/server";
import { authenticateRequest } from "../auth/authorization.js";
import { registerAllTools } from "./tools.js";

export function getMcpHandler(env: Env, allowedHostnames: string[], clientId: string) {
  return createMcpHandler(
    async () => {
      const server = new McpServer({
        name: "exposure-agent",
        version: "0.1.0",
      });

      registerAllTools(server, { env, clientId });
      return server;
    },
    {
      route: "/mcp",
      allowedHostnames,
      allowedOriginHostnames: [env.MCP_ORIGIN_HOSTNAME],
      corsOptions: {
        origin: `https://${env.MCP_ORIGIN_HOSTNAME}`,
        methods: "GET, POST, OPTIONS",
        headers: "Content-Type, Cf-Access-Jwt-Assertion, CF-Access-Client-Id, CF-Access-Client-Secret",
      },
    }
  );
}

export async function handleMcpRequest(request: Request, env: Env): Promise<Response> {
  const requestUrl = new URL(request.url);
  // Only the configured hostname is accepted. Local development sets
  // MCP_HOSTNAME and MCP_ORIGIN_HOSTNAME to localhost instead of the Worker
  // shipping a standing exception for it.
  const allowedHosts = new Set([env.MCP_HOSTNAME]);
  if (!allowedHosts.has(requestUrl.hostname)) {
    return new Response(JSON.stringify({ error: "Bad Request: invalid MCP host" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const origin = request.headers.get("Origin");
  if (origin) {
    try {
      if (new URL(origin).hostname !== env.MCP_ORIGIN_HOSTNAME) {
        return new Response(JSON.stringify({ error: "Forbidden: invalid MCP origin" }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        });
      }
    } catch {
      return new Response(JSON.stringify({ error: "Bad Request: invalid Origin" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": origin || `https://${env.MCP_ORIGIN_HOSTNAME}`,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers":
          "Content-Type, Accept, Cf-Access-Jwt-Assertion, CF-Access-Client-Id, CF-Access-Client-Secret, MCP-Protocol-Version, Mcp-Session-Id",
      },
    });
  }

  const jwtHeader = request.headers.get("Cf-Access-Jwt-Assertion");
  let principal;
  try {
    principal = await authenticateRequest(env, request);
  } catch {
    return new Response(JSON.stringify({ error: "Forbidden" }), {
      status: 403,
      headers: { "Content-Type": "application/json" },
    });
  }
  const clientId = principal.client_id;
  const role = principal.role;

  const handler = getMcpHandler(env, [env.MCP_HOSTNAME], clientId);

  return await handler.fetch(request, {
    authInfo: {
      token: jwtHeader,
      sub: clientId,
      clientId,
      scopes: [role],
      props: {
        clientId,
        role,
      },
    } as any,
  });
}
