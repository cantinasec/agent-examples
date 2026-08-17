import { describe, it, expect, beforeEach } from "vitest";
import { McpServer } from "@modelcontextprotocol/server";
import { registerAllTools } from "../src/mcp/tools.js";
import { createTestDb } from "./mock-d1.js";
import { ensurePrincipal } from "../src/auth/principals.js";

describe("MCP Server Tools Registration and Execution", () => {
  let db: D1Database;
  let env: Env;

  beforeEach(async () => {
    db = createTestDb();
    env = {
      DB: db,
      DEFAULT_TARGET_EXPIRY_DAYS: "7",
      MAX_TARGET_EXPIRY_DAYS: "30",
    } as any;

    await ensurePrincipal(db, "admin-user", "Admin User", "admin");
    await ensurePrincipal(db, "read-user", "Read User", "read");
  });

  it("registers all 10 MCP tools", () => {
    const server = new McpServer({ name: "test-mcp", version: "1.0.0" });
    registerAllTools(server, { env, clientId: "admin-user" });

    const registeredTools = (server as any)._registeredTools;
    expect(registeredTools).toBeDefined();
    expect(registeredTools["list_targets"]).toBeDefined();
    expect(registeredTools["list_findings"]).toBeDefined();
    expect(registeredTools["get_finding"]).toBeDefined();
    expect(registeredTools["browse_target"]).toBeDefined();
    expect(registeredTools["scan_target"]).toBeDefined();
    expect(registeredTools["get_scan_status"]).toBeDefined();
    expect(registeredTools["put_targets"]).toBeDefined();
    expect(registeredTools["add_target"]).toBeDefined();
    expect(registeredTools["remove_target"]).toBeDefined();
    expect(registeredTools["triage_finding"]).toBeDefined();
  });

  it("admin principal can add targets and list targets via MCP tools", async () => {
    const server = new McpServer({ name: "test-mcp", version: "1.0.0" });
    registerAllTools(server, { env, clientId: "admin-user" });

    const addTool = (server as any)._registeredTools["add_target"];
    const addResult = await addTool.handler({
      host: "my-app.example.com",
      authorization_ref: "AUTH-001",
      notes: "Production dashboard",
    });

    expect(addResult.isError).toBeFalsy();
    expect(addResult.content[0].text).toContain("my-app.example.com");

    const listTool = (server as any)._registeredTools["list_targets"];
    const listResult = await listTool.handler({});
    expect(listResult.isError).toBeFalsy();
    expect(listResult.content[0].text).toContain("my-app.example.com");
  });

  it("read principal cannot add targets or triage findings", async () => {
    const server = new McpServer({ name: "test-mcp", version: "1.0.0" });
    registerAllTools(server, { env, clientId: "read-user" });

    const addTool = (server as any)._registeredTools["add_target"];
    const addResult = await addTool.handler({
      host: "forbidden.example.com",
      authorization_ref: "AUTH-001",
    });

    expect(addResult.isError).toBe(true);
    expect(addResult.content[0].text).toContain("role 'admin' is required");
  });
});
