import { defineConfig } from "vitest/config";
import { resolve } from "node:path";

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
  },
  resolve: {
    alias: {
      "cloudflare:workers": resolve(import.meta.dirname, "test/cloudflare-workers-shim.ts"),
    },
  },
});
