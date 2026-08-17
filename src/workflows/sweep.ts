// ponytail: batch fan-out over active scope targets

import { WorkflowEntrypoint, WorkflowEvent, WorkflowStep } from "cloudflare:workers";
import { TargetWorkflowParams } from "./target.js";
import { isPaused } from "../core/scope.js";

export interface SweepWorkflowParams {
  triggeredBy?: string;
}

export class SweepWorkflow extends WorkflowEntrypoint<Env, SweepWorkflowParams> {
  async run(event: WorkflowEvent<SweepWorkflowParams>, step: WorkflowStep) {
    const now = Date.now();

    if (await step.do("check-paused", async () => isPaused(this.env.DB))) {
      return { swept: 0, paused: true };
    }

    if (!this.env.TARGET_WORKFLOW) {
      throw new Error("TARGET_WORKFLOW binding is required");
    }

    const targets = await step.do("fetch-active-targets", async () => {
      const rows = await this.env.DB
        .prepare("SELECT host FROM targets WHERE status = 'active' AND expires_at > ? ORDER BY host ASC")
        .bind(now)
        .all<{ host: string }>();

      return (rows.results || []).map((r) => r.host);
    });

    if (targets.length === 0) {
      return { swept: 0, message: "No active targets in scope" };
    }

    // Batch fan-out in chunks of 100
    const batchSize = 100;
    const batches: string[][] = [];
    for (let i = 0; i < targets.length; i += batchSize) {
      batches.push(targets.slice(i, i + batchSize));
    }

    let launchedCount = 0;
    for (let b = 0; b < batches.length; b++) {
      const batchHosts = batches[b];
      await step.do(`fanout-batch-${b}`, async () => {
        const items = batchHosts.map((host) => {
          const scanId = crypto.randomUUID();
          return {
            id: scanId,
            params: { host, scanId } as TargetWorkflowParams,
          };
        });
        await this.env.TARGET_WORKFLOW.createBatch(items);
      });
      launchedCount += batchHosts.length;
    }

    return {
      swept: launchedCount,
      totalBatches: batches.length,
    };
  }
}
