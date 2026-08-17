// ponytail: nightly target expiry cleanup

import { WorkflowEntrypoint, WorkflowEvent, WorkflowStep } from "cloudflare:workers";
import { retireExpiredTargets } from "../core/scope.js";

export class ExpireWorkflow extends WorkflowEntrypoint<Env> {
  async run(_event: WorkflowEvent<unknown>, step: WorkflowStep) {
    const retiredCount = await step.do("retire-expired", async () => {
      return await retireExpiredTargets(this.env.DB);
    });

    return {
      retired: retiredCount,
      timestamp: Date.now(),
    };
  }
}
