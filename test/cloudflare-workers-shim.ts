// ponytail: Node.js testing shim for cloudflare:workers module

export class WorkflowEntrypoint<Env = unknown, Params = unknown> {
  ctx: ExecutionContext;
  env: Env;

  constructor(ctx: ExecutionContext, env: Env) {
    this.ctx = ctx;
    this.env = env;
  }

  run(event: any, step: any): Promise<any> {
    throw new Error("run not implemented");
  }
}

export class DurableObject<Env = unknown> {
  ctx: DurableObjectState;
  env: Env;

  constructor(ctx: DurableObjectState, env: Env) {
    this.ctx = ctx;
    this.env = env;
  }
}

export class WorkerEntrypoint<Env = unknown> {
  ctx: ExecutionContext;
  env: Env;

  constructor(ctx: ExecutionContext, env: Env) {
    this.ctx = ctx;
    this.env = env;
  }
}
