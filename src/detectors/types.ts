// ponytail: common detector interfaces

import { DnsResolutionResult } from "../core/doh.js";

export interface ProbeResponse {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  redirectChain?: string[];
}

export interface RenderedPage {
  markdown?: string;
  html?: string;
  screenshotKey?: string | null;
}

export interface PathProbeResult {
  path: string;
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  contentType?: string;
}

export interface DetectorContext {
  host: string;
  probe: ProbeResponse;
  render?: RenderedPage;
  doh?: DnsResolutionResult;
  paths?: PathProbeResult[];
  aiAnalysis?: {
    isExposed: boolean;
    confidence: number;
    reason: string;
  };
}
