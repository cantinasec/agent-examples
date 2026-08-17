// ponytail: Cloudflare JSON DoH with standard fetch

export interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

export interface DohResponse {
  Status: number; // 0 = NOERROR, 3 = NXDOMAIN
  TC: boolean;
  RD: boolean;
  RA: boolean;
  AD: boolean;
  CD: boolean;
  Question: Array<{ name: string; type: number }>;
  Answer?: DohAnswer[];
}

export interface DnsResolutionResult {
  host: string;
  status: "resolved" | "nxdomain" | "error";
  aRecords: string[];
  aaaaRecords: string[];
  cnameRecords: string[];
  allIps: string[];
  rawAnswers: DohAnswer[];
}

/**
 * Resolve a hostname via DNS-over-HTTPS. Issues parallel A and AAAA queries.
 * Bare IPs are returned directly without network requests.
 */
export async function resolveHostDoh(
  host: string,
  dohEndpoint = "https://cloudflare-dns.com/dns-query"
): Promise<DnsResolutionResult> {
  const result: DnsResolutionResult = {
    host,
    status: "error",
    aRecords: [],
    aaaaRecords: [],
    cnameRecords: [],
    allIps: [],
    rawAnswers: [],
  };

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    result.status = "resolved";
    result.aRecords.push(host);
    result.allIps.push(host);
    return result;
  }
  if (/^[0-9a-fA-F:]+$/.test(host) && host.includes(":")) {
    result.status = "resolved";
    result.aaaaRecords.push(host);
    result.allIps.push(host);
    return result;
  }

  try {
    const [aRes, aaaaRes] = await Promise.all([
      queryDoh(host, "A", dohEndpoint),
      queryDoh(host, "AAAA", dohEndpoint),
    ]);

    const answers = [...(aRes.Answer || []), ...(aaaaRes.Answer || [])];
    result.rawAnswers = answers;

    if (aRes.Status === 3 && aaaaRes.Status === 3) {
      result.status = "nxdomain";
      return result;
    }

    for (const ans of answers) {
      if (ans.type === 1) {
        result.aRecords.push(ans.data);
        result.allIps.push(ans.data);
      } else if (ans.type === 28) {
        result.aaaaRecords.push(ans.data);
        result.allIps.push(ans.data);
      } else if (ans.type === 5) {
        result.cnameRecords.push(ans.data);
      }
    }

    if (result.allIps.length > 0 || result.cnameRecords.length > 0) {
      result.status = "resolved";
    } else {
      result.status = "nxdomain";
    }
  } catch {
    result.status = "error";
  }

  return result;
}

async function queryDoh(
  name: string,
  type: string,
  endpoint: string
): Promise<DohResponse> {
  const url = `${endpoint}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const resp = await fetch(url, {
    headers: {
      Accept: "application/dns-json",
    },
  });

  if (!resp.ok) {
    throw new Error(`DoH query failed with status ${resp.status}`);
  }

  return (await resp.json()) as DohResponse;
}
