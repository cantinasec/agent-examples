// ponytail: simple R2 keying by timestamp and hash

/**
 * Save a screenshot to R2 keyed by host and timestamp.
 */
export async function saveScreenshot(
  bucket: R2Bucket,
  host: string,
  screenshotData: ArrayBuffer | Uint8Array,
  mimeType = "image/png"
): Promise<string> {
  const timestamp = Date.now();
  const randomSuffix = Math.random().toString(36).substring(2, 8);
  const key = `screenshots/${host}/${timestamp}-${randomSuffix}.png`;

  await bucket.put(key, screenshotData, {
    httpMetadata: {
      contentType: mimeType,
    },
    customMetadata: {
      host,
      capturedAt: timestamp.toString(),
    },
  });

  return key;
}

export async function getEvidenceBlob(
  bucket: R2Bucket,
  key: string
): Promise<R2ObjectBody | null> {
  return await bucket.get(key);
}

// Header values that carry a live credential. Keys are preserved so detector
// checks that only test for a header's presence keep working.
const CREDENTIAL_HEADERS = new Set([
  "set-cookie",
  "cookie",
  "authorization",
  "proxy-authorization",
]);

/**
 * Findings and Workflow step results are stored durably. Mask credential-bearing
 * header values at capture so a scanned host's session cookies never reach D1,
 * step storage, or MCP tool output.
 */
export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const safe: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    safe[key] = CREDENTIAL_HEADERS.has(key.toLowerCase()) ? "[REDACTED]" : value;
  }
  return safe;
}

/**
 * Mask the values in a credential-dumping response body while keeping the key
 * names, which is what makes the finding actionable. Handles the two shapes the
 * probe paths return: dotenv `KEY=value` and JSON `"value": "..."` as served by
 * Spring Boot's /actuator/env.
 */
export function redactBodyValues(body: string): string {
  if (body.trimStart().startsWith("{")) {
    return body.replace(/("value"\s*:\s*)"(?:[^"\\]|\\.)*"/g, '$1"[REDACTED]"');
  }
  return body.replace(
    /^([ \t]*(?:export[ \t]+)?[^\s=#][^\r\n=]*=[ \t]*)[^\r\n]+/gm,
    "$1[REDACTED]"
  );
}
