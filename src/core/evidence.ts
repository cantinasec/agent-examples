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
