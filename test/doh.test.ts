import { describe, it, expect, vi, beforeEach } from "vitest";
import { resolveHostDoh } from "../src/core/doh.js";

describe("DoH (DNS-over-HTTPS) Resolution", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("resolves IPv4 bare IP directly without making network requests", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const res = await resolveHostDoh("192.0.2.1");

    expect(res.status).toBe("resolved");
    expect(res.aRecords).toEqual(["192.0.2.1"]);
    expect(res.allIps).toEqual(["192.0.2.1"]);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("resolves IPv6 bare IP directly without making network requests", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const res = await resolveHostDoh("2001:db8::1");

    expect(res.status).toBe("resolved");
    expect(res.aaaaRecords).toEqual(["2001:db8::1"]);
    expect(res.allIps).toEqual(["2001:db8::1"]);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("parses DoH JSON responses for hostname", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (url: any) => {
      const urlStr = url.toString();
      if (urlStr.includes("type=AAAA")) {
        return new Response(
          JSON.stringify({
            Status: 0,
            TC: false,
            RD: true,
            RA: true,
            AD: false,
            CD: false,
            Question: [{ name: "example.com", type: 28 }],
            Answer: [
              { name: "example.com", type: 28, TTL: 300, data: "2001:db8::10" },
            ],
          })
        );
      }
      return new Response(
        JSON.stringify({
          Status: 0,
          TC: false,
          RD: true,
          RA: true,
          AD: false,
          CD: false,
          Question: [{ name: "example.com", type: 1 }],
          Answer: [
            { name: "example.com", type: 1, TTL: 300, data: "192.0.2.10" },
          ],
        })
      );
    });

    const res = await resolveHostDoh("example.com");
    expect(res.status).toBe("resolved");
    expect(res.aRecords).toEqual(["192.0.2.10"]);
    expect(res.aaaaRecords).toEqual(["2001:db8::10"]);
    expect(res.allIps).toHaveLength(2);
  });

  it("handles NXDOMAIN response properly", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      return new Response(
        JSON.stringify({
          Status: 3,
          TC: false,
          RD: true,
          RA: true,
          AD: false,
          CD: false,
          Question: [{ name: "nonexistent.example.com", type: 1 }],
        })
      );
    });

    const res = await resolveHostDoh("nonexistent.example.com");
    expect(res.status).toBe("nxdomain");
    expect(res.allIps).toHaveLength(0);
  });
});
