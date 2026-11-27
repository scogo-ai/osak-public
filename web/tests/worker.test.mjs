import assert from "node:assert/strict";
import { test } from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import worker, { addNoStoreHeaders, constantTimeEqual, injectHomeRuntimeConfig, publicRepositoryUrl } from "../src/index.js";

const { privateKey, publicKey } = await generateKeyPair("RS256");
const publicJwk = { ...(await exportJWK(publicKey)), alg: "RS256", kid: "test-key", use: "sig" };
const accessIssuer = "https://osak-team.cloudflareaccess.com";
const accessAudience = "osak-admin-audience";

const accessToken = async ({
  issuer = accessIssuer,
  audience = accessAudience,
  commonName = "access-id",
  type = "app",
  expiration = "5m",
  notBefore,
} = {}) => {
  let token = new SignJWT({ type, common_name: commonName })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt();
  if (expiration) token = token.setExpirationTime(expiration);
  if (notBefore) token = token.setNotBefore(notBefore);
  return token.sign(privateKey);
};

const env = (overrides = {}) => ({
  PUBLIC_ORIGIN: "https://origin.example.invalid",
  ORIGIN_SHARED_SECRET: "local-secret",
  ACCESS_SERVICE_TOKEN_ID: "access-id",
  ACCESS_TEAM_ISSUER: accessIssuer,
  ACCESS_ADMIN_AUDIENCE: accessAudience,
  OSAK_ADMIN_ACCESS_TOKEN: "admin-secret",
  ASSETS: { fetch: async () => new Response("<html>asset</html>", { headers: { "content-type": "text/html" } }) },
  ...overrides,
});

test("constant-time comparison accepts exact values and rejects mismatches", () => {
  assert.equal(constantTimeEqual("abc", "abc"), true);
  assert.equal(constantTimeEqual("abc", "abd"), false);
  assert.equal(constantTimeEqual("abc", "ab"), false);
});

test("static responses receive security headers", async () => {
  const response = await worker.fetch(new Request("https://osak.example/"), env());
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.match(response.headers.get("content-security-policy"), /default-src 'self'/);
});

test("origin responses are never cacheable, including errors", async () => {
  const response = addNoStoreHeaders(new Response("upstream", { status: 503, headers: { "cache-control": "public, max-age=60" } }));
  assert.equal(response.status, 503);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("cdn-cache-control"), "no-store");
});

test("home document receives runtime public config without changing committed HTML", async () => {
  const html = '<!doctype html><html><head><meta name="turnstile-site-key" content=""></head><body><a data-repository-link href="#" hidden aria-hidden="true">repo</a><span id="repository-pending">pending</span></body></html>';
  const response = await injectHomeRuntimeConfig(new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } }), {
    TURNSTILE_SITE_KEY: "1x00000000000000000000AA",
    REPOSITORY_URL: "https://github.com/example/osak",
  });
  const output = await response.text();
  assert.match(output, /content="1x00000000000000000000AA"/);
  assert.match(output, /href="https:\/\/github\.com\/example\/osak"/);
  assert.match(output, /data-repository-link href="https:\/\/github\.com\/example\/osak"/);
  assert.match(output, /id="repository-pending" hidden/);
  assert.equal(publicRepositoryUrl("http://github.com/example/osak"), "");
});

test("repository link stays hidden when B2 URL is absent", async () => {
  const html = '<meta name="turnstile-site-key" content=""><a data-repository-link href="#" hidden aria-hidden="true">repo</a><span id="repository-pending">pending</span>';
  const response = await injectHomeRuntimeConfig(new Response(html, { headers: { "content-type": "text/html" } }), { TURNSTILE_SITE_KEY: "1x00000000000000000000AA" });
  const output = await response.text();
  assert.match(output, /content="1x00000000000000000000AA"/);
  assert.match(output, /data-repository-link href="#" hidden/);
  assert.match(output, /id="repository-pending">pending/);
});

test("admin requests are denied before origin access without both Access headers", async () => {
  const originalFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => { called = true; return new Response("unexpected"); };
  try {
    const response = await worker.fetch(new Request("https://osak.example/api/v1/admin/users"), env());
    assert.equal(response.status, 403);
    assert.equal(called, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("admin requests reject forged service-token headers without a valid Access JWT", async () => {
  const originalFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => { called = true; return new Response("unexpected"); };
  try {
    const response = await worker.fetch(new Request("https://osak.example/api/v1/admin/users", {
      headers: {
        "CF-Access-Client-Id": "access-id",
        "CF-Access-Client-Secret": "access-secret",
      },
    }), env());
    assert.equal(response.status, 403);
    assert.equal(called, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("origin requests forward the shared secret and preserve a streamed body", async () => {
  const originalFetch = globalThis.fetch;
  let upstreamRequest;
  const stream = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode("chunk-a")); controller.close(); } });
  globalThis.fetch = async (request) => { upstreamRequest = request; return new Response(stream, { status: 200, headers: { "content-type": "text/event-stream" } }); };
  try {
    const response = await worker.fetch(new Request("https://osak.example/mcp", { method: "POST", body: "stream me", headers: { "content-type": "application/json", "X-Forwarded-For": "spoofed", "X-Forwarded-Host": "spoofed", "X-OSAK-Client-IP": "spoofed", "CF-Connecting-IP": "203.0.113.9" } }), env());
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("content-type"), "text/event-stream");
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.ok(response.body, "streaming response body should be present");
    assert.equal(upstreamRequest.headers.get("x-osak-origin-secret"), "local-secret");
    assert.equal(upstreamRequest.headers.get("x-osak-admin-access"), null);
    assert.equal(upstreamRequest.headers.get("x-forwarded-host"), "osak.example");
    assert.equal(upstreamRequest.headers.get("x-forwarded-for"), "203.0.113.9");
    assert.equal(upstreamRequest.headers.get("x-osak-client-ip"), "203.0.113.9");
    assert.equal(await response.text(), "chunk-a");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("admin requests pass only with a valid Access service-token JWT", async () => {
  const originalFetch = globalThis.fetch;
  let upstreamRequest;
  const assertion = await accessToken();
  globalThis.fetch = async (request) => {
    const url = request instanceof Request ? request.url : String(request);
    if (url.endsWith("/cdn-cgi/access/certs")) {
      return new Response(JSON.stringify({ keys: [publicJwk] }), {
        headers: { "content-type": "application/json" },
      });
    }
    upstreamRequest = request;
    return new Response("ok");
  };
  try {
    const request = new Request("https://osak.example/api/v1/admin/users", { headers: {
      "CF-Access-Jwt-Assertion": assertion,
      "CF-Access-Client-Id": "forged-id",
      "CF-Access-Client-Secret": "forged-secret",
      Cookie: "CF_Authorization=forged-cookie",
      "X-OSAK-Origin-Secret": "client-spoof",
      "X-OSAK-Admin-Access": "client-spoof",
    } });
    const response = await worker.fetch(request, env());
    assert.equal(response.status, 200);
    assert.equal(upstreamRequest.headers.get("x-osak-origin-secret"), "local-secret");
    assert.equal(upstreamRequest.headers.get("x-osak-admin-access"), "admin-secret");
    assert.equal(upstreamRequest.headers.get("cf-access-client-id"), null);
    assert.equal(upstreamRequest.headers.get("cf-access-client-secret"), null);
    assert.equal(upstreamRequest.headers.get("cf-access-jwt-assertion"), null);
    assert.equal(upstreamRequest.headers.get("cookie"), null);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("admin JWT validation rejects issuer, audience, type, common-name, and time claim failures", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (request) => {
    const url = request instanceof Request ? request.url : String(request);
    if (url.endsWith("/cdn-cgi/access/certs")) {
      return new Response(JSON.stringify({ keys: [publicJwk] }), {
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error("origin must not be reached");
  };
  try {
    const cases = [
      { name: "issuer", issuer: "https://wrong-team.cloudflareaccess.com" },
      { name: "audience", audience: "wrong-audience" },
      { name: "type", type: "user" },
      { name: "common name", commonName: "wrong-client" },
      { name: "expired", expiration: "-1s" },
      { name: "not before", notBefore: "10m" },
    ];
    for (const invalid of cases) {
      const assertion = await accessToken(invalid);
      const response = await worker.fetch(new Request("https://osak.example/api/v1/admin/users", {
        headers: { "Cf-Access-Jwt-Assertion": assertion },
      }), env());
      assert.equal(response.status, 403, invalid.name);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("missing origin configuration returns a generic service error", async () => {
  const response = await worker.fetch(new Request("https://osak.example/docs"), env({ PUBLIC_ORIGIN: "", ORIGIN_BASE_URL: "", ORIGIN_URL: "" }));
  assert.equal(response.status, 503);
  assert.doesNotMatch(await response.text(), /origin\.example/);
});

test("origin failures become a non-cacheable gateway error", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("origin down"); };
  try {
    const response = await worker.fetch(new Request("https://osak.example/api/v1/health"), env());
    assert.equal(response.status, 502);
    assert.equal(response.headers.get("cache-control"), "no-store");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
