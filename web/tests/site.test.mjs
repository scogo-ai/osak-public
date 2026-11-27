import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const read = (file) => readFile(resolve(root, file), "utf8");
const readRepo = (file) => readFile(resolve(root, "..", file), "utf8");

test("home page exposes the required public sections and routes", async () => {
  const html = await read("static/index.html");
  for (const expected of ["OSAK — Open Security Advisory Kosh", "how-it-works", "coverage", "get-key", "/privacy", "/terms", "/docs", "/mcp", "/api/v1/health"]) {
    assert.ok(html.includes(expected), `missing ${expected}`);
  }
  assert.match(html, /Zero Data Retention by design/);
  assert.match(html, /We never store the assets you send/);
  assert.match(html, /I agree to the <a href="\/terms">terms of use/);
  assert.match(html, /Request metadata/);
  assert.match(html, /Account details/);
  assert.match(html, /Email me an API key/);
  assert.match(html, /one-time API key/);
  assert.match(html, /won’t revoke it or issue a second one/);
  assert.match(html, /favicon\.svg/);
  assert.match(html, /data-repository-link[^>]+hidden/);
  assert.doesNotMatch(html, /github\.com\//i);
});

test("published legal pages describe the signup and retention terms", async () => {
  const [privacy, terms] = await Promise.all([read("static/privacy/index.html"), read("static/terms/index.html")]);
  for (const page of [privacy, terms]) {
    assert.doesNotMatch(page, /draft — needs legal review|Proposed public beta wording/i);
    assert.match(page, /We never store the assets you send/);
    assert.match(page, /account details for the life of the account/i);
    assert.match(page, /request metadata .* for 90 days/i);
  }
  assert.doesNotMatch(privacy, /verified email address/);
  assert.match(privacy, /one API-key email/);
  assert.match(terms, /issued after the signup checks and emailed once/);
  assert.match(terms, /never revoke or issue a second active key/);
  assert.doesNotMatch(terms, /email verification/);
  assert.match(privacy, /match|resolve/);
  assert.match(terms, /Do not use OSAK to conduct active discovery/);
});

test("client never sends cookies or telemetry and uses contract signup fields", async () => {
  const app = await read("static/app.js");
  assert.doesNotMatch(app, /document\.cookie|navigator\.sendBeacon|google-analytics|plausible|segment/i);
  assert.match(app, /credentials: "omit"/);
  for (const field of ["name:", "organization:", "email:", "turnstile_token:", "accept_terms:", "accepted_terms_version:"]) assert.match(app, new RegExp(field));
  assert.match(app, /one email containing your API key/);
  assert.doesNotMatch(app, /verification link|verification email/i);
});

test("build script includes both legal pages", async () => {
  const packageJson = JSON.parse(await read("package.json"));
  assert.equal(packageJson.scripts.build, "node scripts/build.mjs");
});

test("active edge protections are scoped to the OSAK hostname", async () => {
  const rateLimits = JSON.parse(await readRepo("deploy/cloudflare/rate-limits.json"));
  const waf = JSON.parse(await readRepo("deploy/cloudflare/waf-rules.json"));
  assert.equal(rateLimits.kind, "zone");
  assert.equal(rateLimits.phase, "http_ratelimit");
  assert.equal(waf.kind, "zone");
  assert.equal(waf.phase, "http_request_firewall_custom");
  for (const ruleset of [rateLimits, waf]) {
    assert.ok(ruleset.rules.length > 0);
    for (const rule of ruleset.rules) {
      assert.equal(rule.enabled, true);
      assert.ok(rule.expression.startsWith('http.host eq "osak.lab.scogo.ai" and '));
    }
  }
  for (const rule of rateLimits.rules) {
    assert.deepEqual(rule.ratelimit.characteristics, ["cf.colo.id", "ip.src"]);
    assert.ok(rule.ratelimit.period > 0 && rule.ratelimit.requests_per_period > 0);
  }
});

test("production Wrangler config uses the exact custom domain and runs the Worker first", async () => {
  const wrangler = await read("wrangler.toml");
  assert.match(wrangler, /workers_dev = false/);
  assert.match(wrangler, /run_worker_first = true/);
  assert.match(wrangler, /\[env\.production\]/);
  assert.match(wrangler, /pattern = "osak\.lab\.scogo\.ai", custom_domain = true/);
});
