import { createRemoteJWKSet, jwtVerify } from "jose";

const API_PREFIX = "/api";
const DOCS_PATHS = new Set(["/docs", "/docs/"]);
const MCP_PATHS = new Set(["/mcp", "/mcp/"]);

const jsonResponse = (status, message) => new Response(JSON.stringify({ error: message }), {
  status,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  },
});

const isApiPath = (pathname) => pathname === API_PREFIX || pathname.startsWith(`${API_PREFIX}/`);

const isDocsPath = (pathname) => DOCS_PATHS.has(pathname) || pathname.startsWith("/docs/");

const isMcpPath = (pathname) => MCP_PATHS.has(pathname) || pathname.startsWith("/mcp/");

const isOriginPath = (pathname) => isApiPath(pathname) || pathname === "/openapi.json" || isDocsPath(pathname) || isMcpPath(pathname);

const isHomePath = (pathname) => pathname === "/" || pathname === "/index.html";

const isAdminPath = (pathname) => pathname === "/api/v1/admin" || pathname.startsWith("/api/v1/admin/");

const constantTimeEqual = (left, right) => {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const length = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < length; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
};

const jwksByIssuer = new Map();

const configuredIssuer = (env) => {
  const value = String(env.ACCESS_TEAM_ISSUER || "").trim().replace(/\/$/, "");
  if (!value) return "";
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.pathname !== "/" || url.search || url.hash) return "";
    return url.toString().replace(/\/$/, "");
  } catch (_) {
    return "";
  }
};

const remoteJwksFor = (issuer) => {
  let jwks = jwksByIssuer.get(issuer);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
    jwksByIssuer.set(issuer, jwks);
  }
  return jwks;
};

const adminServiceTokenValid = async (request, env) => {
  const issuer = configuredIssuer(env);
  const audience = String(env.ACCESS_ADMIN_AUDIENCE || "").trim();
  const expectedCommonName = String(env.ACCESS_SERVICE_TOKEN_ID || "").trim();
  const internalAdminSecret = String(env.OSAK_ADMIN_ACCESS_TOKEN || "");
  const assertion = request.headers.get("Cf-Access-Jwt-Assertion") || "";
  if (!issuer || !audience || !expectedCommonName || !internalAdminSecret || !assertion) return false;

  try {
    const { payload } = await jwtVerify(assertion, remoteJwksFor(issuer), {
      algorithms: ["RS256"],
      issuer,
      audience,
    });
    return payload.type === "app" && payload.common_name === expectedCommonName;
  } catch (_) {
    return false;
  }
};

const addStaticSecurityHeaders = (response) => {
  const headers = new Headers(response.headers);
  headers.set("content-security-policy", "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self' https://challenges.cloudflare.com; style-src 'self'; connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; img-src 'self' data:; font-src 'self'; upgrade-insecure-requests");
  headers.set("referrer-policy", "strict-origin-when-cross-origin");
  headers.set("permissions-policy", "camera=(), geolocation=(), microphone=(), payment=()");
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-frame-options", "DENY");
  headers.set("strict-transport-security", "max-age=31536000; includeSubDomains");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
};

const addNoStoreHeaders = (response) => {
  const headers = new Headers(response.headers);
  headers.set("cache-control", "no-store");
  headers.set("cdn-cache-control", "no-store");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
};

const publicRepositoryUrl = (value) => {
  if (!value) return "";
  try {
    const url = new URL(String(value).trim());
    if (url.protocol !== "https:" || !url.hostname) return "";
    url.username = "";
    url.password = "";
    url.hash = "";
    return url.toString().replace(/\/$/, "");
  } catch (_) {
    return "";
  }
};

const injectHomeRuntimeConfig = async (response, env) => {
  const siteKey = String(env.TURNSTILE_SITE_KEY || "").trim();
  const repositoryUrl = publicRepositoryUrl(env.REPOSITORY_URL);
  if ((!siteKey && !repositoryUrl) || !(response.headers.get("content-type") || "").includes("text/html")) return response;

  if (typeof HTMLRewriter === "function") {
    return new HTMLRewriter()
      .on('meta[name="turnstile-site-key"]', {
        element(element) { element.setAttribute("content", siteKey); },
      })
      .on("a[data-repository-link]", {
        element(element) {
          if (repositoryUrl) {
            element.setAttribute("href", repositoryUrl);
            element.removeAttribute("hidden");
            element.removeAttribute("aria-hidden");
            element.removeAttribute("aria-disabled");
          } else {
            element.setAttribute("hidden", "");
            element.setAttribute("aria-hidden", "true");
            element.setAttribute("aria-disabled", "true");
          }
        },
      })
      .on("#repository-pending", {
        element(element) {
          if (repositoryUrl) element.setAttribute("hidden", "");
          else element.removeAttribute("hidden");
        },
      })
      .transform(response);
  }

  // Node-based tests and local non-Workers servers do not expose HTMLRewriter.
  // Keep the same behavior there while production uses the streaming rewriter.
  let html = await response.text();
  html = html.replace(/(<meta[^>]+name=["']turnstile-site-key["'][^>]+content=["'])[^"']*(["'])/i, `$1${siteKey.replace(/&/g, "&amp;").replace(/"/g, "&quot;")}$2`);
  if (repositoryUrl) {
    html = html.replace(/(<a[^>]+data-repository-link[^>]+)\s+hidden(?:=["'][^"']*["'])?/i, "$1");
    html = html.replace(/(<a[^>]+data-repository-link[^>]+href=["'])[^"']*(["'])/i, `$1${repositoryUrl}$2`);
    html = html.replace(/(<span[^>]*id=["']repository-pending["'][^>]*)(>)/i, "$1 hidden$2");
  }
  const headers = new Headers(response.headers);
  headers.delete("content-length");
  return new Response(html, { status: response.status, statusText: response.statusText, headers });
};

const originRequest = async (request, env, url) => {
  const origin = env.PUBLIC_ORIGIN || env.ORIGIN_BASE_URL || env.ORIGIN_URL;
  if (!origin) return jsonResponse(503, "Origin is not configured");
  let target;
  try {
    target = new URL(`${url.pathname}${url.search}`, origin);
  } catch (_) {
    return jsonResponse(500, "Origin configuration is invalid");
  }
  const headers = new Headers(request.headers);
  for (const name of [
    "host",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "cf-connecting-ip",
    "cf-ipcountry",
    "cf-ray",
    "cf-visitor",
    "cf-access-jwt-assertion",
    "cookie",
    "x-osak-client-ip",
    "x-osak-origin-secret",
    "x-osak-admin-access",
    "cf-access-client-id",
    "cf-access-client-secret",
  ]) headers.delete(name);
  const clientIP = request.headers.get("cf-connecting-ip");
  if (clientIP) {
    headers.set("x-osak-client-ip", clientIP);
    headers.set("x-forwarded-for", clientIP);
  }
  headers.set("x-forwarded-host", url.host);
  headers.set("x-forwarded-proto", url.protocol.replace(":", ""));
  headers.set("x-osak-origin-secret", env.ORIGIN_SHARED_SECRET || "");
  if (isAdminPath(url.pathname)) {
    // The origin trusts this internal header only after the Worker has checked
    // the Cloudflare Access service token. Never forward client identity claims.
    headers.delete("cf-access-client-id");
    headers.delete("cf-access-client-secret");
    headers.set("x-osak-admin-access", env.OSAK_ADMIN_ACCESS_TOKEN || "");
  }
  const body = request.method === "GET" || request.method === "HEAD" ? undefined : request.body;
  const requestInit = { method: request.method, headers, body, redirect: "manual" };
  if (body) requestInit.duplex = "half";
  const upstream = new Request(target, requestInit);
  // Return the upstream response directly: this keeps MCP/HTTP streaming bodies unbuffered.
  try {
    return addNoStoreHeaders(await fetch(upstream));
  } catch (_) {
    return jsonResponse(502, "Origin unavailable");
  }
};

const handleRequest = async (request, env) => {
  const url = new URL(request.url);
  if (isOriginPath(url.pathname)) {
    if (isAdminPath(url.pathname) && !(await adminServiceTokenValid(request, env))) {
      return jsonResponse(403, "Access denied");
    }
    return originRequest(request, env, url);
  }
  if (!env.ASSETS || typeof env.ASSETS.fetch !== "function") return jsonResponse(500, "Static assets are not configured");
  const assetResponse = await env.ASSETS.fetch(request);
  const configuredResponse = request.method === "GET" && isHomePath(url.pathname)
    ? await injectHomeRuntimeConfig(assetResponse, env)
    : assetResponse;
  return addStaticSecurityHeaders(configuredResponse);
};

export default { fetch: handleRequest };

export { addNoStoreHeaders, addStaticSecurityHeaders, constantTimeEqual, handleRequest, injectHomeRuntimeConfig, isOriginPath, publicRepositoryUrl };
