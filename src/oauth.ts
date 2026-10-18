import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Context, Env, Hono, MiddlewareHandler } from "hono";

// Minimal single-user OAuth 2.1 authorization server for the HTTP transport.
//
// Claude.ai custom connectors can only authenticate with OAuth (authorization code + PKCE,
// dynamic client registration), so the MCP server embeds a small authorization server.
// Everything is stateless: clients, authorization requests, codes and tokens are HMAC-signed
// blobs, so a container restart does not log anybody out. Rotating MCP_OAUTH_SECRET revokes
// every client, code and token at once.

export interface OAuthConfig {
  publicUrl: string;
  secret: Buffer;
  username: string;
  passwordDigest: Buffer;
  allowedRedirects: string[];
  accessTtl: number;
  refreshTtl: number;
}

type TokenType = "client" | "req" | "code" | "access" | "refresh";

interface Claims {
  typ: TokenType;
  exp: number;
  [key: string]: unknown;
}

const DEFAULT_REDIRECTS = [
  "https://claude.ai/",
  "https://claude.com/",
  "http://localhost",
  "http://127.0.0.1",
];
const MAX_FAILURES_PER_IP = 5;
const MAX_FAILURES_GLOBAL = 30;
const LOCKOUT_MS = 15 * 60 * 1000;

const sha256 = (value: string) => createHash("sha256").update(value).digest();

const safeEqual = (a: Buffer, b: Buffer) => a.length === b.length && timingSafeEqual(a, b);

const now = () => Math.floor(Date.now() / 1000);

export function loadOAuthConfig(env: NodeJS.ProcessEnv): OAuthConfig | null {
  if (env.MCP_AUTH_DISABLED === "1") return null;

  const publicUrl = env.MCP_OAUTH_PUBLIC_URL?.trim().replace(/\/+$/, "");
  const password = env.MCP_OAUTH_PASSWORD;
  const secret = env.MCP_OAUTH_SECRET;
  if (!publicUrl || !password || !secret) {
    throw new Error(
      "HTTP mode requires MCP_OAUTH_PUBLIC_URL, MCP_OAUTH_PASSWORD and MCP_OAUTH_SECRET " +
        "(or MCP_AUTH_DISABLED=1 to run without authentication)",
    );
  }
  if (!/^https?:\/\//.test(publicUrl)) {
    throw new Error("MCP_OAUTH_PUBLIC_URL must start with http:// or https://");
  }
  if (secret.length < 32) {
    throw new Error("MCP_OAUTH_SECRET must be at least 32 characters");
  }
  if (password.length < 12) {
    throw new Error("MCP_OAUTH_PASSWORD must be at least 12 characters");
  }

  const extra = (env.MCP_OAUTH_ALLOWED_REDIRECTS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

  return {
    publicUrl,
    secret: Buffer.from(secret),
    username: env.MCP_OAUTH_USER?.trim() || "admin",
    passwordDigest: sha256(password),
    allowedRedirects: [...DEFAULT_REDIRECTS, ...extra],
    accessTtl: Number(env.MCP_OAUTH_ACCESS_TTL) || 60 * 60,
    refreshTtl: Number(env.MCP_OAUTH_REFRESH_TTL) || 30 * 24 * 60 * 60,
  };
}

function sign(cfg: OAuthConfig, typ: TokenType, data: Record<string, unknown>, ttl: number) {
  const claims: Claims = { ...data, typ, exp: now() + ttl };
  const body = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const mac = createHmac("sha256", cfg.secret).update(body).digest("base64url");
  return `${body}.${mac}`;
}

function verify(cfg: OAuthConfig, token: string | undefined, typ: TokenType): Claims | null {
  if (!token) return null;
  const [body, mac, extra] = token.split(".");
  if (!body || !mac || extra !== undefined) return null;
  const expected = createHmac("sha256", cfg.secret).update(body).digest();
  if (!safeEqual(Buffer.from(mac, "base64url"), expected)) return null;
  try {
    const claims = JSON.parse(Buffer.from(body, "base64url").toString()) as Claims;
    if (claims.typ !== typ || typeof claims.exp !== "number" || claims.exp < now()) return null;
    return claims;
  } catch {
    return null;
  }
}

function redirectAllowed(cfg: OAuthConfig, uri: string): boolean {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  if (url.hash || url.username || url.password) return false;
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) return false;
  return cfg.allowedRedirects.some((prefix) => {
    if (prefix.startsWith("http://localhost") || prefix.startsWith("http://127.0.0.1")) {
      return loopback && uri.startsWith(prefix);
    }
    return uri.startsWith(prefix);
  });
}

const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);

function loginPage(clientName: string, redirectHost: string, req: string, error?: string) {
  return `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dokploy MCP</title>
<style>
body{font:16px system-ui,sans-serif;background:#111;color:#eee;display:grid;place-items:center;min-height:100vh;margin:0}
form{background:#1b1b1b;padding:28px;border-radius:12px;width:min(360px,90vw);display:grid;gap:12px}
h1{font-size:18px;margin:0}p{margin:0;color:#aaa;font-size:14px}
input,button{font:inherit;padding:10px;border-radius:8px;border:1px solid #444;background:#222;color:#eee}
button{background:#3b82f6;border-color:#3b82f6;cursor:pointer}.err{color:#f87171}
</style></head><body>
<form method="post" action="/authorize">
<h1>Dokploy MCP</h1>
<p><b>${escapeHtml(clientName)}</b> (${escapeHtml(redirectHost)}) quiere acceder al servidor MCP de Dokploy.</p>
${error ? `<p class="err">${escapeHtml(error)}</p>` : ""}
<input type="hidden" name="req" value="${escapeHtml(req)}">
<input name="username" autocomplete="username" placeholder="Usuario" required>
<input name="password" type="password" autocomplete="current-password" placeholder="Contraseña" required>
<button type="submit">Autorizar</button>
</form></body></html>`;
}

const htmlHeaders = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
  "X-Frame-Options": "DENY",
};

function oauthError(c: Context, error: string, description: string, status: 400 | 401 = 400) {
  c.header("Cache-Control", "no-store");
  return c.json({ error, error_description: description }, status);
}

function clientIp(c: Context): string {
  const forwarded = c.req.header("x-forwarded-for");
  if (!forwarded) return "unknown";
  // Our reverse proxy appends the real peer address last; earlier entries are client-supplied.
  return forwarded.split(",").at(-1)?.trim() || "unknown";
}

export function bearerAuth(cfg: OAuthConfig): MiddlewareHandler {
  const metadata = `${cfg.publicUrl}/.well-known/oauth-protected-resource`;
  return async (c, next) => {
    const header = c.req.header("authorization") ?? "";
    const token = header.toLowerCase().startsWith("bearer ") ? header.slice(7).trim() : undefined;
    const claims = verify(cfg, token, "access");
    if (!claims || claims.aud !== `${cfg.publicUrl}/mcp`) {
      const detail = token ? ', error="invalid_token"' : "";
      c.header("WWW-Authenticate", `Bearer resource_metadata="${metadata}"${detail}`);
      return c.json({ error: "unauthorized" }, 401);
    }
    await next();
    return undefined;
  };
}

export function registerOAuthRoutes<E extends Env>(app: Hono<E>, cfg: OAuthConfig) {
  const failures = new Map<string, { count: number; until: number }>();
  let globalFailures = { count: 0, until: 0 };

  const locked = (ip: string) => {
    const t = Date.now();
    const entry = failures.get(ip);
    if (entry && entry.until > t && entry.count >= MAX_FAILURES_PER_IP) return true;
    return globalFailures.until > t && globalFailures.count >= MAX_FAILURES_GLOBAL;
  };
  const recordFailure = (ip: string) => {
    const t = Date.now();
    const entry = failures.get(ip);
    const count = entry && entry.until > t ? entry.count + 1 : 1;
    failures.set(ip, { count, until: t + LOCKOUT_MS });
    globalFailures = {
      count: globalFailures.until > t ? globalFailures.count + 1 : 1,
      until: t + LOCKOUT_MS,
    };
  };

  const resourceMetadata = () => ({
    resource: `${cfg.publicUrl}/mcp`,
    authorization_servers: [cfg.publicUrl],
    bearer_methods_supported: ["header"],
  });
  app.get("/.well-known/oauth-protected-resource", (c) => c.json(resourceMetadata()));
  app.get("/.well-known/oauth-protected-resource/mcp", (c) => c.json(resourceMetadata()));

  app.get("/.well-known/oauth-authorization-server", (c) =>
    c.json({
      issuer: cfg.publicUrl,
      authorization_endpoint: `${cfg.publicUrl}/authorize`,
      token_endpoint: `${cfg.publicUrl}/token`,
      registration_endpoint: `${cfg.publicUrl}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
    }),
  );

  // Dynamic client registration (RFC 7591). The client is a signed blob of its redirect URIs.
  app.post("/register", async (c) => {
    let body: { redirect_uris?: unknown; client_name?: unknown };
    try {
      const text = await c.req.text();
      if (text.length > 8192) return oauthError(c, "invalid_client_metadata", "Body too large");
      body = JSON.parse(text);
    } catch {
      return oauthError(c, "invalid_client_metadata", "Invalid JSON body");
    }
    const uris = body.redirect_uris;
    if (
      !Array.isArray(uris) ||
      uris.length === 0 ||
      uris.length > 5 ||
      !uris.every((uri) => typeof uri === "string" && redirectAllowed(cfg, uri))
    ) {
      return oauthError(c, "invalid_redirect_uri", "redirect_uris not allowed for this server");
    }
    const name =
      typeof body.client_name === "string" ? body.client_name.slice(0, 80) : "MCP client";
    const clientId = sign(cfg, "client", { uris, name }, 365 * 24 * 60 * 60);
    c.header("Cache-Control", "no-store");
    return c.json(
      {
        client_id: clientId,
        client_name: name,
        redirect_uris: uris,
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      },
      201,
    );
  });

  // Step 1: validate the authorization request and show the login form.
  app.get("/authorize", (c) => {
    const q = c.req.query();
    const client = verify(cfg, q.client_id, "client");
    const uris = (client?.uris as string[] | undefined) ?? [];
    const redirectUri = q.redirect_uri;
    // Never redirect to an unvalidated URI: show the error here instead.
    if (!client || !redirectUri || !uris.includes(redirectUri)) {
      return c.text("Invalid client_id or redirect_uri", 400);
    }
    const redirectError = (error: string) => {
      const url = new URL(redirectUri);
      url.searchParams.set("error", error);
      if (q.state) url.searchParams.set("state", q.state);
      return c.redirect(url.toString(), 302);
    };
    if (q.response_type !== "code") return redirectError("unsupported_response_type");
    if (!q.code_challenge || q.code_challenge_method !== "S256") {
      return redirectError("invalid_request");
    }
    const req = sign(
      cfg,
      "req",
      { cid: q.client_id, ruri: q.redirect_uri, cc: q.code_challenge, state: q.state ?? null },
      10 * 60,
    );
    return new Response(loginPage(String(client.name), new URL(redirectUri).host, req), {
      headers: htmlHeaders,
    });
  });

  // Step 2: check the credentials and hand the code back to the client.
  app.post("/authorize", async (c) => {
    const form = await c.req.parseBody();
    const req = typeof form.req === "string" ? form.req : "";
    const claims = verify(cfg, req, "req");
    if (!claims) return c.text("Authorization request expired, start again", 400);
    const client = verify(cfg, String(claims.cid), "client");
    if (!client) return c.text("Invalid client", 400);

    const ip = clientIp(c);
    const page = (message: string, status: 401 | 429) =>
      new Response(
        loginPage(String(client.name), new URL(String(claims.ruri)).host, req, message),
        { status, headers: htmlHeaders },
      );
    if (locked(ip)) return page("Demasiados intentos. Espera unos minutos.", 429);

    const userOk = safeEqual(sha256(String(form.username ?? "")), sha256(cfg.username));
    const passOk = safeEqual(sha256(String(form.password ?? "")), cfg.passwordDigest);
    if (!(userOk && passOk)) {
      recordFailure(ip);
      await new Promise((resolve) => setTimeout(resolve, 400));
      return page("Usuario o contraseña incorrectos.", 401);
    }

    const code = sign(
      cfg,
      "code",
      { cid: claims.cid, ruri: claims.ruri, cc: claims.cc, jti: randomBytes(8).toString("hex") },
      60,
    );
    const url = new URL(String(claims.ruri));
    url.searchParams.set("code", code);
    if (claims.state) url.searchParams.set("state", String(claims.state));
    return c.redirect(url.toString(), 302);
  });

  const usedCodes = new Map<string, number>();

  const issueTokens = (clientId: string) => ({
    access_token: sign(
      cfg,
      "access",
      { aud: `${cfg.publicUrl}/mcp`, cid: clientId },
      cfg.accessTtl,
    ),
    token_type: "Bearer",
    expires_in: cfg.accessTtl,
    refresh_token: sign(cfg, "refresh", { cid: clientId }, cfg.refreshTtl),
  });

  app.post("/token", async (c) => {
    const form = await c.req.parseBody();
    const get = (key: string) => (typeof form[key] === "string" ? (form[key] as string) : "");
    c.header("Cache-Control", "no-store");

    if (get("grant_type") === "authorization_code") {
      const claims = verify(cfg, get("code"), "code");
      if (!claims) return oauthError(c, "invalid_grant", "Invalid or expired code");
      if (claims.cid !== get("client_id") || claims.ruri !== get("redirect_uri")) {
        return oauthError(c, "invalid_grant", "client_id or redirect_uri mismatch");
      }
      const challenge = createHash("sha256").update(get("code_verifier")).digest("base64url");
      if (
        !get("code_verifier") ||
        !safeEqual(Buffer.from(challenge), Buffer.from(String(claims.cc)))
      ) {
        return oauthError(c, "invalid_grant", "PKCE verification failed");
      }
      const jti = String(claims.jti);
      for (const [id, exp] of usedCodes) if (exp < now()) usedCodes.delete(id);
      if (usedCodes.has(jti)) return oauthError(c, "invalid_grant", "Code already used");
      usedCodes.set(jti, Number(claims.exp));
      return c.json(issueTokens(String(claims.cid)));
    }

    if (get("grant_type") === "refresh_token") {
      const claims = verify(cfg, get("refresh_token"), "refresh");
      if (!claims || (get("client_id") && claims.cid !== get("client_id"))) {
        return oauthError(c, "invalid_grant", "Invalid or expired refresh token");
      }
      return c.json(issueTokens(String(claims.cid)));
    }

    return oauthError(c, "unsupported_grant_type", "Use authorization_code or refresh_token");
  });
}
