import { createHash } from "node:crypto";
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { bearerAuth, loadOAuthConfig, registerOAuthRoutes } from "./oauth.js";

const PUBLIC = "https://mcp.example.test";
const CALLBACK = "https://claude.ai/api/mcp/auth_callback";
const PASSWORD = "test-password-123456";

const env = {
  MCP_OAUTH_PUBLIC_URL: PUBLIC,
  MCP_OAUTH_PASSWORD: PASSWORD,
  MCP_OAUTH_SECRET: "x".repeat(40),
  MCP_OAUTH_USER: "owner",
} as NodeJS.ProcessEnv;

function makeApp() {
  const cfg = loadOAuthConfig(env)!;
  const app = new Hono();
  registerOAuthRoutes(app, cfg);
  app.use("/mcp", bearerAuth(cfg));
  app.post("/mcp", (c) => c.json({ ok: true }));
  return app;
}

const pkce = () => {
  const verifier = "v".repeat(60);
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
};

const form = (data: Record<string, string>) => ({
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams(data).toString(),
});

async function register(app: Hono, redirect = CALLBACK) {
  const res = await app.request("/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ redirect_uris: [redirect], client_name: "Claude" }),
  });
  return res;
}

async function authorize(app: Hono, clientId: string, challenge: string) {
  const query = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: CALLBACK,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "xyz",
  });
  const page = await app.request(`/authorize?${query}`);
  const html = await page.text();
  const req = /name="req" value="([^"]+)"/.exec(html)?.[1] ?? "";
  return { page, req };
}

async function login(app: Hono, req: string, password = PASSWORD, ip = "1.1.1.1") {
  const res = await app.request("/authorize", {
    ...form({ req, username: "owner", password }),
    headers: { "Content-Type": "application/x-www-form-urlencoded", "x-forwarded-for": ip },
  });
  return res;
}

async function fullFlow(app: Hono) {
  const { client_id: clientId } = (await (await register(app)).json()) as { client_id: string };
  const { verifier, challenge } = pkce();
  const { req } = await authorize(app, clientId, challenge);
  const done = await login(app, req);
  const location = new URL(done.headers.get("location") ?? "");
  const code = location.searchParams.get("code") ?? "";
  const token = await app.request(
    "/token",
    form({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      redirect_uri: CALLBACK,
      client_id: clientId,
    }),
  );
  return { clientId, verifier, code, location, token };
}

describe("loadOAuthConfig", () => {
  it("fails closed when settings are missing", () => {
    expect(() => loadOAuthConfig({} as NodeJS.ProcessEnv)).toThrow(/MCP_OAUTH/);
    expect(() => loadOAuthConfig({ ...env, MCP_OAUTH_SECRET: "short" })).toThrow(/32/);
    expect(() => loadOAuthConfig({ ...env, MCP_OAUTH_PASSWORD: "short" })).toThrow(/12/);
  });

  it("only runs open with an explicit opt-out", () => {
    expect(loadOAuthConfig({ MCP_AUTH_DISABLED: "1" } as NodeJS.ProcessEnv)).toBeNull();
  });
});

describe("metadata and protection", () => {
  it("publishes discovery documents", async () => {
    const app = makeApp();
    const resource = await (await app.request("/.well-known/oauth-protected-resource")).json();
    expect(resource).toMatchObject({ resource: `${PUBLIC}/mcp`, authorization_servers: [PUBLIC] });
    const server = await (await app.request("/.well-known/oauth-authorization-server")).json();
    expect(server).toMatchObject({
      issuer: PUBLIC,
      code_challenge_methods_supported: ["S256"],
      registration_endpoint: `${PUBLIC}/register`,
    });
  });

  it("rejects calls without a valid token and points to the metadata", async () => {
    const app = makeApp();
    const none = await app.request("/mcp", { method: "POST" });
    expect(none.status).toBe(401);
    expect(none.headers.get("www-authenticate")).toContain("resource_metadata=");
    const bad = await app.request("/mcp", {
      method: "POST",
      headers: { Authorization: "Bearer not-a-token" },
    });
    expect(bad.status).toBe(401);
    expect(bad.headers.get("www-authenticate")).toContain("invalid_token");
  });
});

describe("registration", () => {
  it("accepts the Claude callback and refuses foreign redirects", async () => {
    const app = makeApp();
    expect((await register(app)).status).toBe(201);
    expect((await register(app, "https://evil.example/cb")).status).toBe(400);
    expect((await register(app, "http://claude.ai/api/mcp/auth_callback")).status).toBe(400);
    expect((await register(app, "https://claude.ai.evil.example/x")).status).toBe(400);
  });
});

describe("authorization code flow with PKCE", () => {
  it("issues a token that opens /mcp and can be refreshed", async () => {
    const app = makeApp();
    const { location, token } = await fullFlow(app);
    expect(location.origin + location.pathname).toBe(CALLBACK);
    expect(location.searchParams.get("state")).toBe("xyz");
    expect(token.status).toBe(200);
    const body = (await token.json()) as { access_token: string; refresh_token: string };

    const ok = await app.request("/mcp", {
      method: "POST",
      headers: { Authorization: `Bearer ${body.access_token}` },
    });
    expect(ok.status).toBe(200);

    const refreshed = await app.request(
      "/token",
      form({ grant_type: "refresh_token", refresh_token: body.refresh_token }),
    );
    expect(refreshed.status).toBe(200);
  });

  it("rejects a reused code, a wrong verifier and tampered tokens", async () => {
    const app = makeApp();
    const first = await fullFlow(app);
    const reuse = await app.request(
      "/token",
      form({
        grant_type: "authorization_code",
        code: first.code,
        code_verifier: first.verifier,
        redirect_uri: CALLBACK,
        client_id: first.clientId,
      }),
    );
    expect(reuse.status).toBe(400);

    const { client_id: clientId } = (await (await register(app)).json()) as { client_id: string };
    const { challenge } = pkce();
    const { req } = await authorize(app, clientId, challenge);
    const done = await login(app, req);
    const code = new URL(done.headers.get("location") ?? "").searchParams.get("code") ?? "";
    const wrong = await app.request(
      "/token",
      form({
        grant_type: "authorization_code",
        code,
        code_verifier: "w".repeat(60),
        redirect_uri: CALLBACK,
        client_id: clientId,
      }),
    );
    expect(wrong.status).toBe(400);

    const body = (await first.token.json()) as { access_token: string };
    const tampered = `${body.access_token.slice(0, -2)}AA`;
    const res = await app.request("/mcp", {
      method: "POST",
      headers: { Authorization: `Bearer ${tampered}` },
    });
    expect(res.status).toBe(401);
  });

  it("does not accept a refresh token as an access token", async () => {
    const app = makeApp();
    const { token } = await fullFlow(app);
    const body = (await token.json()) as { refresh_token: string };
    const res = await app.request("/mcp", {
      method: "POST",
      headers: { Authorization: `Bearer ${body.refresh_token}` },
    });
    expect(res.status).toBe(401);
  });

  it("refuses to redirect to an unregistered URI", async () => {
    const app = makeApp();
    const { client_id: clientId } = (await (await register(app)).json()) as { client_id: string };
    const query = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: "https://evil.example/cb",
      code_challenge: "c",
      code_challenge_method: "S256",
    });
    const res = await app.request(`/authorize?${query}`);
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();
  });

  it("requires S256 PKCE", async () => {
    const app = makeApp();
    const { client_id: clientId } = (await (await register(app)).json()) as { client_id: string };
    const query = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: CALLBACK,
    });
    const res = await app.request(`/authorize?${query}`);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("error=invalid_request");
  });
});

describe("login", () => {
  it("rejects a wrong password and locks the address after repeated failures", async () => {
    const app = makeApp();
    const { client_id: clientId } = (await (await register(app)).json()) as { client_id: string };
    const { req } = await authorize(app, clientId, pkce().challenge);

    for (let i = 0; i < 5; i++) {
      const res = await login(app, req, "wrong-password-xx", "9.9.9.9");
      expect(res.status).toBe(401);
    }
    const locked = await login(app, req, PASSWORD, "9.9.9.9");
    expect(locked.status).toBe(429);

    const other = await login(app, req, PASSWORD, "8.8.8.8");
    expect(other.status).toBe(302);
  }, 15000);
});
