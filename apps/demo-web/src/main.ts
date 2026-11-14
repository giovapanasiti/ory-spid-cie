import { randomBytes } from "node:crypto";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import "@fastify/cookie";
import * as client from "openid-client";
import { decodeJwt } from "jose";
import { Csrf, bool, createLogger, fastifyLoggerOptions, html, loadConfig, originAllowed, port, requestJson, secret, z, type SafeHtml } from "@iam/shared";
import { csp, layout, registerWebDefaults, sendHtml } from "@iam/ui";

/**
 * Demo Relying Party for the platform (Hydra as OpenID Provider) using
 * openid-client: Authorization Code + PKCE, state, nonce, refresh token
 * rotation, revocation, RP-initiated logout and step-up authentication.
 * Sessions are kept in memory (single-replica demo only).
 */
const c = loadConfig(
  z.object({
    PORT: port(5555),
    PUBLIC_URL: z.string().url(),
    OIDC_ISSUER: z.string().url(),
    OIDC_INTERNAL_URL: z.string().url(),
    OIDC_CLIENT_ID: z.string().min(1),
    OIDC_CLIENT_SECRET: secret(16),
    API_URL: z.string().url(),
    API_AUDIENCE: z.string().default("demo-api"),
    CSRF_SECRET: secret(32),
    SECURE_COOKIES: bool(true),
    ALLOW_INSECURE_HTTP: bool(false),
  }),
);
const log = createLogger("demo-web");
const publicUrl = c.PUBLIC_URL.replace(/\/$/, "");
const issuerOrigin = new URL(c.OIDC_ISSUER).origin;
const internalOrigin = new URL(c.OIDC_INTERNAL_URL).origin;
const csrf = new Csrf(c.CSRF_SECRET);
const SCOPE = "openid offline_access profile email fiscal_number profile.read";

interface Session {
  pending?: { state: string; nonce: string; verifier: string; stepUp: boolean };
  tokens?: { access_token: string; refresh_token?: string; id_token?: string; expires_at?: number };
  claims?: Record<string, unknown>;
  refreshCount: number;
  lastResult?: { title: string; status: number; body: unknown; header?: string };
}
const sessions = new Map<string, Session>();

let configPromise: Promise<client.Configuration> | undefined;
async function oidcConfig(): Promise<client.Configuration> {
  configPromise ??= (async () => {
    // Discovery is fetched server-to-server; the issuer (public URL) is kept as-is and validated.
    const md = (await requestJson<client.ServerMetadata>(`${c.OIDC_INTERNAL_URL.replace(/\/$/, "")}/.well-known/openid-configuration`)).data;
    if (md.issuer !== c.OIDC_ISSUER) throw new Error(`issuer mismatch: ${md.issuer}`);
    const cfg = new client.Configuration(md, c.OIDC_CLIENT_ID, undefined, client.ClientSecretBasic(c.OIDC_CLIENT_SECRET));
    cfg[client.customFetch] = (url: string, options: client.CustomFetchOptions) => {
      const u = new URL(url);
      const target = u.origin === issuerOrigin ? internalOrigin + u.pathname + u.search : url;
      return fetch(target, options as RequestInit);
    };
    if (c.ALLOW_INSECURE_HTTP) client.allowInsecureRequests(cfg);
    return cfg;
  })().catch((err) => {
    configPromise = undefined;
    throw err;
  });
  return configPromise;
}

const app = Fastify({ logger: fastifyLoggerOptions("demo-web"), trustProxy: true });
await registerWebDefaults(app, { secureCookies: c.SECURE_COOKIES, defaultCsp: csp({ formAction: null }) });

function session(req: FastifyRequest, reply: FastifyReply): { sid: string; s: Session } {
  let sid = req.cookies.demo_sid;
  if (!sid || !sessions.has(sid)) {
    sid = randomBytes(24).toString("base64url");
    sessions.set(sid, { refreshCount: 0 });
    reply.setCookie("demo_sid", sid, { path: "/", httpOnly: true, secure: c.SECURE_COOKIES, sameSite: "lax", maxAge: 86400 });
  }
  return { sid, s: sessions.get(sid)! };
}

function claimsTable(obj: Record<string, unknown>): SafeHtml {
  return html`<table>${Object.entries(obj).map(([k, v]) => html`<tr><th>${k}</th><td><code>${typeof v === "object" ? JSON.stringify(v) : String(v)}</code></td></tr>`)}</table>`;
}

app.get("/", async (req, reply) => {
  const { sid, s } = session(req, reply);
  const token = csrf.issue(sid);
  const form = (action: string, label: string, cls = "") =>
    html`<form method="post" action="${action}" style="display:inline"><input type="hidden" name="csrf" value="${token}"><button class="${cls}">${label}</button></form>`;
  const at = s.tokens ? (decodeJwt(s.tokens.access_token) as Record<string, unknown>) : undefined;
  const body = s.tokens
    ? html`<h1>Benvenuto ${String(s.claims?.given_name ?? s.claims?.sub ?? "")}</h1>
<div class="grid2"><div class="card"><h2>ID token (claims verificati)</h2>${claimsTable(s.claims ?? {})}</div>
<div class="card"><h2>Access token (estensioni)</h2><p class="muted">Decodificato solo per visualizzazione; l'API lo valida in modo indipendente.</p>${claimsTable({ aud: at?.aud, scp: at?.scp, exp: at?.exp, ext: at?.ext })}
<p>Refresh token: ${s.tokens.refresh_token ? "presente" : "assente"} · rotazioni effettuate: ${s.refreshCount}</p></div></div>
<div class="card"><h2>API protetta</h2><div class="row">${form("/call/profile", "GET /api/profile")}${form("/call/sensitive", "GET /api/sensitive (LoA alto, ≤5 min)")}${form("/call/public", "GET /api/public", "secondary")}</div>
${s.lastResult ? html`<h3>${s.lastResult.title} → ${s.lastResult.status}</h3>${s.lastResult.header ? html`<p><code>WWW-Authenticate: ${s.lastResult.header}</code></p>` : ""}<pre>${JSON.stringify(s.lastResult.body, null, 2)}</pre>
${s.lastResult.header?.includes("insufficient_user_authentication") ? html`<p><a class="btn" href="/login?level=high">Esegui step-up con SPID/CIE (livello alto)</a></p>` : ""}` : ""}</div>
<div class="card row">${form("/refresh", "Rinnova token (rotazione)", "secondary")}${form("/logout", "Esci", "danger")}</div>`
    : html`<h1>Applicazione demo</h1><div class="card"><p>Questa applicazione usa la piattaforma IAM tramite OpenID Connect (Hydra).</p>
<p class="row"><a class="btn" href="/login">Accedi</a><a class="btn secondary" href="/login?level=high">Accedi con SPID/CIE livello alto</a></p></div>`;
  return sendHtml(reply, layout({ title: "Demo RP", brand: "Demo App", body }));
});

app.get("/login", async (req, reply) => {
  const { s } = session(req, reply);
  const stepUp = (req.query as Record<string, string>).level === "high";
  const cfg = await oidcConfig();
  const verifier = client.randomPKCECodeVerifier();
  s.pending = { state: client.randomState(), nonce: client.randomNonce(), verifier, stepUp };
  const params: Record<string, string> = {
    redirect_uri: `${publicUrl}/callback`,
    scope: SCOPE,
    audience: c.API_AUDIENCE,
    state: s.pending.state,
    nonce: s.pending.nonce,
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: "S256",
  };
  if (stepUp) Object.assign(params, { acr_values: "urn:iam:loa:high", prompt: "login consent", max_age: "0" });
  return reply.redirect(client.buildAuthorizationUrl(cfg, params).toString());
});

app.get("/callback", async (req, reply) => {
  const { s } = session(req, reply);
  const p = s.pending;
  s.pending = undefined;
  if (!p) return reply.code(400).send("no pending authentication");
  const cfg = await oidcConfig();
  const current = new URL(req.url, publicUrl);
  if (current.searchParams.get("error")) {
    return sendHtml(reply, layout({ title: "Errore", body: html`<div class="card"><h1>Accesso non completato</h1><p><code>${current.searchParams.get("error")}</code>: ${current.searchParams.get("error_description") ?? ""}</p><a href="/">Torna alla home</a></div>` }), 400);
  }
  try {
    const tokens = await client.authorizationCodeGrant(cfg, current, { pkceCodeVerifier: p.verifier, expectedState: p.state, expectedNonce: p.nonce, idTokenExpected: true });
    const claims = tokens.claims() as Record<string, unknown> | undefined;
    if (p.stepUp && claims?.loa !== "urn:iam:loa:high") throw new Error(`step-up not satisfied (loa=${String(claims?.loa)})`);
    s.tokens = { access_token: tokens.access_token, refresh_token: tokens.refresh_token, id_token: tokens.id_token, expires_at: Date.now() + (tokens.expires_in ?? 0) * 1000 };
    s.claims = claims;
    s.lastResult = undefined;
    return reply.redirect("/");
  } catch (err) {
    log.warn({ err: String(err) }, "callback failed");
    return sendHtml(reply, layout({ title: "Errore", body: html`<div class="card"><h1>Validazione fallita</h1><p>${String(err)}</p><a href="/">Torna alla home</a></div>` }), 400);
  }
});

async function guardPost(req: FastifyRequest, reply: FastifyReply): Promise<Session | null> {
  const { sid, s } = session(req, reply);
  if (!originAllowed(req.headers, [publicUrl]) || !csrf.verify(sid, (req.body as Record<string, string>)?.csrf)) {
    await reply.code(403).send("CSRF validation failed");
    return null;
  }
  return s;
}

app.post("/call/:name", async (req, reply) => {
  const s = await guardPost(req, reply);
  if (!s) return;
  const name = (req.params as { name: string }).name;
  if (!["profile", "sensitive", "public"].includes(name)) return reply.code(404).send();
  const res = await fetch(`${c.API_URL.replace(/\/$/, "")}/api/${name}`, {
    headers: s.tokens ? { authorization: `Bearer ${s.tokens.access_token}` } : {},
    signal: AbortSignal.timeout(20000),
  });
  s.lastResult = { title: `GET /api/${name}`, status: res.status, body: await res.json().catch(() => null), header: res.headers.get("www-authenticate") ?? undefined };
  return reply.redirect("/");
});

app.post("/refresh", async (req, reply) => {
  const s = await guardPost(req, reply);
  if (!s?.tokens?.refresh_token) return reply.redirect("/");
  const cfg = await oidcConfig();
  try {
    const old = s.tokens.refresh_token;
    const t = await client.refreshTokenGrant(cfg, old);
    s.tokens = { access_token: t.access_token, refresh_token: t.refresh_token ?? old, id_token: t.id_token ?? s.tokens.id_token, expires_at: Date.now() + (t.expires_in ?? 0) * 1000 };
    s.refreshCount++;
    s.lastResult = { title: "Refresh token grant", status: 200, body: { rotated: !!t.refresh_token && t.refresh_token !== old } };
  } catch (err) {
    s.lastResult = { title: "Refresh token grant", status: 400, body: { error: String(err) } };
  }
  return reply.redirect("/");
});

app.post("/logout", async (req, reply) => {
  const s = await guardPost(req, reply);
  if (!s) return;
  const cfg = await oidcConfig();
  const idToken = s.tokens?.id_token;
  if (s.tokens?.refresh_token) await client.tokenRevocation(cfg, s.tokens.refresh_token).catch(() => undefined);
  s.tokens = undefined;
  s.claims = undefined;
  if (!idToken) return reply.redirect("/");
  return reply.redirect(client.buildEndSessionUrl(cfg, { id_token_hint: idToken, post_logout_redirect_uri: `${publicUrl}/` }).toString());
});

app.listen({ host: "0.0.0.0", port: c.PORT }).catch((err) => {
  log.error({ err: String(err) }, "fatal");
  process.exit(1);
});
