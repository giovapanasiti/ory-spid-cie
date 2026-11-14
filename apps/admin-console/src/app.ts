import { randomBytes } from "node:crypto";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import "@fastify/cookie";
import {
  AuditClient,
  Csrf,
  HttpError,
  HydraAdmin,
  IdentityServiceClient,
  KratosClient,
  Sealer,
  fastifyLoggerOptions,
  html,
  loaRank,
  oidcIdentifiers,
  originAllowed,
  raw,
  requestJson,
  type OAuth2Client,
  type SafeHtml,
} from "@iam/shared";
import { csp, layout, registerWebDefaults, sendHtml } from "@iam/ui";
import { BrokerAdmin } from "./broker.js";
import { OidcClient, type PendingAuth } from "./oidc.js";
import { ALL_ROLES, can, type Permission } from "./rbac.js";
import { registerFederation } from "./federation.js";

export interface AdminConfig {
  publicUrl: string;
  secureCookies: boolean;
  bootstrapEmails: string[];
  requiredLoA?: string;
  sessionTtlSeconds: number;
  /** Origin of the OIDC provider (logout form redirects there). */
  oidcIssuerOrigin: string;
  auditReadUrl?: string;
  auditReadToken?: string;
}

export interface AdminDeps {
  oidc: OidcClient;
  kratos: KratosClient;
  hydra: HydraAdmin;
  identity: IdentityServiceClient;
  broker: BrokerAdmin;
  audit: AuditClient;
  sealer: Sealer;
  csrf: Csrf;
}

export interface AdminSession {
  sid: string;
  sub: string;
  name: string;
  email?: string;
  loa?: string;
  authTime?: number;
  idToken: string;
}

export interface Ctx {
  session: AdminSession;
  roles: string[];
  actor: { id: string; roles: string[] };
  csrf: string;
}

declare module "fastify" {
  interface FastifyRequest {
    ctx?: Ctx;
  }
}

const SESSION = "admin_session";
const PENDING = "admin_oidc";

export function nav(ctx: Ctx): SafeHtml {
  const items: [string, string, Permission][] = [
    ["/", "Dashboard", "dashboard"],
    ["/users", "Utenti", "users.read"],
    ["/clients", "Client OAuth2", "clients.read"],
    ["/federation", "Federazione SPID/CIE", "federation.read"],
    ["/audit", "Audit", "audit.read"],
  ];
  return html`${items.filter(([, , p]) => can(ctx.roles, p)).map(([href, label]) => html`<a href="${href}">${label}</a>`)}
<span class="muted" style="color:#cfd8e3">${ctx.session.name} (${ctx.roles.join(", ")})</span>
<form method="post" action="/logout" style="display:inline"><input type="hidden" name="csrf" value="${ctx.csrf}"><button class="link" style="color:#fff">Esci</button></form>`;
}

export function adminPage(ctx: Ctx, title: string, body: SafeHtml): string {
  return layout({ title: `${title} · Admin`, body, nav: nav(ctx), brand: "IAM Admin" });
}

export function flash(reply: FastifyReply, msg: string, type: "success" | "error" = "success") {
  reply.setCookie("admin_flash", JSON.stringify({ msg, type }), { path: "/", httpOnly: true, sameSite: "strict", maxAge: 30 });
}

export function takeFlash(req: FastifyRequest, reply: FastifyReply): SafeHtml {
  const raw_ = req.cookies.admin_flash;
  if (!raw_) return html``;
  reply.clearCookie("admin_flash", { path: "/" });
  try {
    const f = JSON.parse(raw_) as { msg: string; type: string };
    return html`<div class="msg ${f.type === "error" ? "error" : "success"}" role="status">${f.msg}</div>`;
  } catch {
    return html``;
  }
}

export function csrfField(ctx: Ctx): SafeHtml {
  return html`<input type="hidden" name="csrf" value="${ctx.csrf}">`;
}

export function errMessage(err: unknown): string {
  if (err instanceof HttpError) {
    const d = err.body as { error?: string; message?: string } | undefined;
    return d?.error ?? d?.message ?? err.message;
  }
  return err instanceof Error ? err.message : String(err);
}

export async function buildApp(cfg: AdminConfig, d: AdminDeps, opts: { logger?: boolean } = {}): Promise<FastifyInstance> {
  const app = Fastify({ logger: opts.logger === false ? false : fastifyLoggerOptions("admin-console"), trustProxy: true, bodyLimit: 256 * 1024 });
  await registerWebDefaults(app, { secureCookies: cfg.secureCookies, defaultCsp: csp({ formAction: null }) });
  const cookieOpts = { path: "/", httpOnly: true, secure: cfg.secureCookies, sameSite: "lax" as const };

  // ------------------------------------------------------------ authentication
  app.get("/login", async (req, reply) => {
    const returnTo = String((req.query as Record<string, string>).return_to ?? "/");
    const { url, pending } = d.oidc.start(returnTo.startsWith("/") && !returnTo.startsWith("//") ? returnTo : "/");
    reply.setCookie(PENDING, d.sealer.seal(pending, "admin-oidc", 600), { ...cookieOpts, maxAge: 600 });
    return reply.redirect(url);
  });

  app.get("/callback", async (req, reply) => {
    const pending = d.sealer.open<PendingAuth>(req.cookies[PENDING], "admin-oidc");
    reply.clearCookie(PENDING, { path: "/" });
    let claims;
    let idToken;
    try {
      ({ claims, idToken } = await d.oidc.finish(req.query as Record<string, string>, pending));
    } catch (err) {
      d.audit.emit({ type: "admin.login", outcome: "failure", correlationId: req.id, context: { reason: errMessage(err) } });
      return sendHtml(reply, layout({ title: "Accesso negato", body: html`<div class="card"><h1>Accesso non riuscito</h1><p>${errMessage(err)}</p><a href="/login">Riprova</a></div>` }), 401);
    }
    const sub = String(claims.sub);
    const loa = typeof claims.loa === "string" ? claims.loa : undefined;
    if (cfg.requiredLoA && loaRank(loa) < loaRank(cfg.requiredLoA)) {
      d.audit.emit({ type: "admin.login", outcome: "failure", actor: sub, correlationId: req.id, context: { reason: "insufficient_assurance", loa } });
      return sendHtml(reply, layout({ title: "Accesso negato", body: html`<div class="card"><h1>Livello di autenticazione insufficiente</h1><p>La console richiede ${cfg.requiredLoA}.</p></div>` }), 403);
    }
    let roles = await d.identity.roles(sub);
    const email = typeof claims.email === "string" ? claims.email.toLowerCase() : undefined;
    if (!roles.length && email && claims.email_verified === true && cfg.bootstrapEmails.includes(email)) {
      const supers = (await d.identity.listRoles("superadmin")).length;
      if (supers === 0) {
        roles = await d.identity.setRoles(sub, ["superadmin"], "bootstrap");
        d.audit.emit({ type: "admin.bootstrap_superadmin", outcome: "success", actor: sub, correlationId: req.id });
      }
    }
    if (!roles.length) {
      d.audit.emit({ type: "admin.login", outcome: "failure", actor: sub, correlationId: req.id, context: { reason: "no_roles" } });
      return sendHtml(reply, layout({ title: "Accesso negato", body: html`<div class="card"><h1>Accesso negato</h1><p>Il tuo account non ha ruoli amministrativi.</p></div>` }), 403);
    }
    const session: AdminSession = {
      sid: randomBytes(16).toString("base64url"),
      sub,
      name: [claims.given_name, claims.family_name].filter(Boolean).join(" ") || email || sub,
      email,
      loa,
      authTime: typeof claims.auth_time === "number" ? claims.auth_time : undefined,
      idToken,
    };
    reply.setCookie(SESSION, d.sealer.seal(session, "admin-session", cfg.sessionTtlSeconds), { ...cookieOpts, sameSite: "strict", maxAge: cfg.sessionTtlSeconds });
    d.audit.emit({ type: "admin.login", outcome: "success", actor: sub, correlationId: req.id, context: { roles, loa } });
    return reply.redirect(pending?.returnTo ?? "/");
  });

  // Session + CSRF + Origin enforcement for everything else.
  app.addHook("preHandler", async (req, reply) => {
    const path = req.url.split("?")[0] ?? "";
    if (["/login", "/callback", "/healthz", "/logged-out"].includes(path) || path.startsWith("/assets/")) return;
    const session = d.sealer.open<AdminSession>(req.cookies[SESSION], "admin-session");
    if (!session) {
      if (req.method === "GET") return reply.redirect(`/login?return_to=${encodeURIComponent(req.url)}`);
      return reply.code(401).send({ error: "unauthenticated" });
    }
    const roles = await d.identity.roles(session.sub); // re-read on every request: revocation is immediate
    if (!roles.length) {
      reply.clearCookie(SESSION, { path: "/" });
      return reply.code(403).send("forbidden");
    }
    req.ctx = { session, roles, actor: { id: session.sub, roles }, csrf: d.csrf.issue(session.sid) };
    if (req.method !== "GET" && req.method !== "HEAD") {
      const body = (req.body ?? {}) as Record<string, unknown>;
      if (!originAllowed(req.headers, [cfg.publicUrl]) || !d.csrf.verify(session.sid, body.csrf)) {
        d.audit.emit({ type: "admin.csrf_rejected", outcome: "failure", actor: session.sub, correlationId: req.id, context: { path } });
        return reply.code(403).type("text/plain").send("CSRF validation failed");
      }
    }
  });

  const guard = (p: Permission) => async (req: FastifyRequest, reply: FastifyReply) => {
    if (!req.ctx || !can(req.ctx.roles, p)) {
      d.audit.emit({ type: "admin.access_denied", outcome: "failure", actor: req.ctx?.session.sub, correlationId: req.id, context: { permission: p, path: req.url.split("?")[0] } });
      return sendHtml(reply, layout({ title: "Non autorizzato", body: html`<div class="card"><h1>403 — permesso mancante</h1><p>Serve il permesso <code>${p}</code>.</p></div>`, nav: req.ctx ? nav(req.ctx) : undefined }), 403);
    }
  };

  app.post("/logout", async (req, reply) => {
    const s = req.ctx!.session;
    reply.clearCookie(SESSION, { path: "/" });
    d.audit.emit({ type: "admin.logout", outcome: "success", actor: s.sub, correlationId: req.id });
    return reply.redirect(d.oidc.endSessionUrl(s.idToken, `${cfg.publicUrl}/logged-out`));
  });
  app.get("/logged-out", async (_req, reply) => sendHtml(reply, layout({ title: "Disconnesso", body: html`<div class="card"><h1>Sei uscito</h1><a href="/login">Accedi di nuovo</a></div>` })));

  // ----------------------------------------------------------------- dashboard
  app.get("/", { preHandler: guard("dashboard") }, async (req, reply) => {
    const ctx = req.ctx!;
    let status: Record<string, unknown> | null = null;
    if (can(ctx.roles, "federation.read")) status = await d.broker.call<Record<string, unknown>>("GET", "/admin/status", ctx.actor).catch(() => null);
    const providers = (status?.providers as { display_name: string; profile: string; trusted: boolean; enabled: boolean; error?: string }[] | undefined) ?? [];
    const stats = (status?.auth_last_24h as Record<string, number> | undefined) ?? {};
    return sendHtml(
      reply,
      adminPage(
        ctx,
        "Dashboard",
        html`${takeFlash(req, reply)}<h1>Dashboard</h1>
<div class="grid2">
<div class="card"><h2>Utente</h2><p>${ctx.session.name}<br><span class="muted">LoA: ${ctx.session.loa ?? "n/d"} · ruoli: ${ctx.roles.join(", ")}</span></p></div>
${status
  ? html`<div class="card"><h2>Autenticazioni federate (24h)</h2>${Object.keys(stats).length ? html`<table>${Object.entries(stats).map(([k, v]) => html`<tr><td>${k}</td><td>${v}</td></tr>`)}</table>` : html`<p class="muted">Nessuna</p>`}</div>
<div class="card"><h2>Provider</h2><table>${providers.map((p) => html`<tr><td>${p.profile.toUpperCase()}</td><td>${p.display_name}</td><td>${!p.enabled ? html`<span class="badge">disabilitato</span>` : p.trusted ? html`<span class="badge ok">trusted</span>` : html`<span class="badge bad" title="${p.error ?? ""}">untrusted</span>`}</td></tr>`)}</table><p><a href="/federation">Dettagli federazione →</a></p></div>`
  : ""}
</div>`,
      ),
    );
  });

  // --------------------------------------------------------------------- users
  app.get("/users", { preHandler: guard("users.read") }, async (req, reply) => {
    const ctx = req.ctx!;
    const q = req.query as Record<string, string>;
    const term = (q.q ?? "").trim();
    let identities: Awaited<ReturnType<KratosClient["listIdentities"]>>["identities"];
    let next: string | undefined;
    let note = "";
    if (/^[0-9a-f-]{36}$/i.test(term)) {
      const one = await d.kratos.getIdentity(term);
      identities = one ? [one] : [];
    } else if (/^[A-Za-z]{6}[0-9LMNPQRSTUV]{2}[A-Za-z][0-9LMNPQRSTUV]{2}[A-Za-z][0-9LMNPQRSTUV]{3}[A-Za-z]$/.test(term) && can(ctx.roles, "users.attributes")) {
      const r = await d.identity.search("fiscal_number", term.toUpperCase());
      identities = (await Promise.all(r.map((id) => d.kratos.getIdentity(id)))).filter((x): x is NonNullable<typeof x> => !!x);
      note = "Ricerca per codice fiscale verificato (registrata in audit).";
      d.audit.emit({ type: "admin.identity_search", outcome: "success", actor: ctx.session.sub, correlationId: req.id, context: { by: "fiscal_number", results: identities.length } });
    } else {
      const r = await d.kratos.listIdentities({ credentialsIdentifier: term || undefined, pageToken: q.page_token, pageSize: 50 });
      identities = r.identities;
      next = r.next;
    }
    return sendHtml(
      reply,
      adminPage(
        ctx,
        "Utenti",
        html`<h1>Utenti</h1>
<form method="get" class="row card"><input type="search" name="q" value="${term}" placeholder="email, UUID${can(ctx.roles, "users.attributes") ? " o codice fiscale" : ""}" style="flex:1"><button>Cerca</button></form>
${note ? html`<div class="msg">${note}</div>` : ""}
<div class="card"><table><tr><th>ID</th><th>Email</th><th>Nome</th><th>Metodi</th><th>Stato</th><th>Creato</th></tr>
${identities.map(
  (i) => html`<tr><td><a href="/users/${i.id}"><code>${i.id.slice(0, 8)}…</code></a></td><td>${i.traits.email ?? "—"}</td><td>${[i.traits.name?.first, i.traits.name?.last].filter(Boolean).join(" ")}</td><td>${Object.keys(i.credentials ?? {}).join(", ")}</td><td>${i.state ?? ""}</td><td>${i.created_at?.slice(0, 10) ?? ""}</td></tr>`,
)}
</table>${next ? html`<p><a href="/users?page_token=${encodeURIComponent(next)}">Pagina successiva →</a></p>` : ""}</div>`,
      ),
    );
  });

  app.get("/users/:id", { preHandler: guard("users.read") }, async (req, reply) => {
    const ctx = req.ctx!;
    const id = (req.params as { id: string }).id;
    const identity = await d.kratos.getIdentity(id, ["oidc"]);
    if (!identity) return reply.code(404).send("not found");
    const [sessions, links, roles] = await Promise.all([d.kratos.identitySessions(id), d.identity.syncLinks(id).catch(() => []), d.identity.roles(id)]);
    const showAttrs = can(ctx.roles, "users.attributes");
    type Attrs = Awaited<ReturnType<IdentityServiceClient["verifiedAttributes"]>>;
    const attrs: Attrs = showAttrs ? await d.identity.verifiedAttributes(id).catch((): Attrs => ({})) : {};
    if (showAttrs) d.audit.emit({ type: "admin.identity_viewed", outcome: "success", actor: ctx.session.sub, correlationId: req.id, context: { identity_id: id } });
    const creds = identity.credentials ?? {};
    return sendHtml(
      reply,
      adminPage(
        ctx,
        "Utente",
        html`${takeFlash(req, reply)}<h1>Identità <code>${id}</code></h1>
<div class="grid2">
<div class="card"><h2>Profilo (tratti dichiarati)</h2><table>
<tr><th>Email</th><td>${identity.traits.email ?? "—"} ${identity.verifiable_addresses?.some((a) => a.verified) ? html`<span class="badge ok">verificata</span>` : html`<span class="badge warn">non verificata</span>`}</td></tr>
<tr><th>Nome</th><td>${identity.traits.name?.first ?? ""} ${identity.traits.name?.last ?? ""}</td></tr>
<tr><th>Stato</th><td>${identity.state}</td></tr><tr><th>Schema</th><td>${identity.schema_id}</td></tr></table></div>
<div class="card"><h2>Metodi di autenticazione</h2><table>${Object.entries(creds).map(
          ([k, c]) => html`<tr><td>${k}</td><td>${k === "oidc" ? oidcIdentifiers(identity).map((x) => html`<div>${x.provider.toUpperCase()} <code>${x.subject.slice(0, 10)}…</code></div>`) : (c.identifiers ?? []).map((x) => html`<div>${x}</div>`)}</td></tr>`,
        )}</table></div>
</div>
<div class="card"><h2>Identità federate collegate</h2><table><tr><th>Provider</th><th>Issuer</th><th>Stato</th><th>Ultimo LoA</th><th>Ultimo ACR</th><th>Ultimo accesso</th><th>Collegata</th></tr>
${links.map((l) => html`<tr><td>${l.provider.toUpperCase()}</td><td><code>${l.issuer}</code></td><td>${l.state}</td><td>${l.last_loa ?? ""}</td><td><code>${l.last_acr ?? ""}</code></td><td>${l.last_auth_at ?? ""}</td><td>${l.linked_at}</td></tr>`)}</table></div>
${showAttrs
  ? html`<div class="card"><h2>Attributi verificati (provenienza)</h2><table><tr><th>Attributo</th><th>Valore</th><th>Fonte</th><th>LoA</th><th>Verificato</th></tr>
${Object.entries(attrs).map(([k, v]) => html`<tr><td>${k}</td><td>${mask(k, v.value)}</td><td>${v.provider.toUpperCase()}</td><td>${v.loa}</td><td>${v.verified_at}</td></tr>`)}</table><p class="muted">I valori sensibili sono mascherati. Accesso registrato in audit.</p></div>`
  : ""}
<div class="card"><h2>Sessioni</h2><table><tr><th>ID</th><th>Attiva</th><th>Autenticata</th><th>Scadenza</th><th>AAL</th><th>Metodi</th><th>Dispositivo</th><th></th></tr>
${sessions.map(
  (s) => html`<tr><td><code>${s.id.slice(0, 8)}…</code></td><td>${s.active ? "sì" : "no"}</td><td>${s.authenticated_at ?? ""}</td><td>${s.expires_at ?? ""}</td><td>${s.authenticator_assurance_level ?? ""}</td><td>${(s.authentication_methods ?? []).map((m) => `${m.method}${m.provider ? ":" + m.provider : ""}`).join(", ")}</td><td class="muted">${s.devices?.[0]?.user_agent?.slice(0, 40) ?? ""}</td>
<td>${can(ctx.roles, "sessions.revoke") && s.active ? html`<form method="post" action="/users/${id}/sessions/${s.id}/revoke" data-confirm="Revocare questa sessione?">${csrfField(ctx)}<button class="danger">Revoca</button></form>` : ""}</td></tr>`,
)}</table>
${can(ctx.roles, "sessions.revoke") ? html`<form method="post" action="/users/${id}/sessions/revoke-all" data-confirm="Revocare TUTTE le sessioni e i consensi OAuth2 di questo utente?">${csrfField(ctx)}<button class="danger">Revoca tutte le sessioni e i token</button></form>` : ""}</div>
<div class="card"><h2>Ruoli amministrativi</h2>
${can(ctx.roles, "roles.manage")
  ? html`<form method="post" action="/users/${id}/roles" data-confirm="Confermi la modifica dei ruoli?">${csrfField(ctx)}<div class="row">${ALL_ROLES.map((r) => html`<label><input type="checkbox" name="roles" value="${r}"${roles.includes(r) ? raw(" checked") : ""}> ${r}</label>`)}</div><button>Salva ruoli</button></form>`
  : html`<p>${roles.join(", ") || "nessuno"}</p>`}</div>`,
      ),
    );
  });

  app.post("/users/:id/sessions/:sid/revoke", { preHandler: guard("sessions.revoke") }, async (req, reply) => {
    const { id, sid } = req.params as { id: string; sid: string };
    const s = await d.kratos.getSession(sid);
    if (!s || s.identity?.id !== id) return reply.code(404).send("not found");
    await d.kratos.revokeSession(sid);
    d.audit.emit({ type: "session.revoked", outcome: "success", actor: req.ctx!.session.sub, correlationId: req.id, context: { identity_id: id, session_id: sid, by: "admin" } });
    flash(reply, "Sessione revocata.");
    return reply.redirect(`/users/${id}`);
  });

  app.post("/users/:id/sessions/revoke-all", { preHandler: guard("sessions.revoke") }, async (req, reply) => {
    const { id } = req.params as { id: string };
    await d.kratos.revokeIdentitySessions(id);
    await d.hydra.revokeLoginSessions(id);
    await d.hydra.revokeConsentSessions(id); // also revokes issued access/refresh tokens
    d.audit.emit({ type: "session.revoked_all", outcome: "success", actor: req.ctx!.session.sub, correlationId: req.id, context: { identity_id: id, by: "admin" } });
    flash(reply, "Tutte le sessioni, i consensi e i token sono stati revocati.");
    return reply.redirect(`/users/${id}`);
  });

  app.post("/users/:id/roles", { preHandler: guard("roles.manage") }, async (req, reply) => {
    const { id } = req.params as { id: string };
    const b = req.body as Record<string, string | string[]>;
    const roles = [b.roles ?? []].flat().filter((r) => ALL_ROLES.includes(r));
    if (id === req.ctx!.session.sub && !roles.includes("superadmin")) {
      flash(reply, "Non puoi rimuovere il tuo ruolo superadmin.", "error");
      return reply.redirect(`/users/${id}`);
    }
    try {
      await d.identity.setRoles(id, roles, req.ctx!.session.sub);
      flash(reply, "Ruoli aggiornati.");
    } catch (err) {
      flash(reply, errMessage(err), "error");
    }
    return reply.redirect(`/users/${id}`);
  });

  // ------------------------------------------------------------- OAuth2 clients
  app.get("/clients", { preHandler: guard("clients.read") }, async (req, reply) => {
    const ctx = req.ctx!;
    const clients = await d.hydra.listClients();
    return sendHtml(
      reply,
      adminPage(
        ctx,
        "Client OAuth2",
        html`${takeFlash(req, reply)}<h1>Client OAuth2 / OIDC</h1>
${can(ctx.roles, "clients.write") ? html`<p><a class="btn" href="/clients/new">Registra nuova applicazione</a></p>` : ""}
<div class="card"><table><tr><th>Client ID</th><th>Nome</th><th>Tipo</th><th>Grant</th><th>Scope</th><th>Audience</th><th>LoA minimo</th><th></th></tr>
${clients.map(
  (c) => html`<tr><td><code>${c.client_id}</code></td><td>${c.client_name}</td><td>${c.token_endpoint_auth_method === "none" ? "pubblico" : "confidenziale"}</td><td>${(c.grant_types ?? []).join(", ")}</td><td>${c.scope}</td><td>${(c.audience ?? []).join(", ")}</td><td>${String(c.metadata?.min_loa ?? "—")}</td>
<td>${can(ctx.roles, "clients.write") ? html`<form method="post" action="/clients/${encodeURIComponent(c.client_id ?? "")}/delete" data-confirm="Eliminare definitivamente il client ${c.client_id}?">${csrfField(ctx)}<button class="danger">Elimina</button></form>` : ""}</td></tr>`,
)}</table><p class="muted">I client secret non vengono mai mostrati dopo la creazione.</p></div>`,
      ),
    );
  });

  app.get("/clients/new", { preHandler: guard("clients.write") }, async (req, reply) => {
    const ctx = req.ctx!;
    return sendHtml(
      reply,
      adminPage(
        ctx,
        "Nuovo client",
        html`<h1>Registra applicazione</h1><form method="post" action="/clients" class="card">${csrfField(ctx)}
<label>Nome</label><input type="text" name="client_name" required maxlength="100">
<label>Tipo</label><select name="kind"><option value="confidential">Confidenziale (server-side, client_secret_basic)</option><option value="public">Pubblico (SPA/mobile, PKCE obbligatorio)</option><option value="machine">Machine-to-machine (client_credentials)</option></select>
<label>Redirect URI (una per riga, nessuna wildcard)</label><textarea name="redirect_uris"></textarea>
<label>Post-logout redirect URI (una per riga)</label><textarea name="post_logout_redirect_uris"></textarea>
<label>Scope consentiti</label><input type="text" name="scope" value="openid offline_access profile email">
<label>Audience (API) consentite, separate da spazio</label><input type="text" name="audience" value="">
<label>LoA minimo richiesto</label><select name="min_loa"><option value="">nessuno</option><option>urn:iam:loa:low</option><option>urn:iam:loa:substantial</option><option>urn:iam:loa:high</option></select>
<label><input type="checkbox" name="skip_consent" value="true"> Applicazione di prima parte (salta consenso)</label>
<p><button>Crea client</button></p></form>`,
      ),
    );
  });

  app.post("/clients", { preHandler: guard("clients.write") }, async (req, reply) => {
    const ctx = req.ctx!;
    const b = req.body as Record<string, string>;
    const lines = (s: string | undefined) => (s ?? "").split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
    const redirects = lines(b.redirect_uris);
    const bad = [...redirects, ...lines(b.post_logout_redirect_uris)].find((u) => u.includes("*") || !/^https?:\/\//.test(u) || (/^http:/.test(u) && !/^http:\/\/(localhost|127\.0\.0\.1)(:|\/)/.test(u)));
    if (bad) {
      flash(reply, `Redirect URI non valida: ${bad} (wildcard e http non-locale non ammessi)`, "error");
      return reply.redirect("/clients/new");
    }
    const kind = b.kind;
    const c: OAuth2Client = {
      client_name: (b.client_name ?? "").slice(0, 100),
      scope: (b.scope ?? "").split(/\s+/).filter((s) => /^[a-z0-9_.:-]+$/i.test(s)).join(" "),
      audience: (b.audience ?? "").split(/\s+/).filter(Boolean),
      metadata: b.min_loa ? { min_loa: b.min_loa } : {},
      skip_consent: b.skip_consent === "true",
    };
    if (kind === "machine") {
      Object.assign(c, { grant_types: ["client_credentials"], response_types: [], token_endpoint_auth_method: "client_secret_basic" });
    } else {
      if (!redirects.length) {
        flash(reply, "Almeno una redirect URI è obbligatoria.", "error");
        return reply.redirect("/clients/new");
      }
      Object.assign(c, {
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        redirect_uris: redirects,
        post_logout_redirect_uris: lines(b.post_logout_redirect_uris),
        token_endpoint_auth_method: kind === "public" ? "none" : "client_secret_basic",
      });
    }
    try {
      const created = await d.hydra.createClient(c);
      d.audit.emit({ type: "client.created", outcome: "success", actor: ctx.session.sub, correlationId: req.id, context: { client_id: created.client_id, kind, grant_types: created.grant_types } });
      return sendHtml(
        reply,
        adminPage(
          ctx,
          "Client creato",
          html`<h1>Client creato</h1><div class="card"><p>Client ID: <code>${created.client_id}</code></p>
${created.client_secret ? html`<div class="msg warn"><strong>Client secret (mostrato una sola volta):</strong><pre>${created.client_secret}</pre>Conservalo in un secrets manager. Non sarà più visualizzabile.</div>` : html`<p>Client pubblico: nessun secret, usare PKCE.</p>`}
<a href="/clients">Torna all'elenco</a></div>`,
        ),
      );
    } catch (err) {
      flash(reply, `Creazione fallita: ${errMessage(err)}`, "error");
      return reply.redirect("/clients/new");
    }
  });

  app.post("/clients/:id/delete", { preHandler: guard("clients.write") }, async (req, reply) => {
    const id = (req.params as { id: string }).id;
    await d.hydra.deleteClient(id);
    d.audit.emit({ type: "client.deleted", outcome: "success", actor: req.ctx!.session.sub, correlationId: req.id, context: { client_id: id } });
    flash(reply, `Client ${id} eliminato.`);
    return reply.redirect("/clients");
  });

  // ---------------------------------------------------------------------- audit
  app.get("/audit", { preHandler: guard("audit.read") }, async (req, reply) => {
    const ctx = req.ctx!;
    const q = req.query as Record<string, string>;
    let events: { id: string; timestamp: string; type: string; outcome: string; actor?: string; service: string; correlation_id?: string; context?: unknown }[] = [];
    let error = "";
    if (cfg.auditReadUrl && cfg.auditReadToken) {
      const u = new URL(cfg.auditReadUrl.replace(/\/$/, "") + "/events");
      for (const k of ["type", "actor", "outcome", "service", "correlation_id"]) if (q[k]) u.searchParams.set(k, q[k]!);
      u.searchParams.set("limit", "200");
      try {
        events = (await requestJson<typeof events>(u.toString(), { headers: { authorization: `Bearer ${cfg.auditReadToken}` } })).data;
      } catch (err) {
        error = errMessage(err);
      }
    }
    return sendHtml(
      reply,
      adminPage(
        ctx,
        "Audit",
        html`<h1>Eventi di audit</h1>
<form method="get" class="card row"><input type="text" name="type" placeholder="tipo (prefisso), es. login." value="${q.type ?? ""}"><input type="text" name="actor" placeholder="actor" value="${q.actor ?? ""}">
<select name="outcome"><option value="">esito</option><option${q.outcome === "success" ? raw(" selected") : ""}>success</option><option${q.outcome === "failure" ? raw(" selected") : ""}>failure</option></select>
<input type="text" name="correlation_id" placeholder="correlation id" value="${q.correlation_id ?? ""}"><button>Filtra</button>
<a href="/audit?type=login.failure">Fallimenti login</a> · <a href="/audit?type=federation.">Federazione</a> · <a href="/audit?type=admin.">Admin</a> · <a href="/audit?type=key.">Chiavi</a></form>
${error ? html`<div class="msg error">${error}</div>` : ""}
<div class="card"><table><tr><th>Quando</th><th>Tipo</th><th>Esito</th><th>Servizio</th><th>Actor</th><th>Contesto</th></tr>
${events.map((e) => html`<tr><td>${e.timestamp}</td><td><code>${e.type}</code></td><td>${e.outcome === "success" ? html`<span class="badge ok">ok</span>` : html`<span class="badge bad">fail</span>`}</td><td>${e.service}</td><td><code>${(e.actor ?? "").slice(0, 12)}</code></td><td><code>${JSON.stringify(e.context ?? {}).slice(0, 300)}</code></td></tr>`)}
</table></div>`,
      ),
    );
  });

  await registerFederation(app, d, guard);
  return app;
}

function mask(name: string, v: unknown): string {
  const s = typeof v === "string" ? v : JSON.stringify(v);
  if (name === "fiscal_number" && s.length > 6) return s.slice(0, 3) + "*".repeat(s.length - 6) + s.slice(-3);
  if (name === "email") return s.replace(/^(.).*(@.*)$/, "$1***$2");
  if (name === "phone_number" && s.length > 4) return "*".repeat(s.length - 4) + s.slice(-4);
  if (name === "birthdate") return s.slice(0, 4) + "-**-**";
  return s;
}
