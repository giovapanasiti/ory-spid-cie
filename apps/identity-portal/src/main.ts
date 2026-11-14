import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import "@fastify/cookie";
import {
  AuditClient,
  Csrf,
  IdentityServiceClient,
  KratosClient,
  bool,
  createLogger,
  fastifyLoggerOptions,
  html,
  loadConfig,
  oidcIdentifiers,
  originAllowed,
  port,
  secret,
  z,
  type KratosSession,
} from "@iam/shared";
import { csp, layout, registerWebDefaults, sendHtml } from "@iam/ui";

/** End-user account portal: profile, verified attributes, linked methods, sessions. */
const c = loadConfig(
  z.object({
    PORT: port(3200),
    PUBLIC_URL: z.string().url(),
    LOGIN_UI_URL: z.string().url(),
    KRATOS_PUBLIC_URL: z.string().url(),
    KRATOS_BROWSER_URL: z.string().url(),
    KRATOS_ADMIN_URL: z.string().url(),
    IDENTITY_SERVICE_URL: z.string().url(),
    IDENTITY_SERVICE_TOKEN: secret(32),
    CSRF_SECRET: secret(32),
    SECURE_COOKIES: bool(true),
    AUDIT_URL: z.string().optional(),
    AUDIT_TOKEN: z.string().optional(),
  }),
);
const log = createLogger("identity-portal");
const publicUrl = c.PUBLIC_URL.replace(/\/$/, "");
const kratos = new KratosClient(c.KRATOS_PUBLIC_URL, c.KRATOS_ADMIN_URL, c.KRATOS_BROWSER_URL);
const identity = new IdentityServiceClient(c.IDENTITY_SERVICE_URL, c.IDENTITY_SERVICE_TOKEN);
const audit = new AuditClient(c.AUDIT_URL, c.AUDIT_TOKEN, "identity-portal", log);
const csrf = new Csrf(c.CSRF_SECRET);

const app = Fastify({ logger: fastifyLoggerOptions("identity-portal"), trustProxy: true });
await registerWebDefaults(app, { secureCookies: c.SECURE_COOKIES, defaultCsp: csp({ formAction: null }) });

async function requireSession(req: FastifyRequest, reply: FastifyReply): Promise<KratosSession | null> {
  const s = await kratos.whoami(req.headers.cookie);
  if (!s?.active || !s.identity) {
    await reply.redirect(kratos.browserFlowUrl("login", { return_to: publicUrl + req.url }));
    return null;
  }
  return s;
}

const nav = (token: string) =>
  html`<a href="/">Il mio account</a><a href="${c.LOGIN_UI_URL.replace(/\/$/, "")}/auth/settings">Impostazioni e sicurezza</a>
<form method="post" action="/logout" style="display:inline"><input type="hidden" name="csrf" value="${token}"><button class="link" style="color:#fff">Esci</button></form>`;

app.get("/", async (req, reply) => {
  const s = await requireSession(req, reply);
  if (!s) return;
  const id = s.identity!.id;
  const [full, links, attrs, others] = await Promise.all([
    kratos.getIdentity(id, ["oidc"]),
    identity.syncLinks(id).catch(() => []),
    identity.verifiedAttributes(id).catch(() => ({}) as Awaited<ReturnType<typeof identity.verifiedAttributes>>),
    kratos.mySessions(req.headers.cookie!).catch(() => [] as KratosSession[]),
  ]);
  const creds = Object.keys(full?.credentials ?? {});
  const federated = full ? oidcIdentifiers(full) : [];
  const methodCount = creds.filter((k) => k !== "oidc").length + federated.length;
  const token = csrf.issue(s.id);
  const flashMsg = (req.query as Record<string, string>).done;
  return sendHtml(
    reply,
    layout({
      title: "Il mio account",
      brand: "Area personale",
      nav: nav(token),
      body: html`${flashMsg ? html`<div class="msg success">Operazione completata.</div>` : ""}
<h1>Il mio account</h1>
<div class="grid2">
<div class="card"><h2>Profilo</h2><table>
<tr><th>Email</th><td>${s.identity!.traits.email ?? "—"}</td></tr>
<tr><th>Nome</th><td>${s.identity!.traits.name?.first ?? ""} ${s.identity!.traits.name?.last ?? ""}</td></tr>
<tr><th>Identificativo</th><td><code>${id}</code></td></tr></table>
<p><a href="${c.LOGIN_UI_URL.replace(/\/$/, "")}/auth/settings">Modifica profilo, password e passkey →</a></p></div>
<div class="card"><h2>Dati verificati</h2>${Object.keys(attrs).length
        ? html`<table>${Object.entries(attrs).map(([k, v]) => html`<tr><th>${k}</th><td>${String(v.value)}</td><td class="muted">${v.provider.toUpperCase()} · ${v.loa.split(":").pop()} · ${v.verified_at.slice(0, 10)}</td></tr>`)}</table><p class="muted">Dati forniti dal gestore dell'identità; non modificabili dall'utente.</p>`
        : html`<p class="muted">Nessun dato verificato. Collega SPID o CIE per verificare la tua identità.</p>`}</div>
</div>
<div class="card"><h2>Metodi di accesso</h2><table>
${creds.filter((k) => k !== "oidc").map((k) => html`<tr><td>${k === "password" ? "Password" : k === "passkey" ? "Passkey" : k}</td><td><span class="badge ok">attivo</span></td></tr>`)}
${links.map((l) => html`<tr><td>${l.provider.toUpperCase()} <span class="muted"><code>${l.issuer}</code></span></td><td>${l.state === "active" ? html`<span class="badge ok">collegato</span>` : html`<span class="badge">scollegato</span>`} <span class="muted">ultimo accesso ${l.last_auth_at ?? "—"} · ${l.last_loa ?? ""}</span></td></tr>`)}
</table>
${methodCount <= 1 ? html`<div class="msg warn">Hai un solo metodo di accesso: non può essere rimosso finché non ne aggiungi un altro (protezione contro il blocco dell'account).</div>` : ""}
<p><a class="btn secondary" href="${c.LOGIN_UI_URL.replace(/\/$/, "")}/auth/settings">Collega SPID / CIE o gestisci i metodi</a></p>
<p class="muted">Per collegare un'identità è richiesta una ri-autenticazione recente. Un'identità SPID/CIE può essere collegata a un solo account.</p></div>
<div class="card"><h2>Sessioni attive</h2><table><tr><th>Sessione</th><th>Autenticata</th><th>Metodi</th><th>Dispositivo</th><th></th></tr>
<tr><td><code>${s.id.slice(0, 8)}…</code> <span class="badge ok">corrente</span></td><td>${s.authenticated_at ?? ""}</td><td>${(s.authentication_methods ?? []).map((m) => m.provider ?? m.method).join(", ")}</td><td class="muted">${s.devices?.[0]?.user_agent?.slice(0, 50) ?? ""}</td><td></td></tr>
${others.map((o) => html`<tr><td><code>${o.id.slice(0, 8)}…</code></td><td>${o.authenticated_at ?? ""}</td><td>${(o.authentication_methods ?? []).map((m) => m.provider ?? m.method).join(", ")}</td><td class="muted">${o.devices?.[0]?.user_agent?.slice(0, 50) ?? ""}</td>
<td><form method="post" action="/sessions/${o.id}/revoke"><input type="hidden" name="csrf" value="${token}"><button class="danger">Disconnetti</button></form></td></tr>`)}
</table>${others.length ? html`<form method="post" action="/sessions/revoke-others"><input type="hidden" name="csrf" value="${token}"><button class="danger">Disconnetti tutte le altre sessioni</button></form>` : ""}</div>`,
    }),
  );
});

async function checkPost(req: FastifyRequest, reply: FastifyReply): Promise<KratosSession | null> {
  const s = await kratos.whoami(req.headers.cookie);
  const body = (req.body ?? {}) as Record<string, string>;
  if (!s?.active || !originAllowed(req.headers, [publicUrl]) || !csrf.verify(s.id, body.csrf)) {
    await reply.code(403).send("CSRF validation failed");
    return null;
  }
  return s;
}

app.post("/sessions/:id/revoke", async (req, reply) => {
  const s = await checkPost(req, reply);
  if (!s) return;
  const id = (req.params as { id: string }).id;
  await kratos.revokeMySession(req.headers.cookie!, id);
  audit.emit({ type: "session.revoked", outcome: "success", actor: s.identity?.id, correlationId: req.id, context: { session_id: id, by: "user" } });
  return reply.redirect("/?done=1");
});

app.post("/sessions/revoke-others", async (req, reply) => {
  const s = await checkPost(req, reply);
  if (!s) return;
  await kratos.revokeMyOtherSessions(req.headers.cookie!);
  audit.emit({ type: "session.revoked_others", outcome: "success", actor: s.identity?.id, correlationId: req.id });
  return reply.redirect("/?done=1");
});

app.post("/logout", async (req, reply) => {
  const s = await checkPost(req, reply);
  if (!s) return;
  const url = await kratos.logoutUrl(req.headers.cookie, publicUrl);
  return reply.redirect(url ?? "/");
});

app.listen({ host: "0.0.0.0", port: c.PORT }).catch((err) => {
  log.error({ err: String(err) }, "fatal");
  process.exit(1);
});
