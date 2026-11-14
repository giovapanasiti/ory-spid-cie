import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import "@fastify/cookie";
import {
  AuditClient,
  Csrf,
  HydraAdmin,
  IdentityServiceClient,
  KratosClient,
  Sealer,
  fastifyLoggerOptions,
  html,
  loaRank,
  originAllowed,
  raw,
  type FlowKind,
  type KratosSession,
  type SelfServiceFlow,
} from "@iam/shared";
import { csp, layout, registerWebDefaults, renderFlow, scriptNodes, sendHtml } from "@iam/ui";
import { buildSessionClaims, type LoginContext } from "./claims.js";
import { decideLogin, parseRequestUrl } from "./policy.js";

export interface AppConfig {
  publicUrl: string;
  kratosBrowserUrl: string;
  secureCookies: boolean;
  rememberLoginSeconds: number;
  rememberConsentSeconds: number;
  /** Extra allowed origins for Origin checks (none by default). */
  allowedOrigins: string[];
}

export interface Deps {
  kratos: KratosClient;
  hydra: HydraAdmin;
  identity: IdentityServiceClient;
  audit: AuditClient;
  csrf: Csrf;
  sealer: Sealer;
}

const REAUTH_COOKIE = "lc_reauth";

/** Friendly texts for broker reason codes surfaced by Kratos after an upstream error. */
const REASONS: Record<string, string> = {
  cancelled: "Autenticazione annullata dall'utente. / Authentication cancelled.",
  insufficient_assurance: "Il livello di autenticazione ottenuto non è sufficiente. / Insufficient authentication assurance.",
  missing_attributes: "Il gestore dell'identità non ha fornito gli attributi necessari. / Required attributes missing.",
  provider_unavailable: "Il gestore dell'identità non è disponibile. / Identity provider unavailable.",
  federation_untrusted: "Impossibile stabilire la fiducia federativa con il gestore. / Federation trust could not be established.",
  flow_expired: "La sessione di autenticazione è scaduta. / Authentication session expired.",
  replay_detected: "Richiesta non valida o già utilizzata. / Invalid or replayed request.",
  invalid_response: "Risposta non valida dal gestore dell'identità. / Invalid identity provider response.",
  configuration_error: "Il servizio di autenticazione non è configurato correttamente. / Authentication service misconfiguration.",
  profile_disabled: "Questo metodo di accesso è momentaneamente disabilitato. / This sign-in method is disabled.",
};

export function friendly(text: string): string {
  for (const [code, msg] of Object.entries(REASONS)) if (text.includes(code)) return msg;
  return text;
}

export async function buildApp(cfg: AppConfig, d: Deps, opts: { logger?: boolean } = {}): Promise<FastifyInstance> {
  const app = Fastify({
    logger: opts.logger === false ? false : fastifyLoggerOptions("login-consent"),
    trustProxy: true,
    requestIdHeader: "x-correlation-id",
  });
  const kratosOrigin = new URL(cfg.kratosBrowserUrl).origin;
  // Kratos flows post to Kratos and redirect to external IdPs: form-action is left
  // unrestricted on those pages (browsers apply it to redirects); scripts limited to self + Kratos.
  const flowCsp = (nonces: string[]) =>
    csp({ scriptSrc: [kratosOrigin, ...nonces.map((n) => `'nonce-${n}'`)], connectSrc: [kratosOrigin] }).replace(/; form-action [^;]+/, "");
  // The authorization server's forms (consent, logout, Kratos flows) redirect to Hydra and
  // to registered client origins; browsers apply form-action to redirects, so it is omitted here.
  await registerWebDefaults(app, { secureCookies: cfg.secureCookies, defaultCsp: csp({ formAction: null }) });
  const allowedOrigins = [cfg.publicUrl, ...cfg.allowedOrigins];

  const cookieHeader = (req: FastifyRequest) => req.headers.cookie;
  const page = (title: string, body: ReturnType<typeof html>, scripts: Parameters<typeof layout>[0]["scripts"] = []) =>
    layout({ title, body, narrow: true, brand: "Accesso", scripts });
  const errorPage = (reply: FastifyReply, status: number, message: string) =>
    sendHtml(reply, page("Errore", html`<div class="card"><h1>Si è verificato un problema</h1><div class="msg error">${message}</div><p class="muted">Riferimento: ${reply.request.id}</p></div>`), status);

  // --------------------------------------------------------------- Hydra login
  app.get("/login", async (req, reply) => {
    const challenge = String((req.query as Record<string, string>).login_challenge ?? "");
    if (!challenge || challenge.length > 4096) return errorPage(reply, 400, "Richiesta di accesso non valida.");
    let lr;
    try {
      lr = await d.hydra.getLoginRequest(challenge);
    } catch {
      return errorPage(reply, 400, "La richiesta di accesso è scaduta o non è valida.");
    }
    const params = parseRequestUrl(lr.request_url, lr.oidc_context?.acr_values, lr.client.metadata?.min_loa);
    const session = await d.kratos.whoami(cookieHeader(req));
    const marker = d.sealer.open<{ c: string; at: number }>(req.cookies[REAUTH_COOKIE], "reauth");
    let assurance: Awaited<ReturnType<IdentityServiceClient["resolveAssurance"]>> | undefined;
    if (session?.active && session.identity) {
      try {
        assurance = await d.identity.resolveAssurance(
          { identity_id: session.identity.id, session_id: session.id, authenticated_at: session.authenticated_at, authentication_methods: session.authentication_methods ?? [] },
          req.id,
        );
      } catch (err) {
        req.log.warn({ err: String(err) }, "assurance resolution failed");
        const r = await d.hydra.rejectLogin(challenge, "access_denied", "account_conflict");
        d.audit.emit({ type: "login.failure", outcome: "failure", actor: session.identity.id, correlationId: req.id, context: { client_id: lr.client.client_id, reason: "assurance_conflict" } });
        return reply.redirect(r.redirect_to);
      }
    }
    const decision = decideLogin({
      params,
      session,
      sessionLoA: assurance?.loa,
      reauthStartedAt: marker?.c === challenge ? marker.at : undefined,
      hydraSkip: lr.skip,
      hydraSubject: lr.subject,
      now: Date.now(),
    });
    if (decision.action === "reject") {
      d.audit.emit({ type: "login.failure", outcome: "failure", actor: session?.identity?.id, correlationId: req.id, context: { client_id: lr.client.client_id, reason: decision.description } });
      const r = await d.hydra.rejectLogin(challenge, decision.error, decision.description);
      return reply.redirect(r.redirect_to);
    }
    if (decision.action === "authenticate") {
      reply.setCookie(REAUTH_COOKIE, d.sealer.seal({ c: challenge, at: Date.now() }, "reauth", 900), {
        path: "/", httpOnly: true, secure: cfg.secureCookies, sameSite: "lax", maxAge: 900,
      });
      const returnTo = `${cfg.publicUrl}/login?login_challenge=${encodeURIComponent(challenge)}`;
      return reply.redirect(d.kratos.browserFlowUrl("login", { return_to: returnTo, refresh: decision.refresh ? "true" : undefined }));
    }
    // accept
    const s = session as KratosSession & { identity: NonNullable<KratosSession["identity"]> };
    const a = assurance!;
    const context: LoginContext = {
      loa: a.loa, amr: a.amr, provider: a.provider, federated_acr: a.federated_acr, auth_time: a.auth_time ?? s.authenticated_at ?? null,
      identity_verified: a.identity_verified, kratos_session_id: s.id,
    };
    const r = await d.hydra.acceptLogin(challenge, {
      subject: s.identity.id,
      remember: true,
      remember_for: cfg.rememberLoginSeconds,
      acr: a.loa,
      amr: a.amr,
      context: context as unknown as Record<string, unknown>,
      identity_provider_session_id: s.id,
    });
    reply.clearCookie(REAUTH_COOKIE, { path: "/" });
    d.audit.emit({
      type: a.provider ? `login.success.${a.provider}` : "login.success",
      outcome: "success",
      actor: s.identity.id,
      correlationId: req.id,
      context: { client_id: lr.client.client_id, loa: a.loa, amr: a.amr, provider: a.provider, required_loa: params.requiredLoA },
    });
    return reply.redirect(r.redirect_to);
  });

  // ------------------------------------------------------------- Hydra consent
  app.get("/consent", async (req, reply) => {
    const challenge = String((req.query as Record<string, string>).consent_challenge ?? "");
    let cr;
    try {
      cr = await d.hydra.getConsentRequest(challenge);
    } catch {
      return errorPage(reply, 400, "La richiesta di consenso è scaduta o non è valida.");
    }
    const minLoA = cr.client?.metadata?.min_loa;
    if (typeof minLoA === "string" && loaRank(cr.acr) < loaRank(minLoA)) {
      const r = await d.hydra.rejectConsent(challenge, "access_denied", "insufficient_assurance");
      return reply.redirect(r.redirect_to);
    }
    if (cr.skip || cr.client?.skip_consent) return reply.redirect(await acceptConsent(challenge, cr.requested_scope ?? [], req.id));
    const token = d.csrf.issue(`consent:${challenge}`);
    const scopes = cr.requested_scope ?? [];
    return sendHtml(
      reply,
      page(
        "Consenso",
        html`<div class="card"><h1>Autorizza ${cr.client?.client_name || cr.client?.client_id}</h1>
<p>L'applicazione richiede l'accesso a:</p>
<form method="post" action="/consent" class="stack">
<input type="hidden" name="challenge" value="${challenge}"><input type="hidden" name="csrf" value="${token}">
${scopes.map((s) => html`<label><input type="checkbox" name="grant_scope" value="${s}" checked${s === "openid" ? raw(" disabled") : ""}> ${scopeLabel(s)}</label>`)}
<input type="hidden" name="grant_scope" value="openid">
<div class="row"><button type="submit" name="action" value="accept">Consenti</button><button type="submit" name="action" value="deny" class="secondary">Nega</button></div>
</form></div>`,
      ),
    );
  });

  app.post("/consent", async (req, reply) => {
    const b = req.body as Record<string, string | string[]>;
    const challenge = String(b.challenge ?? "");
    if (!originAllowed(req.headers, allowedOrigins) || !d.csrf.verify(`consent:${challenge}`, b.csrf)) {
      return errorPage(reply, 403, "Richiesta non valida (CSRF).");
    }
    if (b.action !== "accept") {
      const r = await d.hydra.rejectConsent(challenge, "access_denied", "user denied consent");
      d.audit.emit({ type: "consent.denied", outcome: "failure", correlationId: req.id });
      return reply.redirect(r.redirect_to);
    }
    const cr = await d.hydra.getConsentRequest(challenge);
    const requested = cr.requested_scope ?? [];
    const granted = [...new Set([b.grant_scope ?? []].flat())].filter((s) => requested.includes(s));
    return reply.redirect(await acceptConsent(challenge, granted, req.id));
  });

  async function acceptConsent(challenge: string, scopes: string[], correlationId: string): Promise<string> {
    const cr = await d.hydra.getConsentRequest(challenge);
    const ctx = (cr.context ?? {}) as unknown as LoginContext;
    const subject = cr.subject ?? "";
    const [identity, verifiedRaw] = await Promise.all([
      d.kratos.getIdentity(subject),
      d.identity.verifiedAttributes(subject).catch(() => ({}) as Record<string, { value: unknown }>),
    ]);
    const verified: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(verifiedRaw)) verified[k] = v.value;
    const session = buildSessionClaims(scopes, identity, verified, { ...ctx, loa: ctx.loa ?? cr.acr ?? "urn:iam:loa:none", amr: ctx.amr ?? cr.amr ?? [] });
    const r = await d.hydra.acceptConsent(challenge, {
      grant_scope: scopes,
      grant_access_token_audience: cr.requested_access_token_audience ?? [],
      remember: !cr.client?.skip_consent,
      remember_for: cfg.rememberConsentSeconds,
      session,
    });
    d.audit.emit({ type: "consent.granted", outcome: "success", actor: subject, correlationId, context: { client_id: cr.client?.client_id, scopes } });
    return r.redirect_to;
  }

  // -------------------------------------------------------------- Hydra logout
  app.get("/logout", async (req, reply) => {
    const challenge = String((req.query as Record<string, string>).logout_challenge ?? "");
    try {
      await d.hydra.getLogoutRequest(challenge);
    } catch {
      return errorPage(reply, 400, "Richiesta di logout non valida.");
    }
    const token = d.csrf.issue(`logout:${challenge}`);
    return sendHtml(
      reply,
      page(
        "Esci",
        html`<div class="card"><h1>Vuoi uscire?</h1><p>Verrai disconnesso da tutte le applicazioni della piattaforma.</p>
<form method="post" action="/logout" class="row"><input type="hidden" name="challenge" value="${challenge}"><input type="hidden" name="csrf" value="${token}">
<button type="submit" name="action" value="accept">Esci</button><button type="submit" name="action" value="deny" class="secondary">Annulla</button></form></div>`,
      ),
    );
  });

  app.post("/logout", async (req, reply) => {
    const b = req.body as Record<string, string>;
    const challenge = String(b.challenge ?? "");
    if (!originAllowed(req.headers, allowedOrigins) || !d.csrf.verify(`logout:${challenge}`, b.csrf)) {
      return errorPage(reply, 403, "Richiesta non valida (CSRF).");
    }
    if (b.action !== "accept") {
      await d.hydra.rejectLogout(challenge);
      return sendHtml(reply, page("Esci", html`<div class="card"><p>Logout annullato. Puoi chiudere questa pagina.</p></div>`));
    }
    const lr = await d.hydra.getLogoutRequest(challenge);
    const r = await d.hydra.acceptLogout(challenge);
    d.audit.emit({ type: "logout", outcome: "success", actor: lr.subject, correlationId: req.id, context: { client_id: lr.client?.client_id } });
    // Also terminate the Kratos session, then continue to Hydra.
    const kratosLogout = await d.kratos.logoutUrl(req.headers.cookie, r.redirect_to);
    return reply.redirect(kratosLogout ?? r.redirect_to);
  });

  // ----------------------------------------------------- Kratos self-service UI
  const flowPage = (kind: FlowKind, title: string) =>
    async function (req: FastifyRequest, reply: FastifyReply) {
      const q = req.query as Record<string, string>;
      if (!q.flow) {
        const params: Record<string, string | undefined> = { return_to: q.return_to, refresh: q.refresh, aal: q.aal };
        return reply.redirect(d.kratos.browserFlowUrl(kind, params));
      }
      const flow = await d.kratos.getFlow(kind, q.flow, req.headers.cookie);
      if ("error" in flow) {
        // Expired / foreign flow: start a new one.
        return reply.redirect(d.kratos.browserFlowUrl(kind));
      }
      const policy = await loginPolicy(flow);
      for (const m of flow.ui.messages ?? []) m.text = friendly(m.text);
      const scripts = scriptNodes(flow.ui);
      reply.cspOverride = flowCsp(scripts.map((s) => s.nonce).filter((n): n is string => !!n));
      const links =
        kind === "login"
          ? html`<p class="muted"><a href="/auth/registration">Crea un account</a> · <a href="/auth/recovery">Password dimenticata?</a></p>`
          : kind === "registration"
            ? html`<p class="muted">Hai già un account? <a href="/auth/login">Accedi</a></p>`
            : html``;
      return sendHtml(
        reply,
        page(
          title,
          html`<div class="card"><h1>${title}</h1>
${policy.notice ? html`<div class="msg warn">${policy.notice}</div>` : ""}
${renderFlow(flow.ui, { groups: policy.groups, providers: policy.providers, oidcHidden: policy.oidcHidden })}
${links}</div>`,
          scripts,
        ),
      );
    };

  /** For Hydra-initiated logins requiring assurance, only federated methods meeting it are offered. */
  async function loginPolicy(flow: SelfServiceFlow): Promise<{ groups?: string[]; providers?: string[]; oidcHidden?: Record<string, string>; notice?: string }> {
    const challenge = (() => {
      try {
        return flow.return_to ? new URL(flow.return_to).searchParams.get("login_challenge") : null;
      } catch {
        return null;
      }
    })() ?? flow.oauth2_login_challenge ?? null;
    if (!challenge) return {};
    try {
      const lr = await d.hydra.getLoginRequest(challenge);
      const p = parseRequestUrl(lr.request_url, lr.oidc_context?.acr_values, lr.client.metadata?.min_loa);
      if (!p.requiredLoA || loaRank(p.requiredLoA) <= 0) return {};
      const allowed = Array.isArray(lr.client.metadata?.allowed_providers) ? (lr.client.metadata!.allowed_providers as string[]) : ["spid", "cie"];
      return {
        groups: ["oidc"],
        providers: allowed,
        oidcHidden: { "upstream_parameters.acr_values": p.requiredLoA },
        notice: `Questa operazione richiede un'autenticazione con livello ${p.requiredLoA.split(":").pop()} (SPID/CIE).`,
      };
    } catch {
      return {};
    }
  }

  app.get("/auth/login", flowPage("login", "Accedi"));
  app.get("/auth/registration", flowPage("registration", "Registrati"));
  app.get("/auth/recovery", flowPage("recovery", "Recupero account"));
  app.get("/auth/verification", flowPage("verification", "Verifica email"));
  app.get("/auth/settings", flowPage("settings", "Impostazioni account"));
  app.get("/auth/error", async (req, reply) => {
    const id = String((req.query as Record<string, string>).id ?? "");
    const e = id ? ((await d.kratos.getError(id)) as { error?: { message?: string; reason?: string } } | undefined) : undefined;
    const text = friendly(e?.error?.reason ?? e?.error?.message ?? "Errore sconosciuto");
    return errorPage(reply, 400, text);
  });
  app.get("/oauth2/error", async (req, reply) => {
    const q = req.query as Record<string, string>;
    return errorPage(reply, 400, `${q.error ?? "error"}: ${friendly(q.error_description ?? "")}`.slice(0, 300));
  });
  app.get("/logged-out", async (_req, reply) =>
    sendHtml(reply, page("Disconnesso", html`<div class="card"><h1>Sei uscito</h1><p>La sessione è stata chiusa.</p></div>`)),
  );
  app.get("/", async (_req, reply) => reply.redirect("/auth/login"));
  return app;
}

function scopeLabel(s: string): string {
  const labels: Record<string, string> = {
    openid: "Identificativo dell'account",
    profile: "Nome e cognome",
    email: "Indirizzo email",
    fiscal_number: "Codice fiscale (attributo verificato SPID/CIE)",
    offline_access: "Accesso continuativo (refresh token)",
    "profile.read": "Lettura del profilo tramite API",
  };
  return labels[s] ?? s;
}
