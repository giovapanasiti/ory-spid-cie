import type { FastifyInstance, FastifyReply, FastifyRequest, preHandlerAsyncHookHandler } from "fastify";
import { html, raw, type SafeHtml } from "@iam/shared";
import { sendHtml } from "@iam/ui";
import type { AdminDeps, Ctx } from "./app.js";
import { adminPage, csrfField, errMessage, flash, takeFlash } from "./app.js";
import { can, type Permission } from "./rbac.js";

/**
 * Federation administration UI: SPID / CIE Relying Party metadata, keys and
 * X.509 certificates (generate, import, CSR, self-signed for tests, upload
 * CA-issued certificates, rotation), trust anchors (with out-of-band
 * thumbprint verification), OpenID Providers, entity configuration preview
 * and trust-chain diagnostics. All writes go through the broker admin API,
 * which validates and audits them.
 */

interface RPProfile {
  profile: "spid" | "cie";
  enabled: boolean;
  environment: string;
  entity_id: string;
  organization_name: string;
  homepage_uri: string;
  policy_uri: string;
  logo_uri: string;
  contacts: string[];
  client_name: string;
  redirect_uris: string[];
  authority_hints: string[];
  trust_marks: { id: string; trust_mark: string }[] | null;
  scopes: string[];
  requested_claims: unknown;
  required_attributes: string[];
  acr_map: { acr: string; loa: string }[];
  default_loa: string;
  signing_alg: string;
  userinfo_encrypted_response_alg: string;
  userinfo_encrypted_response_enc: string;
  entity_configuration_ttl_seconds: number;
  require_op_trust_mark?: string;
  clock_skew_seconds: number;
  max_id_token_age_seconds: number;
  ui_locales: string;
}

interface KeyInfo {
  id: string;
  profile: string;
  purpose: string;
  kid: string;
  alg: string;
  key_type: string;
  status: string;
  public_jwk: unknown;
  cert_pem?: string;
  certificate?: { subject: string; issuer: string; serial: string; not_before: string; not_after: string; sha256_fingerprint: string; self_signed: boolean; uris?: string[] };
  created_at: string;
  activated_at?: string;
  retired_at?: string;
}

interface Provider {
  id: string;
  profile: string;
  entity_id: string;
  display_name: string;
  logo_uri: string;
  enabled: boolean;
  sort_order: number;
}

interface TrustAnchorView {
  id: string;
  profile: string;
  entity_id: string;
  jwks: { keys: unknown[] };
  description: string;
  enabled: boolean;
  thumbprints: string[];
}

type Guard = (p: Permission) => preHandlerAsyncHookHandler;

const PROFILES = ["spid", "cie"] as const;
const LOAS = ["urn:iam:loa:low", "urn:iam:loa:substantial", "urn:iam:loa:high"];
const SIG_ALGS = ["RS256", "RS512", "PS256", "PS512", "ES256", "ES512"];
const ENC_ALGS = ["RSA-OAEP-256", "RSA-OAEP", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"];
const ENC_ENCS = ["A256CBC-HS512", "A128CBC-HS256"];
const KEY_TYPES = ["RSA-2048", "RSA-3072", "RSA-4096", "EC-P256", "EC-P384", "EC-P521"];
const PURPOSES: Record<string, string[]> = { spid: ["federation", "core-sig", "core-enc"], cie: ["federation", "core-sig", "core-enc"], facade: ["facade-sig"] };
const PURPOSE_HELP: Record<string, string> = {
  federation: "Firma Entity Configuration e risposte federative (jwks dell'EC)",
  "core-sig": "Firma request object e client assertion (private_key_jwt)",
  "core-enc": "Decifratura UserInfo / ID token cifrati (RSA-OAEP)",
  "facade-sig": "Firma ID token interni verso Kratos",
};

function tabs(active: string): SafeHtml {
  const t: [string, string][] = [
    ["/federation", "Panoramica"],
    ["/federation/profile/spid", "Profilo SPID"],
    ["/federation/profile/cie", "Profilo CIE"],
    ["/federation/keys", "Chiavi e certificati"],
    ["/federation/trust-anchors", "Trust Anchor"],
    ["/federation/providers", "Identity Provider"],
    ["/federation/diagnostics", "Diagnostica"],
  ];
  return html`<nav class="tabs">${t.map(([h, l]) => html`<a href="${h}" class="${h === active ? "active" : ""}">${l}</a>`)}</nav>`;
}

const lines = (s: unknown) =>
  String(s ?? "")
    .split(/\r?\n/)
    .map((x) => x.trim())
    .filter(Boolean);

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  try {
    return JSON.parse(Buffer.from(jwt.split(".")[1] ?? "", "base64url").toString("utf8")) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function daysUntil(iso: string): number {
  return Math.floor((Date.parse(iso) - Date.now()) / 86400000);
}

function statusBadge(s: string): SafeHtml {
  const cls = s === "active" ? "ok" : s === "retired" ? "bad" : "warn";
  return html`<span class="badge ${cls}">${s}</span>`;
}

function select(name: string, options: string[], value: string | undefined): SafeHtml {
  return html`<select name="${name}">${options.map((o) => html`<option value="${o}"${o === value ? raw(" selected") : ""}>${o}</option>`)}</select>`;
}

export async function registerFederation(app: FastifyInstance, d: AdminDeps, guard: Guard): Promise<void> {
  const R = guard("federation.read");
  const W = guard("federation.write");
  const call = <T>(req: FastifyRequest, method: string, path: string, body?: unknown) => d.broker.call<T>(method, path, req.ctx!.actor, body);
  const page = (req: FastifyRequest, reply: FastifyReply, title: string, active: string, body: SafeHtml) =>
    sendHtml(reply, adminPage(req.ctx!, title, html`<h1>Federazione SPID / CIE</h1>${tabs(active)}${takeFlash(req, reply)}${body}`));
  const writable = (ctx: Ctx) => can(ctx.roles, "federation.write");
  const back = (reply: FastifyReply, to: string, msg: string, type: "success" | "error" = "success") => {
    flash(reply, msg, type);
    return reply.redirect(to);
  };

  // ------------------------------------------------------------------ overview
  app.get("/federation", { preHandler: R }, async (req, reply) => {
    let st: Record<string, unknown>;
    try {
      st = await call<Record<string, unknown>>(req, "GET", "/admin/status");
    } catch (err) {
      return page(req, reply, "Federazione", "/federation", html`<div class="msg error">Broker non raggiungibile: ${errMessage(err)}</div>`);
    }
    const profiles = (st.profiles as { profile: string; enabled: boolean; entity_id: string; environment: string; warnings: string[]; self_trust?: { trusted: boolean; error?: string; exp?: string; trust_mark_errors?: string[] } }[]) ?? [];
    const providers = (st.providers as (Provider & { trusted: boolean; error?: string; chain_exp?: string; trust_marks?: string[] })[]) ?? [];
    const keys = (st.keys as KeyInfo[]) ?? [];
    const failures = (st.recent_failures as { profile: string; op_entity_id: string; reason: string; created_at: string }[]) ?? [];
    const expiring = keys.filter((k) => k.certificate && daysUntil(k.certificate.not_after) < 60);
    return page(
      req,
      reply,
      "Federazione",
      "/federation",
      html`<div class="msg warn">Ambiente broker: <strong>${String(st.environment)}</strong>. La configurazione di produzione richiede onboarding ufficiale (AgID per SPID, Ministero dell'Interno per CIE): trust anchor, trust mark e certificati non possono essere generati localmente.</div>
<div class="grid2">${profiles.map(
        (p) => html`<div class="card"><h2>${p.profile.toUpperCase()} ${p.enabled ? html`<span class="badge ok">abilitato</span>` : html`<span class="badge">disabilitato</span>`}</h2>
<p><code>${p.entity_id}</code><br><span class="muted">ambiente: ${p.environment}</span></p>
<p>Fiducia della propria EC: ${p.self_trust ? (p.self_trust.trusted ? html`<span class="badge ok">trust chain valida</span> <span class="muted">scade ${p.self_trust.exp ?? ""}</span>` : html`<span class="badge bad">non verificabile</span><br><small class="muted">${p.self_trust.error ?? ""}</small>`) : html`<span class="muted">nessun trust anchor</span>`}</p>
${(p.self_trust?.trust_mark_errors ?? []).map((e) => html`<div class="msg error">Trust mark: ${e}</div>`)}
${(p.warnings ?? []).map((w) => html`<div class="msg warn">${w}</div>`)}
<p><a href="/federation/profile/${p.profile}">Modifica metadati</a> · <a href="/federation/entity-configuration/${p.profile}">Entity Configuration</a></p></div>`,
      )}</div>
<div class="card"><h2>Identity Provider</h2><table><tr><th>Profilo</th><th>Nome</th><th>Entity ID</th><th>Stato</th><th>Trust chain</th><th>Scadenza chain</th></tr>
${providers.map((p) => html`<tr><td>${p.profile.toUpperCase()}</td><td>${p.display_name}</td><td><code>${p.entity_id}</code></td><td>${p.enabled ? "abilitato" : "disabilitato"}</td><td>${!p.enabled ? "—" : p.trusted ? html`<span class="badge ok">valida</span>` : html`<span class="badge bad">non valida</span><br><small class="muted">${p.error ?? ""}</small>`}</td><td>${p.chain_exp && !p.chain_exp.startsWith("0001") ? p.chain_exp : "—"}</td></tr>`)}</table></div>
<div class="card"><h2>Chiavi e certificati</h2>
${expiring.length ? expiring.map((k) => html`<div class="msg warn">Certificato della chiave <code>${k.kid.slice(0, 12)}…</code> (${k.profile}/${k.purpose}) scade tra ${daysUntil(k.certificate!.not_after)} giorni.</div>`) : html`<p class="muted">Nessun certificato in scadenza entro 60 giorni.</p>`}
<p>${keys.filter((k) => k.status === "active").length} chiavi attive, ${keys.filter((k) => k.status === "next").length} pronte per la rotazione, ${keys.filter((k) => k.status === "deprecated").length} deprecate. <a href="/federation/keys">Gestisci →</a></p></div>
<div class="card"><h2>Errori recenti di autenticazione federata</h2><table><tr><th>Quando</th><th>Profilo</th><th>OP</th><th>Motivo</th></tr>
${failures.map((f) => html`<tr><td>${f.created_at}</td><td>${f.profile}</td><td><code>${f.op_entity_id}</code></td><td><code>${f.reason}</code></td></tr>`)}</table></div>`,
    );
  });

  // -------------------------------------------------------- profile (metadata)
  app.get("/federation/profile/:p", { preHandler: R }, async (req, reply) => {
    const p = (req.params as { p: string }).p;
    if (!PROFILES.includes(p as "spid")) return reply.code(404).send("not found");
    const ctx = req.ctx!;
    let res: { config: RPProfile; warnings: string[] };
    try {
      res = await call(req, "GET", `/admin/profiles/${p}`);
    } catch (err) {
      return page(req, reply, "Profilo", `/federation/profile/${p}`, html`<div class="msg error">${errMessage(err)}</div>`);
    }
    const c = res.config;
    const ro = !writable(ctx);
    const dis = ro ? raw(" disabled") : "";
    const field = (label: string, name: string, value: string | number | undefined, help = "", type = "text") =>
      html`<label for="${name}">${label}</label><input id="${name}" type="${type}" name="${name}" value="${value ?? ""}"${dis}>${help ? html`<div class="muted">${help}</div>` : ""}`;
    const area = (label: string, name: string, value: string, help = "", rows = 3) =>
      html`<label for="${name}">${label}</label><textarea id="${name}" name="${name}" rows="${rows}"${dis}>${value}</textarea>${help ? html`<div class="muted">${help}</div>` : ""}`;
    return page(
      req,
      reply,
      `Profilo ${p.toUpperCase()}`,
      `/federation/profile/${p}`,
      html`${(res.warnings ?? []).map((w) => html`<div class="msg warn">${w}</div>`)}
<form method="post" action="/federation/profile/${p}" class="card">${csrfField(ctx)}
<h2>Relying Party ${p.toUpperCase()}</h2>
<label><input type="checkbox" name="enabled" value="true"${c.enabled ? raw(" checked") : ""}${dis}> Profilo abilitato (se disabilitato, il pulsante "${p === "spid" ? "Accedi con SPID" : "Entra con CIE"}" restituisce l'errore profile_disabled)</label>
<label for="environment">Ambiente</label>${ro ? html`<input type="text" value="${c.environment}" disabled>` : select("environment", ["local", "test", "production"], c.environment)}
<div class="grid2"><div>
${field("Entity ID / client_id", "entity_id", c.entity_id, "URL HTTPS dell'RP; l'EC è pubblicata in <entity_id>/.well-known/openid-federation")}
${field("Nome organizzazione", "organization_name", c.organization_name)}
${field("Homepage URI", "homepage_uri", c.homepage_uri)}
${field("Policy URI (informativa privacy)", "policy_uri", c.policy_uri)}
${field("Logo URI (SVG raccomandato)", "logo_uri", c.logo_uri)}
${field("Nome client", "client_name", c.client_name)}
${area("Contatti (uno per riga, PEC per SPID)", "contacts", (c.contacts ?? []).join("\n"))}
</div><div>
${area("Redirect URI (una per riga, nessuna wildcard)", "redirect_uris", (c.redirect_uris ?? []).join("\n"), "La prima è usata nelle richieste di autenticazione")}
${area("Authority hints (Trust Anchor o Intermediari)", "authority_hints", (c.authority_hints ?? []).join("\n"))}
${field("Scope richiesti (oltre a openid)", "scopes", (c.scopes ?? []).filter((s) => s !== "openid").join(" "))}
${area("Attributi obbligatori (uno per riga)", "required_attributes", (c.required_attributes ?? []).join("\n"), "Se mancanti l'accesso fallisce con missing_attributes")}
${area("Parametro claims (JSON)", "requested_claims", JSON.stringify(c.requested_claims ?? {}, null, 2), "Gli attributi SPID sono restituiti solo da UserInfo", 8)}
</div></div>
<h2>Livelli di autenticazione</h2>
${area("Mappa ACR → LoA interno (una riga: acr = loa)", "acr_map", (c.acr_map ?? []).map((m) => `${m.acr} = ${m.loa}`).join("\n"), "Non si assume equivalenza tra profili: ogni profilo ha la propria mappa", 4)}
<label for="default_loa">LoA predefinito richiesto</label>${ro ? html`<input type="text" value="${c.default_loa}" disabled>` : select("default_loa", LOAS, c.default_loa)}
<h2>Crittografia e tempi</h2>
<div class="grid2"><div>
<label>Algoritmo di firma</label>${ro ? html`<input type="text" value="${c.signing_alg}" disabled>` : select("signing_alg", SIG_ALGS, c.signing_alg)}
<label>UserInfo cifratura (alg)</label>${ro ? html`<input type="text" value="${c.userinfo_encrypted_response_alg}" disabled>` : select("userinfo_encrypted_response_alg", ENC_ALGS, c.userinfo_encrypted_response_alg)}
<label>UserInfo cifratura (enc)</label>${ro ? html`<input type="text" value="${c.userinfo_encrypted_response_enc}" disabled>` : select("userinfo_encrypted_response_enc", ENC_ENCS, c.userinfo_encrypted_response_enc)}
${field("Trust mark richiesto per gli OP (opzionale)", "require_op_trust_mark", c.require_op_trust_mark ?? "")}
</div><div>
${field("Durata Entity Configuration (secondi)", "entity_configuration_ttl_seconds", c.entity_configuration_ttl_seconds, "", "number")}
${field("Tolleranza orologio (secondi)", "clock_skew_seconds", c.clock_skew_seconds, "", "number")}
${field("Età massima ID token (secondi)", "max_id_token_age_seconds", c.max_id_token_age_seconds, "", "number")}
${field("ui_locales", "ui_locales", c.ui_locales)}
</div></div>
${ro ? "" : html`<p><button>Salva profilo</button></p>`}
</form>
<div class="card"><h2>Trust mark</h2><p class="muted">I trust mark sono rilasciati dal Trust Anchor (o da un emittente autorizzato) al termine dell'onboarding. Incollare il JWT ricevuto; la validità viene verificata dalla diagnostica.</p>
<table><tr><th>ID</th><th>Emittente</th><th>Rilasciato</th><th>Scadenza</th><th></th></tr>
${(c.trust_marks ?? []).map((tm, i) => {
        const pl = decodeJwtPayload(tm.trust_mark);
        return html`<tr><td><code>${tm.id}</code></td><td><code>${String(pl.iss ?? "")}</code></td><td>${pl.iat ? new Date(Number(pl.iat) * 1000).toISOString() : ""}</td><td>${pl.exp ? new Date(Number(pl.exp) * 1000).toISOString() : "—"}</td>
<td>${ro ? "" : html`<form method="post" action="/federation/profile/${p}/trust-marks/${i}/delete" data-confirm="Rimuovere il trust mark?">${csrfField(ctx)}<button class="danger">Rimuovi</button></form>`}</td></tr>`;
      })}</table>
${ro ? "" : html`<form method="post" action="/federation/profile/${p}/trust-marks">${csrfField(ctx)}<label>ID trust mark</label><input type="text" name="id" placeholder="https://registry.spid.gov.it/openid_relying_party/public/" required>
<label>Trust mark (JWT)</label><textarea name="trust_mark" required></textarea><button>Aggiungi trust mark</button></form>`}</div>`,
    );
  });

  const saveProfile = async (req: FastifyRequest, cfg: RPProfile) => call(req, "PUT", `/admin/profiles/${cfg.profile}`, cfg);

  app.post("/federation/profile/:p", { preHandler: W }, async (req, reply) => {
    const p = (req.params as { p: string }).p as "spid" | "cie";
    const b = req.body as Record<string, string>;
    const current = (await call<{ config: RPProfile }>(req, "GET", `/admin/profiles/${p}`)).config;
    let claims: unknown;
    try {
      claims = JSON.parse(b.requested_claims || "{}");
    } catch {
      return back(reply, `/federation/profile/${p}`, "Il parametro claims non è JSON valido.", "error");
    }
    const acrMap = lines(b.acr_map).map((l) => {
      const [acr, loa] = l.split("=").map((s) => s.trim());
      return { acr: acr ?? "", loa: loa ?? "" };
    });
    const cfg: RPProfile = {
      ...current,
      enabled: b.enabled === "true",
      environment: b.environment ?? current.environment,
      entity_id: (b.entity_id ?? "").trim(),
      organization_name: (b.organization_name ?? "").trim(),
      homepage_uri: (b.homepage_uri ?? "").trim(),
      policy_uri: (b.policy_uri ?? "").trim(),
      logo_uri: (b.logo_uri ?? "").trim(),
      client_name: (b.client_name ?? "").trim(),
      contacts: lines(b.contacts),
      redirect_uris: lines(b.redirect_uris),
      authority_hints: lines(b.authority_hints),
      scopes: ["openid", ...(b.scopes ?? "").split(/\s+/).filter(Boolean)],
      required_attributes: lines(b.required_attributes),
      requested_claims: claims,
      acr_map: acrMap,
      default_loa: b.default_loa ?? current.default_loa,
      signing_alg: b.signing_alg ?? current.signing_alg,
      userinfo_encrypted_response_alg: b.userinfo_encrypted_response_alg ?? current.userinfo_encrypted_response_alg,
      userinfo_encrypted_response_enc: b.userinfo_encrypted_response_enc ?? current.userinfo_encrypted_response_enc,
      require_op_trust_mark: (b.require_op_trust_mark ?? "").trim() || undefined,
      entity_configuration_ttl_seconds: Number(b.entity_configuration_ttl_seconds),
      clock_skew_seconds: Number(b.clock_skew_seconds),
      max_id_token_age_seconds: Number(b.max_id_token_age_seconds),
      ui_locales: (b.ui_locales ?? "").trim(),
      trust_marks: current.trust_marks ?? [],
    };
    try {
      await saveProfile(req, cfg);
      return back(reply, `/federation/profile/${p}`, "Profilo salvato.");
    } catch (err) {
      return back(reply, `/federation/profile/${p}`, `Validazione fallita: ${errMessage(err)}`, "error");
    }
  });

  app.post("/federation/profile/:p/trust-marks", { preHandler: W }, async (req, reply) => {
    const p = (req.params as { p: string }).p;
    const b = req.body as Record<string, string>;
    const cfg = (await call<{ config: RPProfile }>(req, "GET", `/admin/profiles/${p}`)).config;
    const tm = (b.trust_mark ?? "").trim();
    if (tm.split(".").length !== 3) return back(reply, `/federation/profile/${p}`, "Il trust mark deve essere un JWT compatto.", "error");
    const pl = decodeJwtPayload(tm);
    if (pl.sub && pl.sub !== cfg.entity_id) return back(reply, `/federation/profile/${p}`, `Il trust mark è rilasciato a ${String(pl.sub)}, non a ${cfg.entity_id}.`, "error");
    cfg.trust_marks = [...(cfg.trust_marks ?? []).filter((t) => t.id !== b.id), { id: (b.id ?? "").trim(), trust_mark: tm }];
    try {
      await saveProfile(req, cfg);
      return back(reply, `/federation/profile/${p}`, "Trust mark aggiunto.");
    } catch (err) {
      return back(reply, `/federation/profile/${p}`, errMessage(err), "error");
    }
  });

  app.post("/federation/profile/:p/trust-marks/:i/delete", { preHandler: W }, async (req, reply) => {
    const { p, i } = req.params as { p: string; i: string };
    const cfg = (await call<{ config: RPProfile }>(req, "GET", `/admin/profiles/${p}`)).config;
    cfg.trust_marks = (cfg.trust_marks ?? []).filter((_, idx) => idx !== Number(i));
    await saveProfile(req, cfg);
    return back(reply, `/federation/profile/${p}`, "Trust mark rimosso.");
  });

  app.get("/federation/entity-configuration/:p", { preHandler: R }, async (req, reply) => {
    const p = (req.params as { p: string }).p;
    try {
      const ec = await call<{ jwt: string; payload: unknown; well_known_url: string }>(req, "GET", `/admin/profiles/${p}/entity-configuration`);
      return page(
        req,
        reply,
        "Entity Configuration",
        "/federation",
        html`<div class="card"><h2>Entity Configuration ${p.toUpperCase()}</h2><p>URL pubblico: <code>${ec.well_known_url}</code></p>
<p class="muted">Questa è l'EC che il broker pubblica ora (firmata con la chiave federativa attiva). Il Trust Anchor la usa per l'onboarding.</p>
<h3>Payload</h3><pre>${JSON.stringify(ec.payload, null, 2)}</pre><h3>JWT firmato</h3><pre style="white-space:pre-wrap;word-break:break-all">${ec.jwt}</pre></div>`,
      );
    } catch (err) {
      return page(req, reply, "Entity Configuration", "/federation", html`<div class="msg error">${errMessage(err)}</div>`);
    }
  });

  // -------------------------------------------------------- keys & certificates
  app.get("/federation/keys", { preHandler: R }, async (req, reply) => {
    const ctx = req.ctx!;
    const keys = await call<KeyInfo[]>(req, "GET", "/admin/keys");
    const ro = !writable(ctx);
    const groups = new Map<string, KeyInfo[]>();
    for (const k of keys) groups.set(`${k.profile}/${k.purpose}`, [...(groups.get(`${k.profile}/${k.purpose}`) ?? []), k]);
    const subjectFields = (prefix: string) => html`<div class="grid2"><div><label>Common Name (CN)</label><input type="text" name="common_name" required placeholder="${prefix}.example.it">
<label>Organizzazione (O)</label><input type="text" name="organization"></div><div>
<label>organizationIdentifier (es. PA:IT-c_h501 o VATIT-12345678901)</label><input type="text" name="organization_identifier">
<label>Paese (C)</label><input type="text" name="country" value="IT" maxlength="2"><label>Località (L)</label><input type="text" name="locality"></div></div>
<label>Entity ID (SAN URI)</label><input type="text" name="entity_id">`;
    const keyRow = (k: KeyInfo) => html`<tr>
<td><code title="${k.kid}">${k.kid.slice(0, 16)}…</code><br><span class="muted">${k.key_type} · ${k.alg}</span></td>
<td>${statusBadge(k.status)}<br><span class="muted">creata ${k.created_at.slice(0, 10)}${k.activated_at ? html`<br>attivata ${k.activated_at.slice(0, 10)}` : ""}</span></td>
<td>${k.certificate
      ? html`<div><strong>${k.certificate.subject}</strong></div><div class="muted">emittente: ${k.certificate.issuer}${k.certificate.self_signed ? html` <span class="badge warn">self-signed</span>` : ""}</div>
<div class="muted">valido ${k.certificate.not_before.slice(0, 10)} → ${k.certificate.not_after.slice(0, 10)} ${daysUntil(k.certificate.not_after) < 60 ? html`<span class="badge bad">in scadenza</span>` : ""}</div><div class="muted"><code>SHA-256 ${k.certificate.sha256_fingerprint.slice(0, 23)}…</code></div>`
      : html`<span class="muted">nessun certificato (opzionale per OIDC; x5c pubblicato se presente)</span>`}</td>
<td><details><summary>JWK pubblica</summary><pre>${JSON.stringify(k.public_jwk, null, 2)}</pre></details>
${k.cert_pem ? html`<details><summary>Certificato PEM</summary><pre>${k.cert_pem}</pre></details>` : ""}
${ro || k.status === "retired"
      ? ""
      : html`<details><summary>Genera CSR</summary><form method="post" action="/federation/keys/${k.id}/csr">${csrfField(ctx)}${subjectFields(k.profile)}<button>Genera CSR</button></form></details>
<details><summary>Carica certificato firmato dalla CA</summary><form method="post" action="/federation/keys/${k.id}/certificate">${csrfField(ctx)}<label>Catena PEM (foglia per prima)</label><textarea name="certificate_pem" required></textarea><button>Carica</button></form></details>
<details><summary>Certificato self-signed (solo test)</summary><form method="post" action="/federation/keys/${k.id}/self-signed">${csrfField(ctx)}${subjectFields(k.profile)}<label>Validità (giorni)</label><input type="number" name="days" value="365" min="1" max="1825"><button>Genera</button></form></details>`}
${ro
      ? ""
      : html`<div class="row" style="margin-top:.5rem">
${k.status === "next" || k.status === "deprecated" ? html`<form method="post" action="/federation/keys/${k.id}/activate" data-confirm="Attivare questa chiave? La chiave attiva corrente diventerà 'deprecated' (ancora pubblicata).">${csrfField(ctx)}<button>Attiva</button></form>` : ""}
${k.status === "next" || k.status === "deprecated" ? html`<form method="post" action="/federation/keys/${k.id}/retire" data-confirm="Ritirare la chiave? Non sarà più pubblicata: verificare che nessun partner la usi ancora.">${csrfField(ctx)}<button class="secondary">Ritira</button></form>` : ""}
${k.status === "retired" ? html`<form method="post" action="/federation/keys/${k.id}/delete" data-confirm="Eliminare DEFINITIVAMENTE la chiave privata? L'operazione è irreversibile.">${csrfField(ctx)}<button class="danger">Elimina</button></form>` : ""}
</div>`}</td></tr>`;
    return page(
      req,
      reply,
      "Chiavi e certificati",
      "/federation/keys",
      html`<div class="msg">Rotazione consigliata: <strong>1)</strong> genera/importa una chiave in stato <em>next</em> (pubblicata ma non usata) <strong>2)</strong> attendi la propagazione (≥ durata EC e cache degli OP) <strong>3)</strong> attiva <strong>4)</strong> ritira la vecchia chiave dopo la scadenza dei token/EC emessi. Le chiavi private sono cifrate a riposo e non sono mai esportabili dalla console.</div>
${[...groups.entries()].map(
        ([g, ks]) => html`<div class="card"><h2>${g.toUpperCase()} <span class="muted" style="font-size:.85rem">${PURPOSE_HELP[g.split("/")[1] ?? ""] ?? ""}</span></h2>
<table><tr><th>Kid</th><th>Stato</th><th>Certificato X.509</th><th>Azioni</th></tr>${ks.map(keyRow)}</table></div>`,
      )}
${ro
  ? ""
  : html`<div class="grid2"><form method="post" action="/federation/keys/generate" class="card">${csrfField(ctx)}<h2>Genera nuova chiave</h2>
<label>Profilo / scopo</label><select name="target">${Object.entries(PURPOSES).flatMap(([p, ps]) => ps.map((x) => html`<option value="${p}/${x}">${p.toUpperCase()} — ${x}</option>`))}</select>
<label>Tipo di chiave</label>${select("key_type", KEY_TYPES, "RSA-3072")}
<label>Algoritmo di firma (vuoto = predefinito)</label><select name="alg"><option value="">predefinito</option>${SIG_ALGS.map((a) => html`<option>${a}</option>`)}</select>
<label>Stato iniziale</label><select name="status"><option value="next">next (pubblicata, per rotazione)</option><option value="active">active (sostituisce subito quella attiva)</option></select>
<p class="muted">SPID richiede chiavi RSA per la cifratura (RSA-OAEP); chiavi ≥ 2048 bit (4096 raccomandata).</p><button>Genera</button></form>
<form method="post" action="/federation/keys/import" class="card">${csrfField(ctx)}<h2>Importa chiave e certificato</h2>
<label>Profilo / scopo</label><select name="target">${Object.entries(PURPOSES).flatMap(([p, ps]) => ps.map((x) => html`<option value="${p}/${x}">${p.toUpperCase()} — ${x}</option>`))}</select>
<label>Chiave privata PEM (PKCS#8, PKCS#1 o SEC1, non cifrata)</label><textarea name="private_key_pem" required autocomplete="off" spellcheck="false"></textarea>
<label>Catena certificati PEM (opzionale)</label><textarea name="certificate_pem"></textarea>
<label>Algoritmo</label><select name="alg"><option value="">predefinito</option>${SIG_ALGS.map((a) => html`<option>${a}</option>`)}</select>
<label>Stato iniziale</label><select name="status"><option value="next">next</option><option value="active">active</option></select>
<div class="msg warn">La chiave privata viene trasmessa al broker e cifrata a riposo; non viene registrata nei log. Usare solo su connessioni TLS.</div><button>Importa</button></form></div>`}`,
    );
  });

  const subjectFrom = (b: Record<string, string>) => ({
    common_name: (b.common_name ?? "").trim(),
    organization: (b.organization ?? "").trim(),
    organization_identifier: (b.organization_identifier ?? "").trim(),
    country: (b.country ?? "").trim().toUpperCase(),
    locality: (b.locality ?? "").trim(),
    entity_id: (b.entity_id ?? "").trim(),
  });
  const target = (b: Record<string, string>) => {
    const [profile, purpose] = String(b.target ?? "").split("/");
    return { profile: profile ?? "", purpose: purpose ?? "" };
  };

  app.post("/federation/keys/generate", { preHandler: W }, async (req, reply) => {
    const b = req.body as Record<string, string>;
    try {
      const k = await call<KeyInfo>(req, "POST", "/admin/keys/generate", { ...target(b), key_type: b.key_type, alg: b.alg ?? "", status: b.status });
      return back(reply, "/federation/keys", `Chiave ${k.kid.slice(0, 12)}… generata (${k.status}).`);
    } catch (err) {
      return back(reply, "/federation/keys", errMessage(err), "error");
    }
  });

  app.post("/federation/keys/import", { preHandler: W }, async (req, reply) => {
    const b = req.body as Record<string, string>;
    try {
      const k = await call<KeyInfo>(req, "POST", "/admin/keys/import", {
        ...target(b),
        alg: b.alg ?? "",
        private_key_pem: b.private_key_pem ?? "",
        certificate_pem: b.certificate_pem ?? "",
        status: b.status,
      });
      return back(reply, "/federation/keys", `Chiave ${k.kid.slice(0, 12)}… importata.`);
    } catch (err) {
      return back(reply, "/federation/keys", `Import fallito: ${errMessage(err)}`, "error");
    }
  });

  for (const action of ["activate", "retire"] as const) {
    app.post(`/federation/keys/:id/${action}`, { preHandler: W }, async (req, reply) => {
      try {
        await call(req, "POST", `/admin/keys/${encodeURIComponent((req.params as { id: string }).id)}/${action}`);
        return back(reply, "/federation/keys", action === "activate" ? "Chiave attivata." : "Chiave ritirata.");
      } catch (err) {
        return back(reply, "/federation/keys", errMessage(err), "error");
      }
    });
  }

  app.post("/federation/keys/:id/delete", { preHandler: W }, async (req, reply) => {
    try {
      await call(req, "DELETE", `/admin/keys/${encodeURIComponent((req.params as { id: string }).id)}`);
      return back(reply, "/federation/keys", "Chiave eliminata.");
    } catch (err) {
      return back(reply, "/federation/keys", errMessage(err), "error");
    }
  });

  app.post("/federation/keys/:id/csr", { preHandler: W }, async (req, reply) => {
    const id = (req.params as { id: string }).id;
    try {
      const r = await call<{ csr_pem: string }>(req, "POST", `/admin/keys/${encodeURIComponent(id)}/csr`, subjectFrom(req.body as Record<string, string>));
      return page(
        req,
        reply,
        "CSR",
        "/federation/keys",
        html`<div class="card"><h2>Certificate Signing Request</h2><p>Invia questa CSR alla Certification Authority prevista dal profilo. Al rilascio, carica il certificato sulla stessa chiave.</p><pre>${r.csr_pem}</pre><a href="/federation/keys">← Torna alle chiavi</a></div>`,
      );
    } catch (err) {
      return back(reply, "/federation/keys", errMessage(err), "error");
    }
  });

  app.post("/federation/keys/:id/self-signed", { preHandler: W }, async (req, reply) => {
    const b = req.body as Record<string, string>;
    try {
      await call(req, "POST", `/admin/keys/${encodeURIComponent((req.params as { id: string }).id)}/self-signed`, { ...subjectFrom(b), days: Number(b.days ?? 365) });
      return back(reply, "/federation/keys", "Certificato self-signed associato (solo per test).");
    } catch (err) {
      return back(reply, "/federation/keys", errMessage(err), "error");
    }
  });

  app.post("/federation/keys/:id/certificate", { preHandler: W }, async (req, reply) => {
    try {
      await call(req, "PUT", `/admin/keys/${encodeURIComponent((req.params as { id: string }).id)}/certificate`, {
        certificate_pem: (req.body as Record<string, string>).certificate_pem ?? "",
      });
      return back(reply, "/federation/keys", "Certificato caricato e associato alla chiave.");
    } catch (err) {
      return back(reply, "/federation/keys", `Certificato rifiutato: ${errMessage(err)}`, "error");
    }
  });

  // ------------------------------------------------------------- trust anchors
  app.get("/federation/trust-anchors", { preHandler: R }, async (req, reply) => {
    const ctx = req.ctx!;
    const tas = await call<TrustAnchorView[]>(req, "GET", "/admin/trust-anchors");
    const ro = !writable(ctx);
    return page(
      req,
      reply,
      "Trust Anchor",
      "/federation/trust-anchors",
      html`<div class="msg warn">Le chiavi dei Trust Anchor sono <strong>pinned</strong>: tutta la fiducia federativa deriva da esse. Le impronte vanno confrontate con quelle comunicate dall'autorità di federazione tramite canale autenticato. Non usare mai chiavi apprese solo dalla rete in produzione.</div>
<div class="card"><table><tr><th>Profilo</th><th>Entity ID</th><th>Impronte JWK (SHA-256)</th><th>Descrizione</th><th>Stato</th><th></th></tr>
${tas.map((t) => html`<tr><td>${t.profile.toUpperCase()}</td><td><code>${t.entity_id}</code></td><td>${(t.thumbprints ?? []).map((x) => html`<div><code>${x}</code></div>`)}</td><td>${t.description}</td><td>${t.enabled ? "abilitato" : "disabilitato"}</td>
<td>${ro ? "" : html`<form method="post" action="/federation/trust-anchors/${t.id}/delete" data-confirm="Rimuovere il trust anchor? Tutti gli OP che dipendono da esso diventeranno non fidati.">${csrfField(ctx)}<button class="danger">Rimuovi</button></form>`}</td></tr>`)}</table></div>
${ro
  ? ""
  : html`<div class="grid2"><form method="post" action="/federation/trust-anchors/preview" class="card">${csrfField(ctx)}<h2>1. Anteprima</h2><p class="muted">Scarica l'Entity Configuration del TA e mostra le impronte delle chiavi (nessun salvataggio).</p>
<label>Entity ID del Trust Anchor</label><input type="text" name="entity_id" required placeholder="https://registry.spid.gov.it">
<label>Profilo</label>${select("profile", ["spid", "cie"], "spid")}<button>Anteprima</button></form>
<form method="post" action="/federation/trust-anchors" class="card">${csrfField(ctx)}<h2>2. Pinning</h2>
<label>Profilo</label>${select("profile", ["spid", "cie"], "spid")}<label>Entity ID</label><input type="text" name="entity_id" required>
<label>JWKS pubblico (JSON)</label><textarea name="jwks" required rows="6" placeholder='{"keys":[...]}'></textarea>
<label>Descrizione</label><input type="text" name="description">
<label><input type="checkbox" name="verified" value="true" required> Ho verificato le impronte tramite canale out-of-band autenticato</label><button>Salva trust anchor</button></form></div>`}`,
    );
  });

  app.post("/federation/trust-anchors/preview", { preHandler: W }, async (req, reply) => {
    const ctx = req.ctx!;
    const b = req.body as Record<string, string>;
    try {
      const r = await call<{ entity_id: string; jwks: unknown; thumbprints: { kid: string; thumbprint_sha256: string }[]; warning: string; federation_entity: unknown }>(req, "POST", "/admin/trust-anchors/preview", { entity_id: b.entity_id });
      return page(
        req,
        reply,
        "Anteprima Trust Anchor",
        "/federation/trust-anchors",
        html`<div class="card"><h2>${r.entity_id}</h2><div class="msg warn">${r.warning}</div>
<table><tr><th>kid</th><th>Impronta SHA-256 (RFC 7638)</th></tr>${(r.thumbprints ?? []).map((t) => html`<tr><td><code>${t.kid}</code></td><td><code>${t.thumbprint_sha256}</code></td></tr>`)}</table>
<h3>Metadati federation_entity</h3><pre>${JSON.stringify(r.federation_entity, null, 2)}</pre>
<form method="post" action="/federation/trust-anchors">${csrfField(ctx)}<input type="hidden" name="profile" value="${b.profile ?? "spid"}"><input type="hidden" name="entity_id" value="${r.entity_id}">
<label>JWKS da salvare</label><textarea name="jwks" rows="8">${JSON.stringify(r.jwks, null, 2)}</textarea><label>Descrizione</label><input type="text" name="description">
<label><input type="checkbox" name="verified" value="true" required> Ho confrontato le impronte con quelle ufficiali</label><button>Salva (pin)</button></form></div>`,
      );
    } catch (err) {
      return back(reply, "/federation/trust-anchors", `Anteprima fallita: ${errMessage(err)}`, "error");
    }
  });

  app.post("/federation/trust-anchors", { preHandler: W }, async (req, reply) => {
    const b = req.body as Record<string, string>;
    if (b.verified !== "true") return back(reply, "/federation/trust-anchors", "Conferma la verifica out-of-band delle impronte.", "error");
    let jwks: unknown;
    try {
      jwks = JSON.parse(b.jwks ?? "");
    } catch {
      return back(reply, "/federation/trust-anchors", "JWKS non valido.", "error");
    }
    try {
      await call(req, "POST", "/admin/trust-anchors", { profile: b.profile, entity_id: (b.entity_id ?? "").trim(), jwks, description: b.description ?? "", enabled: true });
      return back(reply, "/federation/trust-anchors", "Trust anchor salvato.");
    } catch (err) {
      return back(reply, "/federation/trust-anchors", errMessage(err), "error");
    }
  });

  app.post("/federation/trust-anchors/:id/delete", { preHandler: W }, async (req, reply) => {
    try {
      await call(req, "DELETE", `/admin/trust-anchors/${encodeURIComponent((req.params as { id: string }).id)}`);
      return back(reply, "/federation/trust-anchors", "Trust anchor rimosso.");
    } catch (err) {
      return back(reply, "/federation/trust-anchors", errMessage(err), "error");
    }
  });

  // ---------------------------------------------------------------- providers
  app.get("/federation/providers", { preHandler: R }, async (req, reply) => {
    const ctx = req.ctx!;
    const list = await call<Provider[]>(req, "GET", "/admin/providers");
    const ro = !writable(ctx);
    const form = (p?: Provider) => html`<form method="post" action="${p ? `/federation/providers/${p.id}` : "/federation/providers"}" class="${p ? "" : "card"}">${csrfField(ctx)}
${p ? "" : html`<h2>Aggiungi Identity Provider</h2>`}
<div class="grid2"><div><label>Profilo</label>${select("profile", ["spid", "cie"], p?.profile ?? "spid")}<label>Entity ID dell'OP</label><input type="text" name="entity_id" value="${p?.entity_id ?? ""}" required></div>
<div><label>Nome visualizzato</label><input type="text" name="display_name" value="${p?.display_name ?? ""}" required maxlength="120"><label>Logo URI</label><input type="text" name="logo_uri" value="${p?.logo_uri ?? ""}"></div></div>
<div class="row"><label><input type="checkbox" name="enabled" value="true"${!p || p.enabled ? raw(" checked") : ""}> Abilitato</label><label>Ordine <input type="number" name="sort_order" value="${p?.sort_order ?? 0}" style="width:5rem"></label><button>${p ? "Aggiorna" : "Aggiungi"}</button></div></form>`;
    return page(
      req,
      reply,
      "Identity Provider",
      "/federation/providers",
      html`<p class="muted">Gli OP sono considerati fidati solo se la loro trust chain verso un trust anchor configurato è valida. L'elenco ufficiale degli IdP SPID è pubblicato dal Trust Anchor (list endpoint).</p>
<div class="card"><table><tr><th>Profilo</th><th>Nome</th><th>Entity ID</th><th>Stato</th><th></th></tr>
${list.map((p) => html`<tr><td>${p.profile.toUpperCase()}</td><td>${p.display_name}</td><td><code>${p.entity_id}</code></td><td>${p.enabled ? "abilitato" : "disabilitato"}</td>
<td><form method="post" action="/federation/diagnostics" style="display:inline">${csrfField(ctx)}<input type="hidden" name="profile" value="${p.profile}"><input type="hidden" name="entity_id" value="${p.entity_id}"><button class="secondary">Verifica trust</button></form>
${ro ? "" : html`<details><summary>Modifica</summary>${form(p)}</details><form method="post" action="/federation/providers/${p.id}/delete" data-confirm="Eliminare il provider?">${csrfField(ctx)}<button class="danger">Elimina</button></form>`}</td></tr>`)}</table></div>
${ro ? "" : form()}`,
    );
  });

  const saveProvider = async (req: FastifyRequest, reply: FastifyReply, id?: string) => {
    const b = req.body as Record<string, string>;
    const body = { profile: b.profile, entity_id: (b.entity_id ?? "").trim(), display_name: (b.display_name ?? "").trim(), logo_uri: (b.logo_uri ?? "").trim(), enabled: b.enabled === "true", sort_order: Number(b.sort_order ?? 0) };
    try {
      await call(req, id ? "PUT" : "POST", id ? `/admin/providers/${encodeURIComponent(id)}` : "/admin/providers", body);
      return back(reply, "/federation/providers", "Provider salvato.");
    } catch (err) {
      return back(reply, "/federation/providers", errMessage(err), "error");
    }
  };
  app.post("/federation/providers", { preHandler: W }, async (req, reply) => saveProvider(req, reply));
  app.post("/federation/providers/:id", { preHandler: W }, async (req, reply) => saveProvider(req, reply, (req.params as { id: string }).id));
  app.post("/federation/providers/:id/delete", { preHandler: W }, async (req, reply) => {
    try {
      await call(req, "DELETE", `/admin/providers/${encodeURIComponent((req.params as { id: string }).id)}`);
      return back(reply, "/federation/providers", "Provider eliminato.");
    } catch (err) {
      return back(reply, "/federation/providers", errMessage(err), "error");
    }
  });

  // -------------------------------------------------------------- diagnostics
  const diagForm = (ctx: Ctx, v: Record<string, string> = {}) => html`<form method="post" action="/federation/diagnostics" class="card">${csrfField(ctx)}<h2>Verifica trust chain</h2>
<div class="grid2"><div><label>Profilo</label>${select("profile", ["spid", "cie"], v.profile ?? "spid")}</div><div><label>Tipo entità</label>${select("entity_type", ["openid_provider", "openid_relying_party", "federation_entity"], v.entity_type ?? "openid_provider")}</div></div>
<label>Entity ID</label><input type="text" name="entity_id" value="${v.entity_id ?? ""}" required>
<label><input type="checkbox" name="no_cache" value="true" checked> Ignora cache</label><button>Risolvi</button></form>
${writable(ctx) ? html`<form method="post" action="/federation/diagnostics/refresh" class="row">${csrfField(ctx)}<button class="secondary">Svuota tutte le cache di trust</button></form>` : ""}`;

  app.get("/federation/diagnostics", { preHandler: R }, async (req, reply) => page(req, reply, "Diagnostica", "/federation/diagnostics", diagForm(req.ctx!)));

  // POST used only to carry CSRF + body; read-only operation (federation.read).
  app.post("/federation/diagnostics", { preHandler: R }, async (req, reply) => {
    const b = req.body as Record<string, string>;
    let out: SafeHtml;
    try {
      const r = await call<{ trusted: boolean; error?: string; chain?: { path: string[]; exp: string; trust_anchor: string; metadata: unknown; trust_marks: unknown[]; trust_mark_errors?: string[] } }>(req, "POST", "/admin/trust/resolve", {
        profile: b.profile,
        entity_id: (b.entity_id ?? "").trim(),
        entity_type: b.entity_type ?? "openid_provider",
        no_cache: b.no_cache === "true",
      });
      out = r.trusted
        ? html`<div class="card"><h2><span class="badge ok">Trust chain valida</span></h2><p>Trust anchor: <code>${r.chain!.trust_anchor}</code> · scadenza: ${r.chain!.exp}</p>
<h3>Percorso</h3><ol>${(r.chain!.path ?? []).map((p) => html`<li><code>${p}</code></li>`)}</ol>
<h3>Trust mark verificati</h3><pre>${JSON.stringify(r.chain!.trust_marks ?? [], null, 2)}</pre>
${(r.chain!.trust_mark_errors ?? []).map((e) => html`<div class="msg error">${e}</div>`)}
<h3>Metadati finali (policy applicate)</h3><pre>${JSON.stringify(r.chain!.metadata, null, 2)}</pre></div>`
        : html`<div class="card"><h2><span class="badge bad">Trust NON stabilita</span></h2><div class="msg error">${r.error ?? ""}</div></div>`;
    } catch (err) {
      out = html`<div class="msg error">${errMessage(err)}</div>`;
    }
    return page(req, reply, "Diagnostica", "/federation/diagnostics", html`${diagForm(req.ctx!, b)}${out}`);
  });

  app.post("/federation/diagnostics/refresh", { preHandler: W }, async (req, reply) => {
    await call(req, "POST", "/admin/trust/refresh");
    return back(reply, "/federation/diagnostics", "Cache di trust svuotate.");
  });
}
