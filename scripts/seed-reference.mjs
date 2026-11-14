// Idempotent LOCAL DEVELOPMENT configuration of the REFERENCE TEST federation
// (italia/spid-cie-oidc-django demo: trust anchor + SPID OP on trust-anchor.localhost:8000,
// CIE OP on cie-provider.localhost:8002). Run by `make reference-up` after the broker RPs
// have been registered at the reference trust anchor (infrastructure/reference-federation/register_rp.py).
//
//  - pins the reference trust anchor for the SPID and CIE profiles (keys taken from its entity
//    configuration WITHOUT out-of-band verification: acceptable only because the trust anchor is
//    a local test container built from the official image);
//  - adds the reference trust anchor to the profiles' authority_hints (fedsim stays as well);
//  - installs the trust mark issued by the reference trust anchor;
//  - registers the reference SPID OP and CIE OP as identity providers.
// Never run against production.
const env = (k) => {
  const v = process.env[k];
  if (!v) throw new Error(`missing env ${k}`);
  return v;
};
const BROKER = env("BROKER_ADMIN_URL");
const TA = env("REFERENCE_TA_URL").replace(/\/$/, "");
const SPID_OP = env("REFERENCE_SPID_OP");
const CIE_OP = env("REFERENCE_CIE_OP");
const headers = { authorization: `Bearer ${env("BROKER_ADMIN_TOKEN")}`, "x-actor": "seed-reference", "x-actor-roles": "superadmin", "content-type": "application/json" };

async function call(method, url, body, h = headers) {
  const res = await fetch(url, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30000) });
  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : undefined;
  } catch {
    data = text;
  }
  return { status: res.status, data };
}

async function waitFor(name, url) {
  for (let i = 0; i < 180; i++) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(3000) });
      if (r.ok) return;
    } catch {
      /* retry */
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`${name} not ready at ${url}`);
}

const payloadOf = (jws) => JSON.parse(Buffer.from(String(jws).trim().split(".")[1], "base64url").toString("utf8"));

async function fetchJws(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.text();
}

async function main() {
  await waitFor("broker", `${BROKER}/healthz`);
  await waitFor("reference trust anchor", `${TA}/.well-known/openid-federation`);
  await waitFor("reference CIE OP", `${CIE_OP}/.well-known/openid-federation`);

  const taEC = payloadOf(await fetchJws(`${TA}/.well-known/openid-federation`));
  if (taEC.iss !== TA || taEC.sub !== TA) throw new Error(`unexpected trust anchor entity configuration iss/sub: ${taEC.iss}`);
  const fetchEndpoint = taEC.metadata?.federation_entity?.federation_fetch_endpoint ?? `${TA}/fetch`;

  const tas = (await call("GET", `${BROKER}/admin/trust-anchors`)).data ?? [];
  const providers = (await call("GET", `${BROKER}/admin/providers`)).data ?? [];

  for (const [profile, op, name] of [
    ["spid", SPID_OP, "SPID OP di riferimento (Developers Italia, test)"],
    ["cie", CIE_OP, "CIE OP di riferimento (Developers Italia, test)"],
  ]) {
    const existingTA = tas.find((t) => t.profile === profile && t.entity_id === TA);
    const taBody = { profile, entity_id: TA, jwks: taEC.jwks, description: "REFERENCE TEST trust anchor (italia/spid-cie-oidc-django demo, public demo keys) — development only", enabled: true };
    const t = existingTA
      ? await call("PUT", `${BROKER}/admin/trust-anchors/${existingTA.id}`, taBody)
      : await call("POST", `${BROKER}/admin/trust-anchors`, taBody);
    if (t.status >= 300) throw new Error(`trust anchor ${profile}: ${t.status} ${JSON.stringify(t.data)}`);

    const cfg = (await call("GET", `${BROKER}/admin/profiles/${profile}`)).data.config;
    if (!cfg.authority_hints.includes(TA)) cfg.authority_hints = [...cfg.authority_hints, TA];

    // Subordinate statement issued by the reference trust anchor; it carries the trust marks of
    // the profiles assigned by register_rp.py.
    const stmt = payloadOf(await fetchJws(`${fetchEndpoint}?sub=${encodeURIComponent(cfg.entity_id)}`));
    if (stmt.sub !== cfg.entity_id) throw new Error(`reference TA statement for ${cfg.entity_id} has sub ${stmt.sub}`);
    const marks = (stmt.trust_marks ?? []).map((m) => ({ id: m.trust_mark_type ?? m.trust_mark_id ?? m.id, trust_mark: m.trust_mark }));
    const ids = new Set(marks.map((m) => m.id));
    // Keep other issuers' marks (fedsim) unless superseded by the same id from this TA.
    cfg.trust_marks = [
      ...(cfg.trust_marks ?? []).filter((m) => !ids.has(m.id) || payloadOf(m.trust_mark).iss !== TA),
      ...marks,
    ].filter((m, i, all) => all.findIndex((x) => x.trust_mark === m.trust_mark) === i);
    const put = await call("PUT", `${BROKER}/admin/profiles/${profile}`, cfg);
    if (put.status >= 300) throw new Error(`profile ${profile}: ${put.status} ${JSON.stringify(put.data)}`);

    const existingOP = providers.find((p) => p.profile === profile && p.entity_id === op);
    const opBody = { profile, entity_id: op, display_name: name, enabled: true, sort_order: 10 };
    const r = existingOP
      ? await call("PUT", `${BROKER}/admin/providers/${existingOP.id}`, opBody)
      : await call("POST", `${BROKER}/admin/providers`, opBody);
    if (r.status >= 300) throw new Error(`provider ${op}: ${r.status} ${JSON.stringify(r.data)}`);
    console.log(`reference federation ${profile}: trust anchor pinned, ${marks.length} trust mark(s) installed, provider ${op} enabled`);
  }
  await call("POST", `${BROKER}/admin/trust/refresh`, {});

  console.log("\nReference federation ready (TEST ONLY).");
  console.log("  Login: http://localhost:5580 -> Accedi -> Accedi con SPID -> 'SPID OP di riferimento' (or Entra con CIE)");
  console.log("  Demo user on the reference OPs: user / oidcuser (public demo credentials)");
}

main().catch((err) => {
  console.error(`seed-reference failed: ${err.message}`);
  process.exit(1);
});
