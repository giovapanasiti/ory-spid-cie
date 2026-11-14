// Idempotent LOCAL DEVELOPMENT seeding (run with `make seed`):
//  - OAuth2 clients in Hydra (admin-console, demo-web, demo-public, demo-m2m)
//  - a development administrator in Kratos + superadmin role
//  - pins the LOCAL TEST trust anchor and obtains RP trust marks from the simulator
// Never run against production: it pins a test trust anchor without out-of-band verification.
const env = (k) => {
  const v = process.env[k];
  if (!v) throw new Error(`missing env ${k}`);
  return v;
};
const HYDRA = env("HYDRA_ADMIN_URL");
const KRATOS = env("KRATOS_ADMIN_URL");
const BROKER = env("BROKER_ADMIN_URL");
const IDS = env("IDENTITY_SERVICE_URL");
const FEDSIM = env("FEDSIM_URL");
const brokerHeaders = { authorization: `Bearer ${env("BROKER_ADMIN_TOKEN")}`, "x-actor": "seed", "x-actor-roles": "superadmin", "content-type": "application/json" };
const idsHeaders = { authorization: `Bearer ${env("IDENTITY_SERVICE_TOKEN")}`, "content-type": "application/json" };

async function call(method, url, body, headers = { "content-type": "application/json" }) {
  const res = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(20000) });
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
  for (let i = 0; i < 90; i++) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(2000) });
      if (r.ok) return;
    } catch {
      /* retry */
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`${name} not ready at ${url}`);
}

async function upsertClient(c) {
  const existing = await call("GET", `${HYDRA}/admin/clients/${encodeURIComponent(c.client_id)}`);
  const r = existing.status === 200 ? await call("PUT", `${HYDRA}/admin/clients/${encodeURIComponent(c.client_id)}`, c) : await call("POST", `${HYDRA}/admin/clients`, c);
  if (r.status >= 300) throw new Error(`client ${c.client_id}: ${r.status} ${JSON.stringify(r.data)}`);
  console.log(`hydra client ${c.client_id}: ${existing.status === 200 ? "updated" : "created"}`);
}

async function main() {
  await waitFor("hydra", `${HYDRA}/health/ready`);
  await waitFor("kratos", `${KRATOS}/admin/health/ready`);
  await waitFor("broker", `${BROKER}/healthz`);
  await waitFor("identity-service", `${IDS}/healthz`);
  await waitFor("fedsim", `${FEDSIM}/healthz`);

  // ---------------------------------------------------------- OAuth2 clients
  await upsertClient({
    client_id: "admin-console", client_name: "Admin Console", client_secret: env("ADMIN_OIDC_CLIENT_SECRET"),
    grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], scope: "openid profile email",
    redirect_uris: ["http://localhost:3100/callback"], post_logout_redirect_uris: ["http://localhost:3100/logged-out"],
    token_endpoint_auth_method: "client_secret_basic", skip_consent: true,
  });
  await upsertClient({
    client_id: "demo-web", client_name: "Demo Web App", client_secret: env("DEMO_OIDC_CLIENT_SECRET"),
    grant_types: ["authorization_code", "refresh_token"], response_types: ["code"],
    scope: "openid offline_access profile email fiscal_number profile.read", audience: ["demo-api"],
    redirect_uris: ["http://localhost:5580/callback"], post_logout_redirect_uris: ["http://localhost:5580/"],
    token_endpoint_auth_method: "client_secret_basic", skip_consent: false,
  });
  await upsertClient({
    client_id: "demo-public", client_name: "Demo Public Client (PKCE)", grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"], scope: "openid offline_access profile profile.read", audience: ["demo-api"],
    redirect_uris: ["http://localhost:5580/public-callback"], token_endpoint_auth_method: "none", skip_consent: false,
  });
  await upsertClient({
    client_id: "demo-m2m", client_name: "Demo Machine Client", client_secret: env("DEMO_M2M_CLIENT_SECRET"),
    grant_types: ["client_credentials"], response_types: [], scope: "reports.read", audience: ["demo-api"],
    token_endpoint_auth_method: "client_secret_basic",
  });

  // ------------------------------------------------------- dev administrator
  const email = env("DEV_ADMIN_EMAIL");
  const found = await call("GET", `${KRATOS}/admin/identities?credentials_identifier=${encodeURIComponent(email)}`);
  let adminId = Array.isArray(found.data) && found.data[0]?.id;
  if (!adminId) {
    const r = await call("POST", `${KRATOS}/admin/identities`, {
      schema_id: "default",
      traits: { email, name: { first: "Admin", last: "Sviluppo" } },
      credentials: { password: { config: { password: env("DEV_ADMIN_PASSWORD") } } },
      verifiable_addresses: [{ value: email, verified: true, via: "email", status: "completed" }],
    });
    if (r.status >= 300) throw new Error(`create admin: ${r.status} ${JSON.stringify(r.data)}`);
    adminId = r.data.id;
    console.log(`kratos identity ${email}: created`);
  } else {
    console.log(`kratos identity ${email}: exists`);
  }
  const roles = await call("PUT", `${IDS}/internal/roles/${adminId}`, { roles: ["superadmin"], actor: "seed" }, idsHeaders);
  if (roles.status >= 300) throw new Error(`roles: ${roles.status} ${JSON.stringify(roles.data)}`);
  console.log(`identity-service: ${email} -> superadmin`);

  // ------------------------------------- LOCAL TEST federation trust bootstrap
  const taJwks = (await call("GET", `${FEDSIM}/ta/dev/jwks`)).data;
  const taId = `${FEDSIM}/ta`;
  const tas = (await call("GET", `${BROKER}/admin/trust-anchors`, undefined, brokerHeaders)).data ?? [];
  for (const profile of ["spid", "cie"]) {
    const existing = tas.find((t) => t.profile === profile && t.entity_id === taId);
    const body = { profile, entity_id: taId, jwks: taJwks, description: "LOCAL TEST trust anchor (fedsim) — development only", enabled: true };
    const r = existing
      ? await call("PUT", `${BROKER}/admin/trust-anchors/${existing.id}`, body, brokerHeaders)
      : await call("POST", `${BROKER}/admin/trust-anchors`, body, brokerHeaders);
    if (r.status >= 300) throw new Error(`trust anchor ${profile}: ${r.status} ${JSON.stringify(r.data)}`);
    const cfg = (await call("GET", `${BROKER}/admin/profiles/${profile}`, undefined, brokerHeaders)).data.config;
    const tm = (await call("GET", `${FEDSIM}/ta/dev/trust-mark?sub=${encodeURIComponent(cfg.entity_id)}`)).data;
    cfg.trust_marks = [{ id: tm.id, trust_mark: tm.trust_mark }];
    cfg.enabled = true;
    const put = await call("PUT", `${BROKER}/admin/profiles/${profile}`, cfg, brokerHeaders);
    if (put.status >= 300) throw new Error(`profile ${profile}: ${put.status} ${JSON.stringify(put.data)}`);
    console.log(`federation ${profile}: test trust anchor pinned, trust mark installed, profile enabled`);
  }
  await call("POST", `${BROKER}/admin/trust/refresh`, {}, brokerHeaders);

  console.log("\nSeed complete.");
  console.log(`  Admin console:  http://localhost:3100  (login: ${email} / password from DEV_ADMIN_PASSWORD in .env)`);
  console.log("  Demo app:       http://localhost:5580");
  console.log("  Account portal: http://localhost:3200");
  console.log("  Mailpit:        http://localhost:8025");
}

main().catch((err) => {
  console.error(`seed failed: ${err.message}`);
  process.exit(1);
});
