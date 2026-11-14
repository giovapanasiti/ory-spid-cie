import { test, expect, request } from "@playwright/test";
import { URLS, dotenv } from "./env";
import { chooseIdp, chooseIdpIfAsked, maybeConsent, opLogin } from "./helpers";

test.describe.configure({ mode: "serial" });

test("login page offers SPID, CIE, passkey and password", async ({ page }) => {
  await page.goto(`${URLS.login}/auth/login`);
  await expect(page.getByRole("button", { name: "Accedi con SPID" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Entra con CIE" })).toBeVisible();
  await expect(page.locator('[data-ory-onclick="oryPasskeyLogin"]')).toBeVisible();
  await expect(page.locator('input[name="password"]')).toBeVisible();
});

test("password registration, OIDC login via Hydra, protected API, refresh rotation, logout", async ({ page }) => {
  const email = `user${Date.now()}@example.org`;
  await page.goto(`${URLS.login}/auth/registration`);
  await page.fill('input[name="traits.email"]', email);
  await page.fill('input[name="traits.name.first"]', "Mario");
  await page.fill('input[name="traits.name.last"]', "Prova");
  const pw = page.locator('input[name="password"]');
  if (await pw.count()) {
    await pw.fill("Correct-Horse-Battery-9!");
    await page.locator('form[data-group="password"] button[type="submit"]').first().click();
  } else {
    // two-step registration (profile first)
    await page.locator('form[data-group="profile"] button[type="submit"]').first().click();
    await page.fill('input[name="password"]', "Correct-Horse-Battery-9!");
    await page.locator('form[data-group="password"] button[type="submit"]').first().click();
  }
  await page.waitForLoadState("domcontentloaded");

  await page.goto(URLS.demo);
  await page.getByRole("link", { name: "Accedi", exact: true }).click();
  await maybeConsent(page);
  await expect(page.locator("h1")).toContainText("Benvenuto");
  await expect(page.locator("body")).toContainText("urn:iam:loa:none");

  await page.getByRole("button", { name: "GET /api/profile" }).click();
  await expect(page.locator("h3")).toContainText("200");
  await page.getByRole("button", { name: /GET \/api\/sensitive/ }).click();
  await expect(page.locator("h3")).toContainText("401");
  await expect(page.locator("body")).toContainText("insufficient_user_authentication");

  await page.getByRole("button", { name: /Rinnova token/ }).click();
  await expect(page.locator("pre")).toContainText('"rotated": true');

  await page.getByRole("button", { name: "Esci" }).click();
  await page.click('button[value="accept"]');
  await page.waitForURL(`${URLS.demo}/`);
  await expect(page.getByRole("link", { name: "Accedi", exact: true })).toBeVisible();
});

test("SPID login (substantial) creates a federated identity with verified attributes", async ({ page }) => {
  await page.goto(URLS.demo);
  await page.getByRole("link", { name: "Accedi", exact: true }).click();
  await page.getByRole("button", { name: "Accedi con SPID" }).click();
  await chooseIdp(page, /SPID Test IdP \(locale\)/);
  await opLogin(page, { user: "u2", acr: "https://www.spid.gov.it/SpidL2" });
  await maybeConsent(page);
  await expect(page.locator("h1")).toContainText("Benvenuto");
  await expect(page.locator("body")).toContainText("urn:iam:loa:substantial");
  await expect(page.locator("body")).toContainText("https://www.spid.gov.it/SpidL2");
  await expect(page.locator("body")).toContainText("PRVBRN79C02F205X"); // fiscal_number scope, verified attribute

  await page.goto(URLS.portal);
  await expect(page.locator("body")).toContainText("Dati verificati");
  await expect(page.locator("body")).toContainText("SPID");
});

test("step-up: high assurance restricted to SPID/CIE and enforced by the API", async ({ page }) => {
  await page.goto(`${URLS.demo}/login?level=high`);
  await expect(page.locator(".msg.warn")).toContainText("high");
  await expect(page.locator('input[name="password"]')).toHaveCount(0);
  await page.getByRole("button", { name: "Entra con CIE" }).click();
  await chooseIdpIfAsked(page, /CIE Test OP \(locale\)/);
  await opLogin(page, { user: "u1", acr: "https://www.spid.gov.it/SpidL3" });
  await maybeConsent(page);
  await expect(page.locator("body")).toContainText("urn:iam:loa:high");
  await page.getByRole("button", { name: /GET \/api\/sensitive/ }).click();
  await expect(page.locator("h3")).toContainText("200");
});

test("CIE with insufficient level is rejected (no silent downgrade)", async ({ page }) => {
  await page.goto(`${URLS.demo}/login?level=high`);
  await page.getByRole("button", { name: "Entra con CIE" }).click();
  await chooseIdpIfAsked(page, /CIE Test OP \(locale\)/);
  await opLogin(page, { user: "u3", acr: "https://www.spid.gov.it/SpidL2" });
  await expect(page.locator("body")).toContainText(/livello di autenticazione ottenuto non è sufficiente|Insufficient/i);
});

test("SPID cancellation is handled gracefully", async ({ page }) => {
  await page.goto(`${URLS.login}/auth/login`);
  await page.getByRole("button", { name: "Accedi con SPID" }).click();
  await chooseIdp(page, /SPID Test IdP \(locale\)/);
  await opLogin(page, { cancel: true });
  await expect(page.locator("body")).toContainText(/annullata|cancelled/i);
});

test("invalid ID token signature from IdP is rejected", async ({ page }) => {
  await page.goto(`${URLS.login}/auth/login`);
  await page.getByRole("button", { name: "Accedi con SPID" }).click();
  await chooseIdp(page, /SPID Test IdP 2/);
  await opLogin(page, { scenario: "bad_signature" });
  await expect(page.locator("body")).toContainText(/Risposta non valida|Invalid identity provider response/);
});

test("machine-to-machine client credentials", async () => {
  const ctx = await request.newContext();
  const basic = Buffer.from(`demo-m2m:${dotenv("DEMO_M2M_CLIENT_SECRET")}`).toString("base64");
  const tok = await ctx.post(`${URLS.hydra}/oauth2/token`, {
    form: { grant_type: "client_credentials", scope: "reports.read", audience: "demo-api" },
    headers: { authorization: `Basic ${basic}` },
  });
  expect(tok.status()).toBe(200);
  const { access_token } = await tok.json();
  const ok = await ctx.get(`${URLS.api}/api/reports`, { headers: { authorization: `Bearer ${access_token}` } });
  expect(ok.status()).toBe(200);
  const wrongKind = await ctx.get(`${URLS.api}/api/profile`, { headers: { authorization: `Bearer ${access_token}` } });
  expect(wrongKind.status()).toBe(403);
  // revocation is honoured (API introspects)
  await ctx.post(`${URLS.hydra}/oauth2/revoke`, { form: { token: access_token }, headers: { authorization: `Basic ${basic}` } });
  const revoked = await ctx.get(`${URLS.api}/api/reports`, { headers: { authorization: `Bearer ${access_token}` } });
  expect(revoked.status()).toBe(401);
});

test("admin console: RBAC-protected federation administration (keys, certificates, metadata)", async ({ page }) => {
  await page.goto(URLS.admin);
  const form = page.locator('form[data-group="password"]');
  await form.locator('input[name="identifier"]').fill(dotenv("DEV_ADMIN_EMAIL"));
  await form.locator('input[name="password"]').fill(dotenv("DEV_ADMIN_PASSWORD"));
  await form.locator('button[type="submit"]').first().click();
  await expect(page.locator("h1")).toContainText("Dashboard");

  await page.goto(`${URLS.admin}/federation`);
  await expect(page.locator("body")).toContainText("trust chain valida");

  await page.goto(`${URLS.admin}/federation/profile/spid`);
  await expect(page.locator('input[name="entity_id"]')).toHaveValue("http://broker.localhost:8090/rp/spid");
  await page.fill('input[name="client_name"]', "IAM Platform (dev e2e)");
  await page.getByRole("button", { name: "Salva profilo" }).click();
  await expect(page.locator(".msg.success")).toContainText("Profilo salvato");

  await page.goto(`${URLS.admin}/federation/keys`);
  await page.locator('form[action="/federation/keys/generate"] select[name="target"]').selectOption("spid/core-sig");
  await page.locator('form[action="/federation/keys/generate"] button').click();
  await expect(page.locator(".msg.success")).toContainText("generata");

  await page.goto(`${URLS.admin}/federation/entity-configuration/spid`);
  await expect(page.locator("pre").first()).toContainText("openid_relying_party");

  await page.goto(`${URLS.admin}/clients`);
  await expect(page.locator("body")).toContainText("demo-web");
});

test("admin console rejects users without roles and cross-site POSTs", async ({ page }) => {
  const ctx = await request.newContext();
  const r = await ctx.post(`${URLS.admin}/federation/keys/generate`, { form: { target: "spid/core-sig" }, maxRedirects: 0 });
  expect([302, 401, 403]).toContain(r.status());
  await page.goto(`${URLS.admin}/federation`);
  await expect(page).toHaveURL(/localhost:4455\/auth\/login|localhost:4444/);
});
