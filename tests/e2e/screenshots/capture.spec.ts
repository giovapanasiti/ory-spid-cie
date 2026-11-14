// Captures the screenshots used in README.md. Uses only the LOCAL test federation and synthetic users.
import { test, expect } from "@playwright/test";
import { URLS, dotenv } from "../specs/env";
import { chooseIdp, maybeConsent, opLogin } from "../specs/helpers";

const OUT = new URL("../../../docs/images/", import.meta.url).pathname;
const shot = (page: import("@playwright/test").Page, name: string) => page.screenshot({ path: `${OUT}${name}.png`, fullPage: false });

test.describe.configure({ mode: "serial" });

test("user flow: login, SPID, demo app, portal", async ({ page }) => {
  await page.goto(`${URLS.login}/auth/login`);
  await expect(page.getByRole("button", { name: "Accedi con SPID" })).toBeVisible();
  await shot(page, "01-login");

  await page.goto(URLS.demo);
  await shot(page, "02-demo-home");
  await page.getByRole("link", { name: "Accedi", exact: true }).click();
  await page.getByRole("button", { name: "Accedi con SPID" }).click();
  await expect(page.locator("h1")).toContainText(/SPID/);
  await shot(page, "03-spid-idp-chooser");
  await chooseIdp(page, /SPID Test IdP \(locale\)/);
  await expect(page.locator(".banner")).toContainText("LOCAL TEST");
  await page.selectOption("#user", "u2");
  await page.selectOption("#acr", "https://www.spid.gov.it/SpidL2");
  await shot(page, "04-fedsim-op-login");
  await opLogin(page, { user: "u2", acr: "https://www.spid.gov.it/SpidL2" });
  await maybeConsent(page);
  await expect(page.locator("h1")).toContainText("Benvenuto");
  await shot(page, "05-demo-welcome-spid");

  await page.getByRole("button", { name: /GET \/api\/sensitive/ }).click();
  await expect(page.locator("h3")).toBeVisible();
  await page.locator("h3").scrollIntoViewIfNeeded();
  await page.evaluate(() => window.scrollBy(0, 200));
  await shot(page, "06-demo-api-stepup");

  await page.goto(URLS.portal);
  await expect(page.locator("body")).toContainText("Dati verificati");
  await shot(page, "07-portal");
});

test("step-up page for high assurance", async ({ page }) => {
  await page.goto(`${URLS.demo}/login?level=high`);
  await expect(page.locator(".msg.warn")).toBeVisible();
  await shot(page, "08-login-stepup-high");
});

test("admin console and federation UI", async ({ page }) => {
  await page.goto(URLS.admin);
  const form = page.locator('form[data-group="password"]');
  await form.locator('input[name="identifier"]').fill(dotenv("DEV_ADMIN_EMAIL"));
  await form.locator('input[name="password"]').fill(dotenv("DEV_ADMIN_PASSWORD"));
  await form.locator('button[type="submit"]').first().click();
  await expect(page.locator("h1")).toContainText("Dashboard");
  await shot(page, "10-admin-dashboard");

  const pages: Array<[string, string]> = [
    ["/federation", "11-federation-overview"],
    ["/federation/profile/spid", "12-federation-profile-spid"],
    ["/federation/keys", "13-federation-keys"],
    ["/federation/trust-anchors", "14-federation-trust-anchors"],
    ["/federation/providers", "15-federation-providers"],
    ["/federation/entity-configuration/spid", "16-federation-entity-configuration"],
    ["/federation/diagnostics", "17-federation-diagnostics"],
    ["/users", "18-admin-users"],
    ["/clients", "19-admin-clients"],
    ["/audit", "20-admin-audit"],
  ];
  for (const [path, name] of pages) {
    await page.goto(`${URLS.admin}${path}`);
    await page.waitForLoadState("networkidle");
    await shot(page, name);
  }
});
