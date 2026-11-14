// Login through the REFERENCE TEST federation: the broker talks to the official reference
// implementation (italia/spid-cie-oidc-django) SPID OP and CIE OP with real trust chains,
// signed request objects, private_key_jwt and encrypted UserInfo. Public demo user: user/oidcuser.
// Passing these tests is interoperability evidence against the reference code, NOT conformance.
import { test, expect, type Page } from "@playwright/test";
import { URLS } from "../specs/env";
import { maybeConsent } from "../specs/helpers";

test.describe.configure({ mode: "serial" });

async function referenceOpLogin(page: Page, host: RegExp) {
  await page.waitForURL(host, { timeout: 60_000 });
  await page.fill('input[name="username"]', "user");
  await page.fill('input[name="password"]', "oidcuser");
  await page.click("#submit");
  // Reference OP consent page (attributes released to the RP).
  await page.waitForSelector("#agree", { timeout: 60_000 });
  await page.click("#agree");
}

test("SPID login via the reference SPID OP", async ({ page }) => {
  await page.goto(URLS.demo);
  await page.getByRole("link", { name: "Accedi", exact: true }).click();
  await page.getByRole("button", { name: "Accedi con SPID" }).click();
  await page.getByRole("button", { name: /SPID OP di riferimento/ }).click();
  await referenceOpLogin(page, /trust-anchor\.localhost:8000\/oidc\/op/);
  await maybeConsent(page);
  await expect(page.locator("h1")).toContainText("Benvenuto");
  await expect(page.locator("body")).toContainText("urn:iam:loa:substantial");
  await expect(page.locator("body")).toContainText("https://www.spid.gov.it/SpidL2");
  await expect(page.locator("body")).toContainText("RSSNTN80R10F839Z");
  await page.getByRole("button", { name: "Esci" }).click();
  await page.click('button[value="accept"]');
});

test("CIE login (step-up to high) via the reference CIE OP", async ({ page }) => {
  await page.goto(`${URLS.demo}/login?level=high`);
  await page.getByRole("button", { name: "Entra con CIE" }).click();
  await page.getByRole("button", { name: /CIE OP di riferimento/ }).click();
  await referenceOpLogin(page, /cie-provider\.localhost:8002\/oidc\/op/);
  await maybeConsent(page);
  await expect(page.locator("h1")).toContainText("Benvenuto");
  await expect(page.locator("body")).toContainText("urn:iam:loa:high");
  await page.getByRole("button", { name: /GET \/api\/sensitive/ }).click();
  await expect(page.locator("h3")).toContainText("200");
});
