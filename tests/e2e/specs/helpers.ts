import { expect, type Page } from "@playwright/test";

/** Completes the simulated OP login page (LOCAL TEST federation). */
export async function opLogin(page: Page, opts: { user?: string; acr?: string; scenario?: string; cancel?: boolean } = {}) {
  await expect(page.locator(".banner")).toContainText("LOCAL TEST");
  await page.selectOption("#user", opts.user ?? "u1");
  if (opts.acr) await page.selectOption("#acr", opts.acr);
  if (opts.scenario) await page.selectOption("#scenario", opts.scenario);
  await page.click(opts.cancel ? "#cancel" : "#login");
}

/** Accepts the Hydra consent screen if shown. */
export async function maybeConsent(page: Page) {
  await page.waitForURL((u) => u.pathname === "/consent" || u.port === "5580" || u.port === "3100" || u.pathname.startsWith("/auth/"), { timeout: 30_000 });
  if (new URL(page.url()).pathname === "/consent") {
    await page.click('button[value="accept"]');
    await page.waitForURL((u) => u.pathname !== "/consent", { timeout: 30_000 });
  }
}

export async function chooseIdp(page: Page, name: RegExp) {
  await expect(page.locator("h1")).toContainText(/SPID|CIE/);
  await page.getByRole("button", { name }).click();
}
