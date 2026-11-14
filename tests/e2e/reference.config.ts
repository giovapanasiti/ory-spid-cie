import { defineConfig, devices } from "@playwright/test";

// End-to-end tests against the REFERENCE TEST federation (italia/spid-cie-oidc-django demo).
// Requires `make dev` and `make reference-up`. Run with `make test-e2e-reference`.
export default defineConfig({
  testDir: "./reference",
  timeout: 180_000,
  expect: { timeout: 30_000 },
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: { ...devices["Desktop Chrome"], trace: "retain-on-failure", screenshot: "only-on-failure", navigationTimeout: 60_000 },
});
