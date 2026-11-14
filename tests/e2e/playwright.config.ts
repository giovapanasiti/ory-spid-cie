import { defineConfig, devices } from "@playwright/test";

// End-to-end tests against the running local stack (`make dev`).
export default defineConfig({
  testDir: "./specs",
  timeout: 90_000,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"], ["html", { open: "never" }]],
  use: { ...devices["Desktop Chrome"], trace: "retain-on-failure", screenshot: "only-on-failure" },
});
