import { defineConfig, devices } from "@playwright/test";

// Captures the README screenshots (docs/images) from the running local stack (`make dev`).
// Run with: cd tests/e2e && npx playwright test -c screenshots.config.ts
export default defineConfig({
  testDir: "./screenshots",
  timeout: 120_000,
  workers: 1,
  reporter: [["list"]],
  use: { ...devices["Desktop Chrome"], viewport: { width: 1280, height: 860 }, locale: "it-IT" },
});
