import js from "@eslint/js";
import tseslint from "typescript-eslint";
import globals from "globals";

export default tseslint.config(
  { ignores: ["**/dist/**", "**/node_modules/**", "coverage/**", "services/federation-broker/**", "tests/e2e/playwright-report/**", "tests/e2e/test-results/**", "infrastructure/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { files: ["**/*.mjs", "**/*.js"], languageOptions: { globals: globals.node } },
  {
    files: ["**/*.ts"],
    rules: {
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      "@typescript-eslint/no-explicit-any": "error",
      "no-eval": "error",
      "no-implied-eval": "error",
    },
  },
);
