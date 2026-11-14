import { createTokenValidator } from "@iam/auth-sdk";
import { loadConfig, port, z, createLogger, bool } from "@iam/shared";
import { buildApp } from "./app.js";

const config = loadConfig(
  z.object({
    PORT: port(5600),
    OAUTH2_ISSUER: z.string().url(),
    OAUTH2_JWKS_URL: z.string().url(),
    OAUTH2_AUDIENCE: z.string().min(1).default("demo-api"),
    HYDRA_ADMIN_URL: z.string().url().optional(),
    ALWAYS_INTROSPECT: bool(false),
  }),
);
const log = createLogger("demo-api");
const validator = createTokenValidator({
  issuer: config.OAUTH2_ISSUER,
  jwksUrl: config.OAUTH2_JWKS_URL,
  audience: config.OAUTH2_AUDIENCE,
  hydraAdminUrl: config.HYDRA_ADMIN_URL,
  alwaysIntrospect: config.ALWAYS_INTROSPECT,
});
buildApp(validator)
  .listen({ host: "0.0.0.0", port: config.PORT })
  .catch((err) => {
    log.error({ err: String(err) }, "fatal");
    process.exit(1);
  });
