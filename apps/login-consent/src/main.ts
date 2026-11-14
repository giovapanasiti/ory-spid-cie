import {
  AuditClient,
  Csrf,
  HydraAdmin,
  IdentityServiceClient,
  KratosClient,
  Sealer,
  bool,
  createLogger,
  csv,
  loadConfig,
  port,
  secret,
  z,
} from "@iam/shared";
import { buildApp } from "./app.js";

const c = loadConfig(
  z.object({
    PORT: port(3000),
    PUBLIC_URL: z.string().url(),
    KRATOS_PUBLIC_URL: z.string().url(),
    KRATOS_BROWSER_URL: z.string().url(),
    KRATOS_ADMIN_URL: z.string().url(),
    HYDRA_ADMIN_URL: z.string().url(),
    IDENTITY_SERVICE_URL: z.string().url(),
    IDENTITY_SERVICE_TOKEN: secret(32),
    COOKIE_SEAL_KEYS: z.string().min(10),
    CSRF_SECRET: secret(32),
    SECURE_COOKIES: bool(true),
    REMEMBER_LOGIN_SECONDS: z.coerce.number().int().min(0).max(86400).default(3600),
    REMEMBER_CONSENT_SECONDS: z.coerce.number().int().min(0).max(31536000).default(2592000),
    ALLOWED_ORIGINS: csv(),
    AUDIT_URL: z.string().optional(),
    AUDIT_TOKEN: z.string().optional(),
  }),
);
const log = createLogger("login-consent");
const app = await buildApp(
  {
    publicUrl: c.PUBLIC_URL.replace(/\/$/, ""),
    kratosBrowserUrl: c.KRATOS_BROWSER_URL,
    secureCookies: c.SECURE_COOKIES,
    rememberLoginSeconds: c.REMEMBER_LOGIN_SECONDS,
    rememberConsentSeconds: c.REMEMBER_CONSENT_SECONDS,
    allowedOrigins: c.ALLOWED_ORIGINS,
  },
  {
    kratos: new KratosClient(c.KRATOS_PUBLIC_URL, c.KRATOS_ADMIN_URL, c.KRATOS_BROWSER_URL),
    hydra: new HydraAdmin(c.HYDRA_ADMIN_URL),
    identity: new IdentityServiceClient(c.IDENTITY_SERVICE_URL, c.IDENTITY_SERVICE_TOKEN),
    audit: new AuditClient(c.AUDIT_URL, c.AUDIT_TOKEN, "login-consent", log),
    csrf: new Csrf(c.CSRF_SECRET),
    sealer: new Sealer(c.COOKIE_SEAL_KEYS),
  },
);
app.listen({ host: "0.0.0.0", port: c.PORT }).catch((err) => {
  log.error({ err: String(err) }, "fatal");
  process.exit(1);
});
