import { AuditClient, Csrf, HydraAdmin, IdentityServiceClient, KratosClient, Sealer, bool, createLogger, csv, loadConfig, port, secret, z } from "@iam/shared";
import { buildApp } from "./app.js";
import { BrokerAdmin } from "./broker.js";
import { OidcClient } from "./oidc.js";

const c = loadConfig(
  z.object({
    PORT: port(3100),
    PUBLIC_URL: z.string().url(),
    OIDC_ISSUER: z.string().url(),
    OIDC_INTERNAL_URL: z.string().url(),
    OIDC_CLIENT_ID: z.string().min(1),
    OIDC_CLIENT_SECRET: secret(32),
    ADMIN_REQUIRED_LOA: z.string().optional(),
    ADMIN_BOOTSTRAP_EMAILS: csv(),
    KRATOS_PUBLIC_URL: z.string().url(),
    KRATOS_ADMIN_URL: z.string().url(),
    HYDRA_ADMIN_URL: z.string().url(),
    IDENTITY_SERVICE_URL: z.string().url(),
    IDENTITY_SERVICE_TOKEN: secret(32),
    BROKER_ADMIN_URL: z.string().url(),
    BROKER_ADMIN_TOKEN: secret(32),
    AUDIT_URL: z.string().optional(),
    AUDIT_TOKEN: z.string().optional(),
    AUDIT_READ_URL: z.string().optional(),
    AUDIT_READ_TOKEN: z.string().optional(),
    COOKIE_SEAL_KEYS: z.string().min(10),
    CSRF_SECRET: secret(32),
    SECURE_COOKIES: bool(true),
    SESSION_TTL_SECONDS: z.coerce.number().int().min(300).max(43200).default(28800),
  }),
);
const log = createLogger("admin-console");
const publicUrl = c.PUBLIC_URL.replace(/\/$/, "");
const app = await buildApp(
  {
    publicUrl,
    secureCookies: c.SECURE_COOKIES,
    bootstrapEmails: c.ADMIN_BOOTSTRAP_EMAILS.map((e) => e.toLowerCase()),
    requiredLoA: c.ADMIN_REQUIRED_LOA || undefined,
    sessionTtlSeconds: c.SESSION_TTL_SECONDS,
    oidcIssuerOrigin: new URL(c.OIDC_ISSUER).origin,
    auditReadUrl: c.AUDIT_READ_URL,
    auditReadToken: c.AUDIT_READ_TOKEN,
  },
  {
    oidc: new OidcClient({
      issuer: c.OIDC_ISSUER,
      internalUrl: c.OIDC_INTERNAL_URL,
      clientId: c.OIDC_CLIENT_ID,
      clientSecret: c.OIDC_CLIENT_SECRET,
      redirectUri: `${publicUrl}/callback`,
      scope: "openid profile email",
      acrValues: c.ADMIN_REQUIRED_LOA || undefined,
    }),
    kratos: new KratosClient(c.KRATOS_PUBLIC_URL, c.KRATOS_ADMIN_URL, c.KRATOS_PUBLIC_URL),
    hydra: new HydraAdmin(c.HYDRA_ADMIN_URL),
    identity: new IdentityServiceClient(c.IDENTITY_SERVICE_URL, c.IDENTITY_SERVICE_TOKEN),
    broker: new BrokerAdmin(c.BROKER_ADMIN_URL, c.BROKER_ADMIN_TOKEN),
    audit: new AuditClient(c.AUDIT_URL, c.AUDIT_TOKEN, "admin-console", log),
    sealer: new Sealer(c.COOKIE_SEAL_KEYS),
    csrf: new Csrf(c.CSRF_SECRET),
  },
);
app.listen({ host: "0.0.0.0", port: c.PORT }).catch((err) => {
  log.error({ err: String(err) }, "fatal");
  process.exit(1);
});
