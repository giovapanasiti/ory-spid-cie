import { loadConfig, z, secret, port, url } from "@iam/shared";

export const config = loadConfig(
  z.object({
    PORT: port(4000),
    DATABASE_URL: z.string().min(1),
    INTERNAL_API_TOKEN: secret(32),
    KRATOS_PUBLIC_URL: url(),
    KRATOS_ADMIN_URL: url(),
    BROKER_ADMIN_URL: url(),
    BROKER_INTERNAL_TOKEN: secret(32),
    FIELD_SEAL_KEYS: z.string().min(10),
    LOOKUP_HMAC_KEY: secret(32),
    AUDIT_URL: z.string().optional(),
    AUDIT_TOKEN: z.string().optional(),
  }),
);
export type Config = typeof config;
