import Fastify, { type FastifyInstance } from "fastify";
import { requireAuth, type TokenValidator } from "@iam/auth-sdk";
import { fastifyLoggerOptions, LOA } from "@iam/shared";

/** Demonstration protected API (resource server). */
export function buildApp(validator: TokenValidator, opts: { logger?: boolean } = {}): FastifyInstance {
  const app = Fastify({ logger: opts.logger === false ? false : fastifyLoggerOptions("demo-api"), bodyLimit: 16 * 1024 });
  app.addHook("onSend", async (_req, reply) => {
    reply.header("cache-control", "no-store");
    reply.header("x-content-type-options", "nosniff");
  });
  app.get("/healthz", async () => ({ ok: true }));
  app.get("/api/public", async () => ({ message: "public data, no token required" }));

  app.get("/api/profile", { preHandler: requireAuth(validator, { kind: "user", scopes: ["profile.read"] }) }, async (req) => {
    const p = req.principal!;
    return { subject: p.subject, client: p.clientId, loa: p.loa ?? LOA.NONE, amr: p.amr ?? [], scopes: p.scopes };
  });

  // Sensitive operation: requires recent (≤ 5 min) high-assurance authentication (SPID L3 / CIE L3).
  app.get(
    "/api/sensitive",
    { preHandler: requireAuth(validator, { kind: "user", scopes: ["profile.read"], minLoA: LOA.HIGH, maxAuthAgeSeconds: 300 }) },
    async (req) => ({ message: "high-assurance operation authorised", subject: req.principal!.subject, loa: req.principal!.loa }),
  );

  // Machine-to-machine endpoint (client_credentials).
  app.get("/api/reports", { preHandler: requireAuth(validator, { kind: "machine", scopes: ["reports.read"] }) }, async (req) => ({
    client: req.principal!.clientId,
    reports: [{ id: 1, name: "daily-logins", value: 42 }],
  }));
  return app;
}
