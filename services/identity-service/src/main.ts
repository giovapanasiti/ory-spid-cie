import { timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import pg from "pg";
import { AuditClient, KratosClient, Sealer, createLogger, fastifyLoggerOptions, migrate, waitForDb, z } from "@iam/shared";
import { config } from "./config.js";
import { BrokerClient } from "./broker.js";
import { ConflictError, IdentityService } from "./service.js";

const here = dirname(fileURLToPath(import.meta.url));
const log = createLogger("identity-service");
const pool = new pg.Pool({ connectionString: config.DATABASE_URL, max: 10 });

function tokenOk(h: string | undefined): boolean {
  const m = /^Bearer (.+)$/.exec(h ?? "");
  if (!m?.[1]) return false;
  const a = Buffer.from(m[1]);
  const b = Buffer.from(config.INTERNAL_API_TOKEN);
  return a.length === b.length && timingSafeEqual(a, b);
}

const uuid = z.string().uuid();

async function main() {
  await waitForDb(pool);
  const applied = await migrate(pool, join(here, "..", "migrations"), 727101);
  if (applied.length) log.info({ applied }, "migrations applied");
  if (process.argv.includes("--migrate")) {
    await pool.end();
    return;
  }
  const audit = new AuditClient(config.AUDIT_URL, config.AUDIT_TOKEN, "identity-service", log);
  const svc = new IdentityService({
    pool,
    kratos: new KratosClient(config.KRATOS_PUBLIC_URL, config.KRATOS_ADMIN_URL, config.KRATOS_PUBLIC_URL),
    broker: new BrokerClient(config.BROKER_ADMIN_URL, config.BROKER_INTERNAL_TOKEN),
    sealer: new Sealer(config.FIELD_SEAL_KEYS),
    lookupKey: config.LOOKUP_HMAC_KEY,
    audit,
  });

  const app = Fastify({ logger: fastifyLoggerOptions("identity-service"), bodyLimit: 64 * 1024, requestIdHeader: "x-correlation-id", genReqId: () => crypto.randomUUID() });
  app.get("/healthz", async () => ({ ok: true }));
  app.get("/readyz", async (_req, reply) => {
    try {
      await pool.query("SELECT 1");
      return { ok: true };
    } catch {
      return reply.code(503).send({ ok: false });
    }
  });

  app.register(async (internal) => {
    internal.addHook("onRequest", async (req: FastifyRequest, reply: FastifyReply) => {
      if (!tokenOk(req.headers.authorization)) return reply.code(401).send({ error: "unauthorized" });
    });
    internal.setErrorHandler((err, req, reply) => {
      if (err instanceof ConflictError) return reply.code(409).send({ error: "conflict", message: err.message });
      if (err instanceof z.ZodError) return reply.code(400).send({ error: "invalid_request", issues: err.issues.map((i) => i.path.join(".")) });
      req.log.error({ err: String(err) }, "request failed");
      return reply.code(500).send({ error: "server_error" });
    });

    const resolveBody = z.object({
      identity_id: uuid,
      session_id: uuid,
      authenticated_at: z.string().optional(),
      authentication_methods: z.array(z.object({ method: z.string(), aal: z.string().optional(), completed_at: z.string().optional(), provider: z.string().optional() })).max(50),
    });
    internal.post("/internal/assurance/resolve", async (req) => {
      const body = resolveBody.parse(req.body);
      return svc.resolveAssurance({ ...body, correlation_id: req.id });
    });
    internal.get("/internal/identities/:id/links", async (req) => svc.links(uuid.parse((req.params as { id: string }).id)));
    internal.post("/internal/identities/:id/links/sync", async (req) => svc.syncLinks(uuid.parse((req.params as { id: string }).id), req.id));
    internal.get("/internal/identities/:id/attributes", async (req) => svc.verifiedAttributes(uuid.parse((req.params as { id: string }).id)));
    internal.get("/internal/identities/search", async (req) => {
      const q = z.object({ name: z.enum(["fiscal_number", "email"]), value: z.string().min(3).max(320) }).parse(req.query);
      return { identity_ids: await svc.findByAttribute(q.name, q.value) };
    });
    internal.get("/internal/roles", async (req) => svc.listRoleAssignments(z.object({ role: z.string().optional() }).parse(req.query).role));
    internal.get("/internal/roles/:id", async (req) => ({ roles: await svc.roles(uuid.parse((req.params as { id: string }).id)) }));
    internal.put("/internal/roles/:id", async (req) => {
      const body = z.object({ roles: z.array(z.string()).max(10), actor: z.string().min(1).max(128) }).parse(req.body);
      return { roles: await svc.setRoles(uuid.parse((req.params as { id: string }).id), body.roles, body.actor, req.id) };
    });
  });

  await app.listen({ host: "0.0.0.0", port: config.PORT });
  const shutdown = async () => {
    await app.close();
    await pool.end();
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((err) => {
  log.error({ err: String(err) }, "fatal");
  process.exit(1);
});
