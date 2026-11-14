import { timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import pg from "pg";
import { AuditEventSchema, createLogger, fastifyLoggerOptions, loadConfig, migrate, port, secret, waitForDb, z, scrubContext } from "@iam/shared";

const config = loadConfig(
  z.object({
    PORT: port(4100),
    DATABASE_URL: z.string().min(1),
    AUDIT_INGEST_TOKEN: secret(32),
    AUDIT_READ_TOKEN: secret(32),
    AUDIT_RETENTION_DAYS: z.coerce.number().int().min(30).max(3650).default(365),
  }),
);
const here = dirname(fileURLToPath(import.meta.url));
const log = createLogger("audit-service");
const pool = new pg.Pool({ connectionString: config.DATABASE_URL, max: 10 });
// An error on an idle client (database restart, failover, terminated connection) is emitted on
// the pool; without a listener node-postgres crashes the process. The pool drops the client and
// reconnects on the next query.
pool.on("error", (err) => log.warn({ error: err.message }, "postgres idle client error"));

function bearer(req: FastifyRequest, expected: string): boolean {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
  if (!m?.[1]) return false;
  const a = Buffer.from(m[1]);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

export const QuerySchema = z.object({
  type: z.string().max(100).optional(),
  actor: z.string().max(256).optional(),
  outcome: z.enum(["success", "failure"]).optional(),
  service: z.string().max(64).optional(),
  correlation_id: z.string().max(128).optional(),
  since: z.string().datetime({ offset: true }).optional(),
  until: z.string().datetime({ offset: true }).optional(),
  limit: z.coerce.number().int().min(1).max(500).default(100),
});

async function purge(): Promise<void> {
  const r = await pool.query("DELETE FROM audit_events WHERE ts < now() - make_interval(days => $1)", [config.AUDIT_RETENTION_DAYS]);
  if (r.rowCount) log.info({ deleted: r.rowCount, retention_days: config.AUDIT_RETENTION_DAYS }, "audit retention applied");
}

async function main() {
  await waitForDb(pool);
  await migrate(pool, join(here, "..", "migrations"), 727201);
  if (process.argv.includes("--migrate")) {
    await pool.end();
    return;
  }
  const app = Fastify({ logger: fastifyLoggerOptions("audit-service"), bodyLimit: 32 * 1024 });
  app.get("/healthz", async () => ({ ok: true }));
  app.post("/events", async (req, reply) => {
    if (!bearer(req, config.AUDIT_INGEST_TOKEN)) return reply.code(401).send({ error: "unauthorized" });
    const parsed = AuditEventSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_event" });
    const e = parsed.data;
    await pool.query(
      `INSERT INTO audit_events(id, ts, correlation_id, actor, type, outcome, service, context) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO NOTHING`,
      [e.id, e.timestamp, e.correlation_id ?? null, e.actor ?? null, e.type, e.outcome, e.service, scrubContext(e.context) ?? null],
    );
    return reply.code(202).send({ accepted: true });
  });
  app.get("/events", async (req: FastifyRequest, reply: FastifyReply) => {
    if (!bearer(req, config.AUDIT_READ_TOKEN)) return reply.code(401).send({ error: "unauthorized" });
    const q = QuerySchema.safeParse(req.query);
    if (!q.success) return reply.code(400).send({ error: "invalid_query" });
    const f = q.data;
    const where: string[] = [];
    const args: unknown[] = [];
    const add = (sql: string, v: unknown) => {
      args.push(v);
      where.push(sql.replace("?", `$${args.length}`));
    };
    if (f.type) add("type LIKE ?", f.type.replace(/[%_]/g, "") + "%");
    if (f.actor) add("actor = ?", f.actor);
    if (f.outcome) add("outcome = ?", f.outcome);
    if (f.service) add("service = ?", f.service);
    if (f.correlation_id) add("correlation_id = ?", f.correlation_id);
    if (f.since) add("ts >= ?", f.since);
    if (f.until) add("ts <= ?", f.until);
    args.push(f.limit);
    const sql = `SELECT id, ts AS timestamp, correlation_id, actor, type, outcome, service, context FROM audit_events
      ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY ts DESC LIMIT $${args.length}`;
    const r = await pool.query(sql, args);
    return r.rows;
  });
  setInterval(() => void purge().catch((err) => log.error({ err: String(err) }, "retention failed")), 3600_000).unref();
  void purge();
  await app.listen({ host: "0.0.0.0", port: config.PORT });
}

main().catch((err) => {
  log.error({ err: String(err) }, "fatal");
  process.exit(1);
});
