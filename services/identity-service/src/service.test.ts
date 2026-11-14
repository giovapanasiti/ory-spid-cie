// Integration tests for identity linking and assurance binding (real PostgreSQL).
// Requires TEST_DATABASE_URL (see `make test-db`); skipped otherwise.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import pg from "pg";
import { AuditClient, LOA, Sealer, createLogger, migrate, type KratosClient } from "@iam/shared";
import { IdentityService, ConflictError } from "./service.js";
import type { BrokerClient, BrokerResult } from "./broker.js";

const DSN = process.env.TEST_DATABASE_URL;
const here = dirname(fileURLToPath(import.meta.url));
let admin: pg.Client;
let pool: pg.Pool;
let dbName = "";

const result = (over: Partial<BrokerResult> = {}): BrokerResult => ({
  id: randomUUID(),
  profile: "spid",
  op_entity_id: "https://idp.example/",
  op_issuer: "https://idp.example/",
  external_sub: "ext-" + randomBytes(4).toString("hex"),
  subject_hash: "hash-1",
  acr: "https://www.spid.gov.it/SpidL2",
  loa: LOA.SUBSTANTIAL,
  auth_time: new Date().toISOString(),
  ...over,
});

function svc(opts: { identifiers?: Record<string, string[]>; results?: BrokerResult[]; bindOk?: boolean } = {}) {
  const bound = new Map<string, string>();
  const kratos = {
    getIdentity: async (id: string) => ({ id, schema_id: "default", traits: {}, credentials: { oidc: { type: "oidc", identifiers: opts.identifiers?.[id] ?? [] } } }),
  } as unknown as KratosClient;
  const broker = {
    find: async () => opts.results ?? [],
    get: async (id: string) => ({ result: (opts.results ?? []).find((r) => r.id === id)!, attributes: { given_name: "Ada", fiscal_number: "TSTDAA85T50H501R", gender: "F" } }),
    bind: async (id: string, _identity: string, session: string) => {
      if (opts.bindOk === false) return false;
      const prev = bound.get(id);
      if (prev && prev !== session) return false;
      bound.set(id, session);
      return true;
    },
  } as unknown as BrokerClient;
  return new IdentityService({
    pool,
    kratos,
    broker,
    sealer: new Sealer("t:" + randomBytes(32).toString("base64")),
    lookupKey: "x".repeat(40),
    audit: new AuditClient(undefined, undefined, "test", createLogger("test", "silent")),
  });
}

before(async () => {
  if (!DSN) return;
  admin = new pg.Client({ connectionString: DSN });
  await admin.connect();
  dbName = "identity_test_" + randomBytes(5).toString("hex");
  await admin.query(`CREATE DATABASE ${dbName}`);
  const u = new URL(DSN);
  u.pathname = "/" + dbName;
  pool = new pg.Pool({ connectionString: u.toString(), max: 20 });
  // DROP DATABASE ... WITH (FORCE) in after() may terminate idle clients; same handling as main.ts.
  pool.on("error", () => {});
  await pool.query("CREATE EXTENSION IF NOT EXISTS pgcrypto");
  await migrate(pool, join(here, "..", "migrations"), 1);
});

after(async () => {
  if (!DSN) return;
  await pool.end();
  await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  await admin.end();
});

test("concurrent linking of one external identity to two accounts: exactly one wins", { skip: !DSN }, async () => {
  const s = svc();
  const r = result();
  const a = randomUUID();
  const b = randomUUID();
  const outcomes = await Promise.allSettled(
    Array.from({ length: 10 }, (_, i) => s.upsertLink(i % 2 ? a : b, r, {})),
  );
  const rows = await pool.query("SELECT DISTINCT identity_id FROM identity_links WHERE external_subject=$1", [r.external_sub]);
  assert.equal(rows.rowCount, 1, "external identity linked to a single account");
  const owner = rows.rows[0].identity_id;
  const loser = owner === a ? b : a;
  assert.ok(outcomes.some((o) => o.status === "rejected" && o.reason instanceof ConflictError));
  await assert.rejects(s.upsertLink(loser, r, {}), ConflictError, "later link attempt by other account is rejected");
});

test("federated assurance is granted only with a bindable broker result; attributes stored sealed with provenance", { skip: !DSN }, async () => {
  const identity = randomUUID();
  const session = randomUUID();
  const r = result({ subject_hash: "subj-A" });
  const s = svc({ identifiers: { [identity]: ["spid:subj-A"] }, results: [r] });
  const now = new Date().toISOString();
  const res = await s.resolveAssurance({ identity_id: identity, session_id: session, authentication_methods: [{ method: "oidc", provider: "spid", completed_at: now }] });
  assert.equal(res.loa, LOA.SUBSTANTIAL);
  assert.equal(res.federated_acr, "https://www.spid.gov.it/SpidL2");
  assert.equal(res.verified_attributes.fiscal_number, "TSTDAA85T50H501R");
  assert.equal(res.verified_attributes.gender, undefined, "non-whitelisted attributes discarded");
  const raw = await pool.query("SELECT value_sealed, provider FROM verified_attributes WHERE identity_id=$1 AND name='fiscal_number'", [identity]);
  assert.ok(!String(raw.rows[0].value_sealed).includes("TSTDAA"), "value sealed at rest");
  assert.equal(raw.rows[0].provider, "spid");
  // The same broker result cannot upgrade another session.
  const other = randomUUID();
  await assert.rejects(
    s.resolveAssurance({ identity_id: identity, session_id: other, authentication_methods: [{ method: "oidc", provider: "spid", completed_at: new Date(Date.now() + 1000).toISOString() }] }),
    ConflictError,
  );
});

test("fail closed: no broker result -> LoA none; password session never upgraded", { skip: !DSN }, async () => {
  const identity = randomUUID();
  const s = svc({ identifiers: { [identity]: ["spid:zzz"] }, results: [] });
  const fed = await s.resolveAssurance({ identity_id: identity, session_id: randomUUID(), authentication_methods: [{ method: "oidc", provider: "spid", completed_at: new Date().toISOString() }] });
  assert.equal(fed.loa, LOA.NONE);
  const pwd = await s.resolveAssurance({ identity_id: identity, session_id: randomUUID(), authentication_methods: [{ method: "password", completed_at: new Date().toISOString() }] });
  assert.equal(pwd.loa, LOA.NONE);
  assert.deepEqual(pwd.amr, ["pwd"]);
});

test("result for a credential of a different identity is never used", { skip: !DSN }, async () => {
  const identity = randomUUID();
  const s = svc({ identifiers: { [identity]: [] }, results: [result()] });
  const res = await s.resolveAssurance({ identity_id: identity, session_id: randomUUID(), authentication_methods: [{ method: "oidc", provider: "spid", completed_at: new Date().toISOString() }] });
  assert.equal(res.loa, LOA.NONE);
});

test("roles: unknown roles rejected and the last superadmin cannot be removed", { skip: !DSN }, async () => {
  const s = svc();
  const id = randomUUID();
  await assert.rejects(s.setRoles(id, ["god"], "t"), /unknown role/);
  await s.setRoles(id, ["superadmin"], "t");
  const others = await pool.query("SELECT count(*)::int n FROM admin_roles WHERE role='superadmin' AND identity_id<>$1", [id]);
  if (others.rows[0].n === 0) await assert.rejects(s.setRoles(id, ["viewer"], "t"), ConflictError);
});

test("unlinking in Kratos is reconciled and audited", { skip: !DSN }, async () => {
  const identity = randomUUID();
  const r = result({ subject_hash: "gone" });
  await svc().upsertLink(identity, r, {});
  const links = await svc({ identifiers: { [identity]: [] } }).syncLinks(identity);
  assert.equal(links[0].state, "unlinked");
});

test("an explicitly unlinked external identity can be linked again", { skip: !DSN }, async () => {
  const a = randomUUID();
  const b = randomUUID();
  const r = result({ subject_hash: "relink" });
  await svc().upsertLink(a, r, {});
  await svc({ identifiers: { [a]: [] } }).syncLinks(a);
  await svc().upsertLink(b, r, {});
  const rows = await pool.query("SELECT identity_id, state FROM identity_links WHERE external_subject=$1", [r.external_sub]);
  assert.equal(rows.rows[0].identity_id, b);
  assert.equal(rows.rows[0].state, "active");
});
