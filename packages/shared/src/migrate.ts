import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Pool } from "pg";

/** Applies *.sql migrations in lexical order exactly once, serialised with an advisory lock. */
export async function migrate(pool: Pool, dir: string, lockId: number): Promise<string[]> {
  const files = (await readdir(dir)).filter((f) => f.endsWith(".sql")).sort();
  const client = await pool.connect();
  const applied: string[] = [];
  try {
    await client.query("SELECT pg_advisory_lock($1)", [lockId]);
    await client.query("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())");
    for (const f of files) {
      const { rowCount } = await client.query("SELECT 1 FROM schema_migrations WHERE version=$1", [f]);
      if (rowCount) continue;
      const sql = await readFile(join(dir, f), "utf8");
      await client.query("BEGIN");
      try {
        await client.query(sql);
        await client.query("INSERT INTO schema_migrations(version) VALUES ($1)", [f]);
        await client.query("COMMIT");
        applied.push(f);
      } catch (err) {
        await client.query("ROLLBACK");
        throw new Error(`migration ${f} failed: ${String(err)}`, { cause: err });
      }
    }
  } finally {
    await client.query("SELECT pg_advisory_unlock($1)", [lockId]).catch(() => undefined);
    client.release();
  }
  return applied;
}

/** Waits for the database to accept connections. */
export async function waitForDb(pool: Pool, attempts = 30): Promise<void> {
  for (let i = 0; i < attempts; i++) {
    try {
      await pool.query("SELECT 1");
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  throw new Error("database not reachable");
}
