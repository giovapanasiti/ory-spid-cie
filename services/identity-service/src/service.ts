import { createHmac } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import {
  LOA,
  isFederated,
  oidcIdentifiers,
  type AuditClient,
  type KratosAuthMethod,
  type KratosClient,
  type Sealer,
} from "@iam/shared";
import type { BrokerClient, BrokerResult } from "./broker.js";

export const ROLES = ["viewer", "support", "client-admin", "federation-admin", "security-auditor", "superadmin"] as const;

/** OIDC amr values (RFC 8176 where applicable) for Kratos methods. */
const AMR: Record<string, string> = {
  password: "pwd",
  passkey: "hwk",
  webauthn: "hwk",
  code: "otp",
  totp: "otp",
  lookup_secret: "kba",
  link_recovery: "email",
  code_recovery: "email",
};

export interface AssuranceResult {
  loa: string;
  acr: string;
  amr: string[];
  provider: string | null;
  federated_acr: string | null;
  auth_time: string | null;
  identity_verified: boolean;
  verified_attributes: Record<string, unknown>;
}

export class ConflictError extends Error {}

/** Attributes persisted as verified (data minimisation: everything else is discarded). */
const KEEP_ATTRIBUTES = ["given_name", "family_name", "fiscal_number", "birthdate", "email", "phone_number", "place_of_birth"];
const LOOKUP_ATTRIBUTES = new Set(["fiscal_number", "email"]);

export interface Deps {
  pool: Pool;
  kratos: KratosClient;
  broker: BrokerClient;
  sealer: Sealer;
  lookupKey: string;
  audit: AuditClient;
}

export class IdentityService {
  constructor(private readonly d: Deps) {}

  lookupHash(name: string, value: string): string {
    return createHmac("sha256", this.d.lookupKey).update(`${name}\u0000${value.trim().toUpperCase()}`).digest("base64url");
  }

  private latestMethod(methods: KratosAuthMethod[]): KratosAuthMethod | undefined {
    return [...methods]
      .filter((m) => m.completed_at)
      .sort((a, b) => Date.parse(b.completed_at!) - Date.parse(a.completed_at!))[0];
  }

  /**
   * Computes the assurance of a Kratos session. Federated assurance is only
   * granted when a broker result for one of the identity's own federated
   * credentials was redeemed by Kratos right before the method completed, and
   * it can be bound to this session exactly once (fail closed otherwise).
   */
  async resolveAssurance(input: {
    identity_id: string;
    session_id: string;
    authenticated_at?: string;
    authentication_methods: KratosAuthMethod[];
    correlation_id?: string;
  }): Promise<AssuranceResult> {
    const latest = this.latestMethod(input.authentication_methods);
    const methodTime = latest?.completed_at ?? input.authenticated_at ?? null;
    const cached = await this.d.pool.query(
      "SELECT * FROM session_assurance WHERE session_id=$1 AND identity_id=$2 AND method_time IS NOT DISTINCT FROM $3",
      [input.session_id, input.identity_id, methodTime],
    );
    if (cached.rowCount) return this.toResult(cached.rows[0], input.identity_id);

    let row: { loa: string; acr: string; amr: string[]; provider: string | null; federated_acr: string | null; auth_time: string | null; result_id: string | null };
    if (latest?.method === "oidc" && isFederated(latest.provider)) {
      row = await this.federated(input.identity_id, input.session_id, latest, input.correlation_id);
    } else {
      // Local methods: identity not proofed in this authentication -> LoA none.
      const amr = [...new Set(input.authentication_methods.map((m) => AMR[m.method] ?? m.method))];
      row = { loa: LOA.NONE, acr: LOA.NONE, amr, provider: null, federated_acr: null, auth_time: methodTime, result_id: null };
    }
    await this.d.pool.query(
      `INSERT INTO session_assurance(session_id, identity_id, method_time, loa, acr, amr, provider, federated_acr, auth_time, result_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT (session_id) DO UPDATE SET method_time=EXCLUDED.method_time, loa=EXCLUDED.loa, acr=EXCLUDED.acr, amr=EXCLUDED.amr,
         provider=EXCLUDED.provider, federated_acr=EXCLUDED.federated_acr, auth_time=EXCLUDED.auth_time, result_id=EXCLUDED.result_id, computed_at=now()
       WHERE session_assurance.identity_id = EXCLUDED.identity_id`,
      [input.session_id, input.identity_id, methodTime, row.loa, row.acr, row.amr, row.provider, row.federated_acr, row.auth_time, row.result_id],
    );
    const saved = await this.d.pool.query("SELECT * FROM session_assurance WHERE session_id=$1", [input.session_id]);
    if (saved.rows[0]?.identity_id !== input.identity_id) throw new ConflictError("session bound to another identity");
    return this.toResult(saved.rows[0], input.identity_id);
  }

  private async federated(identityId: string, sessionId: string, m: KratosAuthMethod, correlationId?: string) {
    const provider = m.provider!;
    const none = { loa: LOA.NONE, acr: LOA.NONE, amr: [provider], provider, federated_acr: null, auth_time: m.completed_at ?? null, result_id: null };
    const identity = await this.d.kratos.getIdentity(identityId, ["oidc"]);
    if (!identity) throw new ConflictError("identity not found");
    const subjects = oidcIdentifiers(identity)
      .filter((c) => c.provider === provider)
      .map((c) => c.subject);
    if (!subjects.length) return none;
    const t = Date.parse(m.completed_at!);
    const results = await this.d.broker.find(subjects, new Date(t - 120_000), new Date(t + 15_000));
    const candidate = results.find(
      (r: BrokerResult) => r.profile === provider && (!r.bound_session_id || r.bound_session_id === sessionId) && (!r.bound_identity_id || r.bound_identity_id === identityId),
    );
    if (!candidate) {
      this.d.audit.emit({ type: "assurance.federated_result_missing", outcome: "failure", actor: identityId, correlationId, context: { provider, session_id: sessionId } });
      return none;
    }
    if (!(await this.d.broker.bind(candidate.id, identityId, sessionId))) {
      this.d.audit.emit({ type: "assurance.bind_conflict", outcome: "failure", actor: identityId, correlationId, context: { provider, result_id: candidate.id } });
      throw new ConflictError("federated authentication already bound to another session");
    }
    const { result, attributes } = await this.d.broker.get(candidate.id);
    await this.upsertLink(identityId, result, attributes, correlationId);
    return {
      loa: result.loa,
      acr: result.loa,
      amr: [provider],
      provider,
      federated_acr: result.acr,
      auth_time: result.auth_time,
      result_id: result.id,
    };
  }

  /** Creates or refreshes the link; refuses if the external identity belongs to another account. */
  async upsertLink(identityId: string, r: BrokerResult, attributes: Record<string, unknown>, correlationId?: string): Promise<void> {
    const client: PoolClient = await this.d.pool.connect();
    try {
      await client.query("BEGIN");
      const ins = await client.query(
        `INSERT INTO identity_links(identity_id, provider, issuer, external_subject, external_subject_hash, last_auth_at, last_loa, last_acr)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (provider, issuer, external_subject) DO UPDATE
           SET identity_id=EXCLUDED.identity_id, last_auth_at=EXCLUDED.last_auth_at, last_loa=EXCLUDED.last_loa,
               last_acr=EXCLUDED.last_acr, state='active', unlinked_at=NULL,
               linked_at=CASE WHEN identity_links.state='unlinked' THEN now() ELSE identity_links.linked_at END
           -- an explicitly unlinked external identity may be linked again (also to another account)
           WHERE identity_links.identity_id = EXCLUDED.identity_id OR identity_links.state = 'unlinked'
         RETURNING id, (xmax = 0) AS inserted`,
        [identityId, r.profile, r.op_issuer, r.external_sub, r.subject_hash, r.auth_time, r.loa, r.acr],
      );
      if (!ins.rowCount) {
        await client.query("ROLLBACK");
        this.d.audit.emit({
          type: "account.link_conflict",
          outcome: "failure",
          actor: identityId,
          correlationId,
          context: { provider: r.profile, issuer: r.op_issuer, subject_hash: r.subject_hash },
        });
        throw new ConflictError("external identity is linked to a different account");
      }
      for (const name of KEEP_ATTRIBUTES) {
        const v = attributes[name];
        if (v === undefined || v === null || v === "") continue;
        const sealed = this.d.sealer.seal(v, `attr:${identityId}:${name}`, 10 * 365 * 86400);
        const lookup = LOOKUP_ATTRIBUTES.has(name) && typeof v === "string" ? this.lookupHash(name, v) : null;
        await client.query(
          `INSERT INTO verified_attributes(identity_id, name, value_sealed, lookup_hash, provider, issuer, loa, verified_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,now())
           ON CONFLICT (identity_id, name) DO UPDATE SET value_sealed=EXCLUDED.value_sealed, lookup_hash=EXCLUDED.lookup_hash,
             provider=EXCLUDED.provider, issuer=EXCLUDED.issuer, loa=EXCLUDED.loa, verified_at=now()`,
          [identityId, name, sealed, lookup, r.profile, r.op_issuer, r.loa],
        );
      }
      await client.query("COMMIT");
      if (ins.rows[0]?.inserted) {
        this.d.audit.emit({ type: "account.linked", outcome: "success", actor: identityId, correlationId, context: { provider: r.profile, issuer: r.op_issuer, loa: r.loa } });
      }
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  async verifiedAttributes(identityId: string): Promise<Record<string, { value: unknown; provider: string; issuer: string; verified_at: string; loa: string }>> {
    const res = await this.d.pool.query("SELECT * FROM verified_attributes WHERE identity_id=$1", [identityId]);
    const out: Record<string, { value: unknown; provider: string; issuer: string; verified_at: string; loa: string }> = {};
    for (const r of res.rows) {
      const value = this.d.sealer.open(r.value_sealed, `attr:${identityId}:${r.name}`);
      if (value === null) continue;
      out[r.name] = { value, provider: r.provider, issuer: r.issuer, verified_at: r.verified_at.toISOString(), loa: r.loa };
    }
    return out;
  }

  private async toResult(row: Record<string, unknown>, identityId: string): Promise<AssuranceResult> {
    const attrs = await this.verifiedAttributes(identityId);
    const flat: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(attrs)) flat[k] = v.value;
    return {
      loa: String(row.loa),
      acr: String(row.acr),
      amr: (row.amr as string[]) ?? [],
      provider: (row.provider as string | null) ?? null,
      federated_acr: (row.federated_acr as string | null) ?? null,
      auth_time: row.auth_time ? new Date(row.auth_time as string).toISOString() : null,
      identity_verified: Object.keys(attrs).length > 0,
      verified_attributes: flat,
    };
  }

  async links(identityId: string) {
    const res = await this.d.pool.query(
      `SELECT id, identity_id, provider, issuer, external_subject_hash, state, last_loa, last_acr, last_auth_at, linked_at, unlinked_at
       FROM identity_links WHERE identity_id=$1 ORDER BY linked_at`,
      [identityId],
    );
    return res.rows;
  }

  /** Reconciles links with Kratos credentials (e.g. after an unlink in Kratos settings). */
  async syncLinks(identityId: string, correlationId?: string) {
    const identity = await this.d.kratos.getIdentity(identityId, ["oidc"]);
    if (!identity) return [];
    const present = new Set(oidcIdentifiers(identity).map((c) => `${c.provider}:${c.subject}`));
    const links = await this.d.pool.query("SELECT id, provider, external_subject_hash FROM identity_links WHERE identity_id=$1 AND state='active'", [identityId]);
    for (const l of links.rows) {
      if (!present.has(`${l.provider}:${l.external_subject_hash}`)) {
        await this.d.pool.query("UPDATE identity_links SET state='unlinked', unlinked_at=now() WHERE id=$1", [l.id]);
        this.d.audit.emit({ type: "account.unlinked", outcome: "success", actor: identityId, correlationId, context: { provider: l.provider, link_id: l.id } });
      }
    }
    return this.links(identityId);
  }

  async findByAttribute(name: string, value: string): Promise<string[]> {
    if (!LOOKUP_ATTRIBUTES.has(name)) return [];
    const res = await this.d.pool.query("SELECT DISTINCT identity_id FROM verified_attributes WHERE name=$1 AND lookup_hash=$2", [name, this.lookupHash(name, value)]);
    return res.rows.map((r) => r.identity_id as string);
  }

  async roles(identityId: string): Promise<string[]> {
    const res = await this.d.pool.query("SELECT role FROM admin_roles WHERE identity_id=$1 ORDER BY role", [identityId]);
    return res.rows.map((r) => r.role as string);
  }

  async setRoles(identityId: string, roles: string[], actor: string, correlationId?: string): Promise<string[]> {
    const wanted = [...new Set(roles)];
    for (const r of wanted) if (!(ROLES as readonly string[]).includes(r)) throw new Error(`unknown role ${r}`);
    const client = await this.d.pool.connect();
    try {
      await client.query("BEGIN");
      const before = (await client.query("SELECT role FROM admin_roles WHERE identity_id=$1 FOR UPDATE", [identityId])).rows.map((r) => r.role as string);
      if (before.includes("superadmin") && !wanted.includes("superadmin")) {
        const others = await client.query("SELECT count(*)::int AS n FROM admin_roles WHERE role='superadmin' AND identity_id<>$1", [identityId]);
        if (others.rows[0].n === 0) throw new ConflictError("cannot remove the last superadmin");
      }
      await client.query("DELETE FROM admin_roles WHERE identity_id=$1", [identityId]);
      for (const r of wanted) await client.query("INSERT INTO admin_roles(identity_id, role, granted_by) VALUES ($1,$2,$3)", [identityId, r, actor]);
      await client.query("COMMIT");
      this.d.audit.emit({ type: "admin.roles_changed", outcome: "success", actor, correlationId, context: { identity_id: identityId, before, after: wanted } });
      return wanted.sort();
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  async listRoleAssignments(role?: string) {
    const res = await this.d.pool.query(
      "SELECT identity_id, array_agg(role ORDER BY role) AS roles FROM admin_roles WHERE ($1::text IS NULL OR identity_id IN (SELECT identity_id FROM admin_roles WHERE role=$1)) GROUP BY identity_id",
      [role ?? null],
    );
    return res.rows;
  }
}
