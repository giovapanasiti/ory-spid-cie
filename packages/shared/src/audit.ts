import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { Logger } from "pino";

/** Canonical audit event (shared with federation-broker and audit-service). */
export const AuditEventSchema = z.object({
  id: z.string().uuid(),
  timestamp: z.string().datetime({ offset: true }),
  correlation_id: z.string().max(128).optional(),
  actor: z.string().max(256).optional(),
  type: z.string().regex(/^[a-z0-9_.]{3,100}$/),
  outcome: z.enum(["success", "failure"]),
  service: z.string().max(64),
  context: z.record(z.string(), z.unknown()).optional(),
});
export type AuditEvent = z.infer<typeof AuditEventSchema>;

/** Keys never allowed inside audit context (defence in depth). */
const FORBIDDEN = /token|secret|password|assertion|code_verifier|^code$|cookie|fiscal|email|birthdate|given_name|family_name/i;

export function scrubContext(ctx: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!ctx) return undefined;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(ctx)) {
    if (FORBIDDEN.test(k)) continue;
    out[k] = typeof v === "string" && v.length > 512 ? v.slice(0, 512) : v;
  }
  return out;
}

export class AuditClient {
  constructor(
    private readonly url: string | undefined,
    private readonly token: string | undefined,
    private readonly service: string,
    private readonly log: Logger,
  ) {}

  emit(e: { type: string; outcome: "success" | "failure"; actor?: string; correlationId?: string; context?: Record<string, unknown> }): void {
    const ev: AuditEvent = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      correlation_id: e.correlationId,
      actor: e.actor,
      type: e.type,
      outcome: e.outcome,
      service: this.service,
      context: scrubContext(e.context),
    };
    this.log.info({ audit_event: ev }, "audit");
    if (!this.url) return;
    void this.ship(ev, 0);
  }

  private async ship(ev: AuditEvent, attempt: number): Promise<void> {
    try {
      const res = await fetch(this.url!, {
        method: "POST",
        headers: { "content-type": "application/json", ...(this.token ? { authorization: `Bearer ${this.token}` } : {}) },
        body: JSON.stringify(ev),
        signal: AbortSignal.timeout(5000),
      });
      if (res.status >= 300) throw new Error(`status ${res.status}`);
    } catch (err) {
      if (attempt < 2) {
        setTimeout(() => void this.ship(ev, attempt + 1), 500 * (attempt + 1));
      } else {
        this.log.error({ event_id: ev.id, err: String(err) }, "audit event delivery failed");
      }
    }
  }
}
