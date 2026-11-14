import { requestJson } from "@iam/shared";

export interface BrokerResult {
  id: string;
  profile: string;
  op_entity_id: string;
  op_issuer: string;
  external_sub: string;
  subject_hash: string;
  acr: string;
  loa: string;
  auth_time: string;
  token_issued_at?: string;
  bound_identity_id?: string | null;
  bound_session_id?: string | null;
}

/** Client for the federation broker internal API. */
export class BrokerClient {
  constructor(
    private readonly base: string,
    private readonly token: string,
  ) {}
  private h() {
    return { authorization: `Bearer ${this.token}` };
  }
  async find(subjects: string[], since: Date, until: Date): Promise<BrokerResult[]> {
    const u = new URL(this.base.replace(/\/$/, "") + "/internal/auth-results");
    subjects.forEach((s) => u.searchParams.append("subject", s));
    u.searchParams.set("since", since.toISOString());
    u.searchParams.set("until", until.toISOString());
    return (await requestJson<BrokerResult[]>(u.toString(), { headers: this.h() })).data;
  }
  async get(id: string): Promise<{ result: BrokerResult; attributes: Record<string, unknown> }> {
    return (await requestJson<{ result: BrokerResult; attributes: Record<string, unknown> }>(
      `${this.base.replace(/\/$/, "")}/internal/auth-results/${encodeURIComponent(id)}`, { headers: this.h() })).data;
  }
  async bind(id: string, identityId: string, sessionId: string): Promise<boolean> {
    const r = await requestJson(`${this.base.replace(/\/$/, "")}/internal/auth-results/${encodeURIComponent(id)}/bind`, {
      json: { identity_id: identityId, session_id: sessionId }, headers: this.h(), allowError: true });
    return r.status === 200;
  }
}
