import { requestJson } from "./http.js";
import type { KratosAuthMethod } from "./kratos.js";

export interface Assurance {
  loa: string;
  acr: string;
  amr: string[];
  provider: string | null;
  federated_acr: string | null;
  auth_time: string | null;
  identity_verified: boolean;
  verified_attributes: Record<string, unknown>;
}

export interface VerifiedAttribute {
  value: unknown;
  provider: string;
  issuer?: string;
  verified_at: string;
  loa: string;
}

export interface IdentityLink {
  id: string;
  identity_id: string;
  provider: string;
  issuer: string;
  external_subject_hash: string;
  state: string;
  last_loa: string | null;
  last_acr: string | null;
  last_auth_at: string | null;
  linked_at: string;
}

/** Client for identity-service internal API. */
export class IdentityServiceClient {
  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
  ) {}
  private h(correlationId?: string) {
    return { authorization: `Bearer ${this.token}`, ...(correlationId ? { "x-correlation-id": correlationId } : {}) };
  }
  private u(p: string) {
    return this.baseUrl.replace(/\/$/, "") + p;
  }

  async resolveAssurance(input: {
    identity_id: string;
    session_id: string;
    authenticated_at?: string;
    authentication_methods: KratosAuthMethod[];
  }, correlationId?: string): Promise<Assurance> {
    return (await requestJson<Assurance>(this.u("/internal/assurance/resolve"), { json: input, headers: this.h(correlationId) })).data;
  }
  async links(identityId: string): Promise<IdentityLink[]> {
    return (await requestJson<IdentityLink[]>(this.u(`/internal/identities/${encodeURIComponent(identityId)}/links`), { headers: this.h() })).data;
  }
  async verifiedAttributes(identityId: string): Promise<Record<string, VerifiedAttribute>> {
    return (await requestJson<Record<string, VerifiedAttribute>>(
      this.u(`/internal/identities/${encodeURIComponent(identityId)}/attributes`), { headers: this.h() })).data;
  }
  async roles(identityId: string): Promise<string[]> {
    return (await requestJson<{ roles: string[] }>(this.u(`/internal/roles/${encodeURIComponent(identityId)}`), { headers: this.h() })).data.roles;
  }
  async setRoles(identityId: string, roles: string[], actor: string): Promise<string[]> {
    return (await requestJson<{ roles: string[] }>(this.u(`/internal/roles/${encodeURIComponent(identityId)}`), {
      method: "PUT", json: { roles, actor }, headers: this.h() })).data.roles;
  }
  async listRoles(role?: string): Promise<{ identity_id: string; roles: string[] }[]> {
    const q = role ? `?role=${encodeURIComponent(role)}` : "";
    return (await requestJson<{ identity_id: string; roles: string[] }[]>(this.u(`/internal/roles${q}`), { headers: this.h() })).data;
  }
  async search(name: "fiscal_number" | "email", value: string): Promise<string[]> {
    const q = `?name=${encodeURIComponent(name)}&value=${encodeURIComponent(value)}`;
    return (await requestJson<{ identity_ids: string[] }>(this.u(`/internal/identities/search${q}`), { headers: this.h() })).data.identity_ids;
  }
  async syncLinks(identityId: string): Promise<IdentityLink[]> {
    return (await requestJson<IdentityLink[]>(this.u(`/internal/identities/${encodeURIComponent(identityId)}/links/sync`), {
      method: "POST", headers: this.h() })).data;
  }
}
