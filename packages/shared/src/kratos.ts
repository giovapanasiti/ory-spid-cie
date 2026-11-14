import { HttpError, requestJson } from "./http.js";

/** Minimal typed client for the Ory Kratos REST API (v26). */
export interface KratosIdentity {
  id: string;
  schema_id: string;
  state?: string;
  traits: { email?: string; name?: { first?: string; last?: string } } & Record<string, unknown>;
  verifiable_addresses?: { value: string; verified: boolean; via: string }[];
  credentials?: Record<string, { type: string; identifiers?: string[]; created_at?: string; updated_at?: string; config?: unknown }>;
  metadata_public?: Record<string, unknown> | null;
  created_at?: string;
  updated_at?: string;
}

export interface KratosAuthMethod {
  method: string;
  aal?: string;
  completed_at?: string;
  provider?: string;
}

export interface KratosSession {
  id: string;
  active: boolean;
  expires_at?: string;
  authenticated_at?: string;
  issued_at?: string;
  authenticator_assurance_level?: string;
  authentication_methods?: KratosAuthMethod[];
  identity?: KratosIdentity;
  devices?: { id: string; ip_address?: string; user_agent?: string; location?: string }[];
}

export interface UiNodeAttributes {
  node_type: "input" | "img" | "a" | "text" | "script" | "div";
  name?: string;
  type?: string;
  value?: unknown;
  required?: boolean;
  disabled?: boolean;
  autocomplete?: string;
  onclickTrigger?: string;
  onloadTrigger?: string;
  href?: string;
  src?: string;
  id?: string;
  nonce?: string;
  async?: boolean;
  crossorigin?: string;
  integrity?: string;
  referrerpolicy?: string;
  text?: { id: number; text: string; type: string };
  width?: number;
  height?: number;
  title?: { text: string };
  pattern?: string;
  maxlength?: number;
}

export interface UiText {
  id: number;
  text: string;
  type: "info" | "error" | "success";
  context?: Record<string, unknown>;
}

export interface UiNode {
  type: string;
  group: string;
  attributes: UiNodeAttributes;
  messages: UiText[];
  meta: { label?: UiText };
}

export interface UiContainer {
  action: string;
  method: string;
  nodes: UiNode[];
  messages?: UiText[];
}

export interface SelfServiceFlow {
  id: string;
  type: string;
  ui: UiContainer;
  return_to?: string;
  request_url?: string;
  oauth2_login_challenge?: string;
  refresh?: boolean;
  requested_aal?: string;
  state?: string;
  expires_at?: string;
}

export type FlowKind = "login" | "registration" | "recovery" | "verification" | "settings";

export class KratosClient {
  constructor(
    readonly publicUrl: string,
    readonly adminUrl: string,
    readonly browserUrl: string,
  ) {}

  private pub(path: string): string {
    return this.publicUrl.replace(/\/$/, "") + path;
  }
  private adm(path: string): string {
    return this.adminUrl.replace(/\/$/, "") + path;
  }

  /** URL the browser must visit to start a self-service flow. */
  browserFlowUrl(kind: FlowKind, params: Record<string, string | undefined> = {}): string {
    const u = new URL(this.browserUrl.replace(/\/$/, "") + `/self-service/${kind}/browser`);
    for (const [k, v] of Object.entries(params)) if (v !== undefined) u.searchParams.set(k, v);
    return u.toString();
  }

  async whoami(cookie: string | undefined): Promise<KratosSession | null> {
    if (!cookie) return null;
    const res = await requestJson<KratosSession>(this.pub("/sessions/whoami"), { headers: { cookie }, allowError: true });
    return res.status === 200 ? res.data : null;
  }

  async getFlow(kind: FlowKind, id: string, cookie: string | undefined): Promise<SelfServiceFlow | { error: number }> {
    const res = await requestJson<SelfServiceFlow>(this.pub(`/self-service/${kind}/flows?id=${encodeURIComponent(id)}`), {
      headers: cookie ? { cookie } : {},
      allowError: true,
    });
    return res.status === 200 ? res.data : { error: res.status };
  }

  async getError(id: string): Promise<unknown> {
    const res = await requestJson<unknown>(this.pub(`/self-service/errors?id=${encodeURIComponent(id)}`), { allowError: true });
    return res.data;
  }

  async logoutUrl(cookie: string | undefined, returnTo?: string): Promise<string | null> {
    if (!cookie) return null;
    const q = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : "";
    const res = await requestJson<{ logout_url: string }>(this.pub(`/self-service/logout/browser${q}`), {
      headers: { cookie },
      allowError: true,
    });
    return res.status === 200 ? res.data.logout_url : null;
  }

  async mySessions(cookie: string): Promise<KratosSession[]> {
    const res = await requestJson<KratosSession[]>(this.pub("/sessions?page_size=100"), { headers: { cookie } });
    return res.data;
  }

  async revokeMySession(cookie: string, id: string): Promise<void> {
    await requestJson(this.pub(`/sessions/${encodeURIComponent(id)}`), { method: "DELETE", headers: { cookie } });
  }

  async revokeMyOtherSessions(cookie: string): Promise<void> {
    await requestJson(this.pub("/sessions"), { method: "DELETE", headers: { cookie } });
  }

  // ---------------------------------------------------------------- admin

  async listIdentities(opts: { credentialsIdentifier?: string; pageSize?: number; pageToken?: string } = {}): Promise<{
    identities: KratosIdentity[];
    next?: string;
  }> {
    const u = new URL(this.adm("/admin/identities"));
    u.searchParams.set("page_size", String(opts.pageSize ?? 50));
    if (opts.pageToken) u.searchParams.set("page_token", opts.pageToken);
    if (opts.credentialsIdentifier) u.searchParams.set("credentials_identifier", opts.credentialsIdentifier);
    const res = await requestJson<KratosIdentity[]>(u.toString());
    const link = res.headers.get("link") ?? "";
    const m = /<[^>]*[?&]page_token=([^&>]+)[^>]*>;\s*rel="next"/.exec(link);
    return { identities: res.data, next: m?.[1] ? decodeURIComponent(m[1]) : undefined };
  }

  async getIdentity(id: string, includeCredentials: string[] = []): Promise<KratosIdentity | null> {
    const u = new URL(this.adm(`/admin/identities/${encodeURIComponent(id)}`));
    for (const c of includeCredentials) u.searchParams.append("include_credential", c);
    const res = await requestJson<KratosIdentity>(u.toString(), { allowError: true });
    if (res.status === 404) return null;
    if (res.status !== 200) throw new HttpError(res.status, res.data, "get identity");
    return res.data;
  }

  async identitySessions(id: string): Promise<KratosSession[]> {
    const res = await requestJson<KratosSession[]>(this.adm(`/admin/identities/${encodeURIComponent(id)}/sessions?page_size=100`), {
      allowError: true,
    });
    return res.status === 200 ? res.data : [];
  }

  async getSession(id: string): Promise<KratosSession | null> {
    const res = await requestJson<KratosSession>(this.adm(`/admin/sessions/${encodeURIComponent(id)}?expand=Identity`), {
      allowError: true,
    });
    return res.status === 200 ? res.data : null;
  }

  async revokeSession(id: string): Promise<void> {
    await requestJson(this.adm(`/admin/sessions/${encodeURIComponent(id)}`), { method: "DELETE" });
  }

  async revokeIdentitySessions(id: string): Promise<void> {
    await requestJson(this.adm(`/admin/identities/${encodeURIComponent(id)}/sessions`), { method: "DELETE", allowError: true });
  }
}

/** Extracts the federated (oidc) credential identifiers of an identity ("<provider>:<subject>"). */
export function oidcIdentifiers(identity: KratosIdentity): { provider: string; subject: string }[] {
  const ids = identity.credentials?.oidc?.identifiers ?? [];
  return ids
    .map((s) => {
      const i = s.indexOf(":");
      return i > 0 ? { provider: s.slice(0, i), subject: s.slice(i + 1) } : null;
    })
    .filter((x): x is { provider: string; subject: string } => x !== null);
}
