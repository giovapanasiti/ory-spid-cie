import { requestJson } from "./http.js";

/** Minimal typed client for the Ory Hydra admin API (v26). Never expose the admin URL publicly. */
export interface OAuth2Client {
  client_id?: string;
  client_name?: string;
  client_secret?: string;
  redirect_uris?: string[];
  post_logout_redirect_uris?: string[];
  grant_types?: string[];
  response_types?: string[];
  scope?: string;
  audience?: string[];
  token_endpoint_auth_method?: string;
  skip_consent?: boolean;
  metadata?: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
  owner?: string;
}

export interface LoginRequest {
  challenge: string;
  skip: boolean;
  subject: string;
  client: OAuth2Client;
  request_url: string;
  requested_scope: string[];
  requested_access_token_audience: string[];
  session_id?: string;
  oidc_context?: { acr_values?: string[]; ui_locales?: string[]; login_hint?: string; id_token_hint_claims?: Record<string, unknown> };
}

export interface ConsentRequest {
  challenge: string;
  skip?: boolean;
  subject?: string;
  client?: OAuth2Client;
  requested_scope?: string[];
  requested_access_token_audience?: string[];
  acr?: string;
  amr?: string[];
  context?: Record<string, unknown>;
  login_session_id?: string;
  oidc_context?: LoginRequest["oidc_context"];
}

export interface LogoutRequest {
  challenge: string;
  subject?: string;
  sid?: string;
  request_url?: string;
  rp_initiated?: boolean;
  client?: OAuth2Client;
}

export interface Redirect {
  redirect_to: string;
}

export interface Introspection {
  active: boolean;
  sub?: string;
  client_id?: string;
  scope?: string;
  aud?: string[];
  exp?: number;
  iat?: number;
  iss?: string;
  token_type?: string;
  token_use?: string;
  ext?: Record<string, unknown>;
}

export class HydraAdmin {
  constructor(readonly adminUrl: string) {}
  private u(path: string): string {
    return this.adminUrl.replace(/\/$/, "") + path;
  }
  private q(kind: string, challenge: string, action = ""): string {
    return this.u(`/admin/oauth2/auth/requests/${kind}${action}?${kind}_challenge=${encodeURIComponent(challenge)}`);
  }

  async getLoginRequest(challenge: string): Promise<LoginRequest> {
    return (await requestJson<LoginRequest>(this.q("login", challenge))).data;
  }
  async acceptLogin(
    challenge: string,
    body: { subject: string; remember?: boolean; remember_for?: number; acr?: string; amr?: string[]; context?: Record<string, unknown>; identity_provider_session_id?: string },
  ): Promise<Redirect> {
    return (await requestJson<Redirect>(this.q("login", challenge, "/accept"), { method: "PUT", json: body })).data;
  }
  async rejectLogin(challenge: string, error: string, description: string): Promise<Redirect> {
    return (
      await requestJson<Redirect>(this.q("login", challenge, "/reject"), {
        method: "PUT",
        json: { error, error_description: description },
      })
    ).data;
  }
  async getConsentRequest(challenge: string): Promise<ConsentRequest> {
    return (await requestJson<ConsentRequest>(this.q("consent", challenge))).data;
  }
  async acceptConsent(
    challenge: string,
    body: {
      grant_scope: string[];
      grant_access_token_audience: string[];
      remember?: boolean;
      remember_for?: number;
      session?: { id_token?: Record<string, unknown>; access_token?: Record<string, unknown> };
    },
  ): Promise<Redirect> {
    return (await requestJson<Redirect>(this.q("consent", challenge, "/accept"), { method: "PUT", json: body })).data;
  }
  async rejectConsent(challenge: string, error: string, description: string): Promise<Redirect> {
    return (
      await requestJson<Redirect>(this.q("consent", challenge, "/reject"), {
        method: "PUT",
        json: { error, error_description: description },
      })
    ).data;
  }
  async getLogoutRequest(challenge: string): Promise<LogoutRequest> {
    return (await requestJson<LogoutRequest>(this.q("logout", challenge))).data;
  }
  async acceptLogout(challenge: string): Promise<Redirect> {
    return (await requestJson<Redirect>(this.q("logout", challenge, "/accept"), { method: "PUT" })).data;
  }
  async rejectLogout(challenge: string): Promise<void> {
    await requestJson(this.q("logout", challenge, "/reject"), { method: "PUT" });
  }
  async revokeConsentSessions(subject: string): Promise<void> {
    await requestJson(this.u(`/admin/oauth2/auth/sessions/consent?subject=${encodeURIComponent(subject)}&all=true`), {
      method: "DELETE",
      allowError: true,
    });
  }
  async revokeLoginSessions(subject: string): Promise<void> {
    await requestJson(this.u(`/admin/oauth2/auth/sessions/login?subject=${encodeURIComponent(subject)}`), {
      method: "DELETE",
      allowError: true,
    });
  }
  async listClients(): Promise<OAuth2Client[]> {
    return (await requestJson<OAuth2Client[]>(this.u("/admin/clients?page_size=500"))).data;
  }
  async getClient(id: string): Promise<OAuth2Client | null> {
    const res = await requestJson<OAuth2Client>(this.u(`/admin/clients/${encodeURIComponent(id)}`), { allowError: true });
    return res.status === 200 ? res.data : null;
  }
  async createClient(c: OAuth2Client): Promise<OAuth2Client> {
    return (await requestJson<OAuth2Client>(this.u("/admin/clients"), { method: "POST", json: c })).data;
  }
  async deleteClient(id: string): Promise<void> {
    await requestJson(this.u(`/admin/clients/${encodeURIComponent(id)}`), { method: "DELETE" });
  }
  async introspect(token: string, scope?: string): Promise<Introspection> {
    const form: Record<string, string> = { token };
    if (scope) form.scope = scope;
    return (await requestJson<Introspection>(this.u("/admin/oauth2/introspect"), { form })).data;
  }
}
