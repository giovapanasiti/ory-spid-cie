import { createHash, randomBytes } from "node:crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { requestJson } from "@iam/shared";

/** Minimal OIDC authorization-code + PKCE client for the admin console (Hydra as OP). */
export interface OidcConfig {
  issuer: string; // public issuer (browser), e.g. http://localhost:4444/
  internalUrl: string; // server-to-server base, e.g. http://hydra:4444
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope: string;
  acrValues?: string;
}

export interface PendingAuth {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
}

export class OidcClient {
  private readonly jwks;
  constructor(private readonly c: OidcConfig) {
    this.jwks = createRemoteJWKSet(new URL(c.internalUrl.replace(/\/$/, "") + "/.well-known/jwks.json"));
  }

  start(returnTo: string, extra: Record<string, string> = {}): { url: string; pending: PendingAuth } {
    const pending: PendingAuth = {
      state: randomBytes(24).toString("base64url"),
      nonce: randomBytes(24).toString("base64url"),
      verifier: randomBytes(48).toString("base64url"),
      returnTo,
    };
    const u = new URL(this.c.issuer.replace(/\/$/, "") + "/oauth2/auth");
    u.searchParams.set("response_type", "code");
    u.searchParams.set("client_id", this.c.clientId);
    u.searchParams.set("redirect_uri", this.c.redirectUri);
    u.searchParams.set("scope", this.c.scope);
    u.searchParams.set("state", pending.state);
    u.searchParams.set("nonce", pending.nonce);
    u.searchParams.set("code_challenge", createHash("sha256").update(pending.verifier).digest("base64url"));
    u.searchParams.set("code_challenge_method", "S256");
    if (this.c.acrValues) u.searchParams.set("acr_values", this.c.acrValues);
    for (const [k, v] of Object.entries(extra)) u.searchParams.set(k, v);
    return { url: u.toString(), pending };
  }

  async finish(query: Record<string, string>, pending: PendingAuth | null) {
    if (!pending || !query.state || query.state !== pending.state) throw new Error("state mismatch");
    if (query.error) throw new Error(`authorization error: ${query.error}`);
    if (!query.code) throw new Error("missing code");
    const basic = Buffer.from(`${encodeURIComponent(this.c.clientId)}:${encodeURIComponent(this.c.clientSecret)}`).toString("base64");
    const tok = await requestJson<{ id_token: string; access_token: string }>(this.c.internalUrl.replace(/\/$/, "") + "/oauth2/token", {
      form: { grant_type: "authorization_code", code: query.code, redirect_uri: this.c.redirectUri, code_verifier: pending.verifier },
      headers: { authorization: `Basic ${basic}` },
    });
    const { payload } = await jwtVerify(tok.data.id_token, this.jwks, {
      issuer: this.c.issuer,
      audience: this.c.clientId,
      algorithms: ["RS256", "ES256", "PS256"],
      clockTolerance: 30,
    });
    if (payload.nonce !== pending.nonce) throw new Error("nonce mismatch");
    return { claims: payload, idToken: tok.data.id_token };
  }

  endSessionUrl(idTokenHint: string, postLogout: string): string {
    const u = new URL(this.c.issuer.replace(/\/$/, "") + "/oauth2/sessions/logout");
    u.searchParams.set("id_token_hint", idTokenHint);
    u.searchParams.set("post_logout_redirect_uri", postLogout);
    return u.toString();
  }
}
