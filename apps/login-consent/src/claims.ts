import type { KratosIdentity } from "@iam/shared";

export interface LoginContext {
  loa: string;
  amr: string[];
  provider: string | null;
  federated_acr: string | null;
  auth_time: string | null;
  identity_verified: boolean;
  kratos_session_id: string;
}

/** Builds the ID token / access token session claims for granted scopes (data minimisation). */
export function buildSessionClaims(
  scopes: string[],
  identity: KratosIdentity | null,
  verified: Record<string, unknown>,
  ctx: LoginContext,
): { id_token: Record<string, unknown>; access_token: Record<string, unknown> } {
  const id: Record<string, unknown> = { loa: ctx.loa, identity_verified: ctx.identity_verified };
  if (ctx.federated_acr) id.federated_acr = ctx.federated_acr;
  if (ctx.provider) id.idp = ctx.provider;
  const traits = identity?.traits ?? {};
  if (scopes.includes("profile")) {
    const given = (verified.given_name as string | undefined) ?? traits.name?.first;
    const family = (verified.family_name as string | undefined) ?? traits.name?.last;
    if (given) id.given_name = given;
    if (family) id.family_name = family;
    if (given || family) id.name = [given, family].filter(Boolean).join(" ");
    if (verified.birthdate) id.birthdate = verified.birthdate;
  }
  if (scopes.includes("email")) {
    const email = traits.email ?? (verified.email as string | undefined);
    if (email) {
      id.email = email;
      const addr = identity?.verifiable_addresses?.find((a) => a.value === email);
      id.email_verified = !!addr?.verified || verified.email === email;
    }
  }
  // Fiscal code only from verified federated attributes and only with the dedicated scope.
  if (scopes.includes("fiscal_number") && typeof verified.fiscal_number === "string") {
    id.fiscal_number = verified.fiscal_number;
  }
  const access: Record<string, unknown> = {
    token_kind: "user",
    loa: ctx.loa,
    amr: ctx.amr,
    auth_time: ctx.auth_time ? Math.floor(Date.parse(ctx.auth_time) / 1000) : undefined,
  };
  if (ctx.provider) access.idp = ctx.provider;
  return { id_token: id, access_token: access };
}
