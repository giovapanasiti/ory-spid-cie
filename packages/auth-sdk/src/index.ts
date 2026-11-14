import { createRemoteJWKSet, jwtVerify, errors as joseErrors, type JWTPayload, type JWTVerifyGetKey } from "jose";
import type { FastifyReply, FastifyRequest, preHandlerAsyncHookHandler } from "fastify";
import { HydraAdmin, loaRank } from "@iam/shared";

/**
 * Reusable resource-server SDK: validates Hydra-issued access tokens (JWT with
 * JWKS, or opaque via introspection), enforces audience/scopes/token kind and
 * authentication assurance (LoA + authentication age) with RFC 9470 step-up errors.
 */
export interface ValidatorOptions {
  issuer: string;
  /** JWKS URL (server-to-server, may differ from the public issuer host). */
  jwksUrl: string;
  /** Expected audience for this API (required). */
  audience: string;
  /** Hydra admin URL; enables introspection for opaque tokens and revocation checks. */
  hydraAdminUrl?: string;
  /** Always introspect (detects revoked JWTs at the cost of a call). */
  alwaysIntrospect?: boolean;
  clockToleranceSeconds?: number;
  /** Override for tests. */
  keySet?: JWTVerifyGetKey;
}

export type TokenKind = "user" | "machine";

export interface Principal {
  subject: string;
  clientId: string;
  scopes: string[];
  kind: TokenKind;
  loa?: string;
  acr?: string;
  amr?: string[];
  authTime?: number;
  claims: Record<string, unknown>;
}

export class AuthError extends Error {
  constructor(
    readonly status: 401 | 403,
    readonly code: string,
    readonly description: string,
    readonly extra: Record<string, string> = {},
  ) {
    super(description);
  }
  wwwAuthenticate(): string {
    const params = { error: this.code, error_description: this.description, ...this.extra };
    return (
      "Bearer " +
      Object.entries(params)
        .map(([k, v]) => `${k}="${v.replace(/["\\]/g, "")}"`)
        .join(", ")
    );
  }
}

const ALLOWED_ALGS = ["RS256", "RS512", "ES256", "ES512", "PS256", "PS512"];

function principalFrom(p: Record<string, unknown>): Principal {
  const ext = (p.ext ?? {}) as Record<string, unknown>;
  const scp = Array.isArray(p.scp) ? (p.scp as string[]) : typeof p.scope === "string" ? p.scope.split(" ").filter(Boolean) : [];
  const clientId = String(p.client_id ?? "");
  const subject = String(p.sub ?? "");
  const kind: TokenKind = ext.token_kind === "user" && subject !== clientId ? "user" : "machine";
  return {
    subject,
    clientId,
    scopes: scp,
    kind,
    loa: typeof ext.loa === "string" ? ext.loa : undefined,
    acr: typeof ext.acr === "string" ? ext.acr : undefined,
    amr: Array.isArray(ext.amr) ? (ext.amr as string[]) : undefined,
    authTime: typeof ext.auth_time === "number" ? ext.auth_time : undefined,
    claims: p,
  };
}

export function createTokenValidator(opts: ValidatorOptions) {
  if (!opts.audience) throw new Error("audience is required");
  const keys = opts.keySet ?? createRemoteJWKSet(new URL(opts.jwksUrl), { timeoutDuration: 5000, cooldownDuration: 30_000 });
  const hydra = opts.hydraAdminUrl ? new HydraAdmin(opts.hydraAdminUrl) : undefined;

  async function introspect(token: string): Promise<Principal> {
    if (!hydra) throw new AuthError(401, "invalid_token", "token is not a valid JWT");
    const r = await hydra.introspect(token);
    if (!r.active) throw new AuthError(401, "invalid_token", "token inactive or revoked");
    if (r.token_use && r.token_use !== "access_token") throw new AuthError(401, "invalid_token", "not an access token");
    if (r.iss && r.iss !== opts.issuer) throw new AuthError(401, "invalid_token", "issuer mismatch");
    if (!(r.aud ?? []).includes(opts.audience)) throw new AuthError(401, "invalid_token", "audience mismatch");
    return principalFrom({ ...r, scope: r.scope, ext: r.ext });
  }

  return {
    async validate(token: string): Promise<Principal> {
      if (!token || token.length > 8192) throw new AuthError(401, "invalid_token", "missing token");
      const looksJwt = token.split(".").length === 3;
      if (!looksJwt) return introspect(token);
      let payload: JWTPayload;
      try {
        const res = await jwtVerify(token, keys, {
          issuer: opts.issuer,
          audience: opts.audience,
          algorithms: ALLOWED_ALGS,
          clockTolerance: opts.clockToleranceSeconds ?? 30,
          requiredClaims: ["exp", "iat", "sub", "client_id"],
        });
        payload = res.payload;
      } catch (err) {
        if (err instanceof joseErrors.JWTExpired) throw new AuthError(401, "invalid_token", "token expired");
        if (err instanceof joseErrors.JWTClaimValidationFailed) throw new AuthError(401, "invalid_token", `claim ${err.claim} invalid`);
        throw new AuthError(401, "invalid_token", "token validation failed");
      }
      if (opts.alwaysIntrospect && hydra) {
        const r = await hydra.introspect(token);
        if (!r.active) throw new AuthError(401, "invalid_token", "token revoked");
      }
      return principalFrom(payload as Record<string, unknown>);
    },
  };
}

export type TokenValidator = ReturnType<typeof createTokenValidator>;

export interface Requirements {
  scopes?: string[];
  kind?: TokenKind;
  /** Minimum internal LoA (user tokens). */
  minLoA?: string;
  /** Maximum age of the user authentication in seconds. */
  maxAuthAgeSeconds?: number;
  /** Restrict to federated methods (e.g. ["spid","cie"]). */
  amrAnyOf?: string[];
}

/** Pure authorisation decision (exported for unit tests). */
export function authorize(p: Principal, req: Requirements, now = Date.now()): void {
  if (req.kind && p.kind !== req.kind) throw new AuthError(403, "insufficient_scope", `a ${req.kind} token is required`);
  for (const s of req.scopes ?? []) {
    if (!p.scopes.includes(s)) throw new AuthError(403, "insufficient_scope", `scope ${s} required`, { scope: (req.scopes ?? []).join(" ") });
  }
  if (req.minLoA && loaRank(p.loa) < loaRank(req.minLoA)) {
    throw new AuthError(401, "insufficient_user_authentication", "a stronger authentication is required", { acr_values: req.minLoA });
  }
  if (req.maxAuthAgeSeconds !== undefined) {
    if (!p.authTime || now / 1000 - p.authTime > req.maxAuthAgeSeconds) {
      throw new AuthError(401, "insufficient_user_authentication", "a more recent authentication is required", {
        max_age: String(req.maxAuthAgeSeconds),
      });
    }
  }
  if (req.amrAnyOf && !(p.amr ?? []).some((m) => req.amrAnyOf!.includes(m))) {
    throw new AuthError(401, "insufficient_user_authentication", "authentication method not accepted");
  }
}

declare module "fastify" {
  interface FastifyRequest {
    principal?: Principal;
  }
}

function sendAuthError(reply: FastifyReply, err: AuthError) {
  return reply
    .code(err.status)
    .header("www-authenticate", err.wwwAuthenticate())
    .header("cache-control", "no-store")
    .send({ error: err.code, error_description: err.description, ...err.extra });
}

/** Fastify preHandler enforcing the requirements. */
export function requireAuth(validator: TokenValidator, req: Requirements = {}): preHandlerAsyncHookHandler {
  return async function (request: FastifyRequest, reply: FastifyReply) {
    const h = request.headers.authorization ?? "";
    const m = /^Bearer ([A-Za-z0-9._~+/=-]+)$/i.exec(h);
    if (!m?.[1]) {
      return sendAuthError(reply, new AuthError(401, "invalid_request", "bearer token required"));
    }
    try {
      const p = await validator.validate(m[1]);
      authorize(p, req);
      request.principal = p;
    } catch (err) {
      if (err instanceof AuthError) return sendAuthError(reply, err);
      request.log.error({ err: String(err) }, "token validation error");
      return reply.code(503).send({ error: "temporarily_unavailable" });
    }
  };
}
