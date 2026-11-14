import { loaRank, requestedLoA, type KratosSession } from "@iam/shared";

/** Parsed OIDC parameters relevant to authentication decisions. */
export interface AuthRequestParams {
  prompt: string[];
  maxAge?: number;
  requiredLoA?: string;
}

export function parseRequestUrl(requestUrl: string, acrValues: string[] | undefined, clientMinLoA?: unknown): AuthRequestParams {
  let prompt: string[] = [];
  let maxAge: number | undefined;
  try {
    const u = new URL(requestUrl);
    prompt = (u.searchParams.get("prompt") ?? "").split(" ").filter(Boolean);
    const ma = u.searchParams.get("max_age");
    if (ma !== null && /^\d{1,9}$/.test(ma)) maxAge = Number(ma);
  } catch {
    /* malformed request_url: no prompt/max_age */
  }
  let required = requestedLoA(acrValues);
  if (typeof clientMinLoA === "string" && loaRank(clientMinLoA) > loaRank(required)) required = clientMinLoA as typeof required;
  return { prompt, maxAge, requiredLoA: required };
}

export type LoginDecision =
  | { action: "accept" }
  | { action: "authenticate"; refresh: boolean; stepUp: boolean; reason: string }
  | { action: "reject"; error: string; description: string };

export interface DecisionInput {
  params: AuthRequestParams;
  session: KratosSession | null;
  /** LoA computed for the current session (undefined when no session). */
  sessionLoA?: string;
  /** Set when this challenge already sent the user to Kratos at this time (ms). */
  reauthStartedAt?: number;
  /** Hydra remembered subject (when skip is true). */
  hydraSubject?: string;
  hydraSkip?: boolean;
  now: number;
}

/**
 * Decides how to handle a Hydra login challenge. A normal Kratos session is
 * never upgraded: insufficient assurance triggers a step-up re-authentication
 * restricted to federated providers, and a fresh but still insufficient
 * authentication is rejected (no silent downgrade, no loop).
 */
export function decideLogin(i: DecisionInput): LoginDecision {
  const { params, session } = i;
  const promptNone = params.prompt.includes("none");
  const authAt = session?.authenticated_at ? Date.parse(session.authenticated_at) : 0;
  const fresh = i.reauthStartedAt !== undefined && authAt >= i.reauthStartedAt - 1000;
  const insufficient = !!params.requiredLoA && loaRank(i.sessionLoA) < loaRank(params.requiredLoA);

  if (!session?.active || !session.identity) {
    return promptNone
      ? { action: "reject", error: "login_required", description: "no active session" }
      : { action: "authenticate", refresh: false, stepUp: insufficientFor(params), reason: "no_session" };
  }
  if (i.hydraSkip && i.hydraSubject && i.hydraSubject !== session.identity.id) {
    return { action: "reject", error: "login_required", description: "session subject mismatch" };
  }
  const tooOld = params.maxAge !== undefined && (i.now - authAt) / 1000 > params.maxAge;
  if (!fresh && (params.prompt.includes("login") || tooOld)) {
    return promptNone
      ? { action: "reject", error: "login_required", description: "re-authentication required" }
      : { action: "authenticate", refresh: true, stepUp: insufficient, reason: tooOld ? "max_age" : "prompt_login" };
  }
  if (insufficient) {
    if (fresh || promptNone) {
      return { action: "reject", error: "access_denied", description: "insufficient_assurance" };
    }
    return { action: "authenticate", refresh: true, stepUp: true, reason: "step_up" };
  }
  return { action: "accept" };
}

function insufficientFor(p: AuthRequestParams): boolean {
  return !!p.requiredLoA && loaRank(p.requiredLoA) > 0;
}
