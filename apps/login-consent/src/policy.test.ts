import { test } from "node:test";
import assert from "node:assert/strict";
import type { KratosSession } from "@iam/shared";
import { decideLogin, parseRequestUrl } from "./policy.js";
import { buildSessionClaims } from "./claims.js";

const now = Date.parse("2026-11-14T10:00:00Z");
const session = (authAgoSec: number): KratosSession => ({
  id: "s1",
  active: true,
  authenticated_at: new Date(now - authAgoSec * 1000).toISOString(),
  identity: { id: "i1", schema_id: "default", traits: {} },
});
const P = (q: string, acr?: string[], min?: string) => parseRequestUrl(`http://localhost:4444/oauth2/auth?${q}`, acr, min);

test("parses prompt, max_age and the strictest acr (client minimum applies)", () => {
  const p = P("prompt=login%20consent&max_age=60", ["urn:iam:loa:low"], "urn:iam:loa:substantial");
  assert.deepEqual(p, { prompt: ["login", "consent"], maxAge: 60, requiredLoA: "urn:iam:loa:substantial" });
  assert.equal(P("max_age=abc").maxAge, undefined);
});

test("no session -> authenticate; prompt=none -> login_required", () => {
  assert.equal(decideLogin({ params: P(""), session: null, now }).action, "authenticate");
  assert.deepEqual(decideLogin({ params: P("prompt=none"), session: null, now }), { action: "reject", error: "login_required", description: "no active session" });
});

test("valid session is reused (SSO)", () => {
  assert.equal(decideLogin({ params: P(""), session: session(10), sessionLoA: "urn:iam:loa:none", now }).action, "accept");
});

test("prompt=login and max_age force re-authentication once, then accept", () => {
  const d = decideLogin({ params: P("prompt=login"), session: session(10), now });
  assert.equal(d.action, "authenticate");
  const fresh = decideLogin({ params: P("prompt=login"), session: session(1), now, reauthStartedAt: now - 5000 });
  assert.equal(fresh.action, "accept");
  assert.equal(decideLogin({ params: P("max_age=30"), session: session(60), now }).action, "authenticate");
  assert.equal(decideLogin({ params: P("max_age=30"), session: session(10), now }).action, "accept");
});

test("password session is not upgraded: step-up then reject if still insufficient", () => {
  const params = P("", ["urn:iam:loa:high"]);
  const d = decideLogin({ params, session: session(10), sessionLoA: "urn:iam:loa:none", now });
  assert.deepEqual(d, { action: "authenticate", refresh: true, stepUp: true, reason: "step_up" });
  const after = decideLogin({ params, session: session(1), sessionLoA: "urn:iam:loa:substantial", now, reauthStartedAt: now - 5000 });
  assert.deepEqual(after, { action: "reject", error: "access_denied", description: "insufficient_assurance" });
  assert.equal(decideLogin({ params, session: session(1), sessionLoA: "urn:iam:loa:high", now }).action, "accept");
});

test("hydra remembered subject mismatch is rejected", () => {
  const d = decideLogin({ params: P(""), session: session(5), now, hydraSkip: true, hydraSubject: "other" });
  assert.equal(d.action, "reject");
});

test("claims are minimised per scope; fiscal number only from verified attributes", () => {
  const ctx = { loa: "urn:iam:loa:high", amr: ["spid"], provider: "spid", federated_acr: "https://www.spid.gov.it/SpidL3", auth_time: "2026-11-14T09:59:00Z", identity_verified: true, kratos_session_id: "s" };
  const identity = { id: "i", schema_id: "d", traits: { email: "a@example.org", name: { first: "Self", last: "Asserted" } } };
  const openidOnly = buildSessionClaims(["openid"], identity, { fiscal_number: "TSTDAA85T50H501R" }, ctx);
  assert.equal(openidOnly.id_token.fiscal_number, undefined);
  assert.equal(openidOnly.id_token.email, undefined);
  const full = buildSessionClaims(["openid", "profile", "email", "fiscal_number"], identity, { given_name: "Ada", family_name: "Test", fiscal_number: "TSTDAA85T50H501R" }, ctx);
  assert.equal(full.id_token.given_name, "Ada", "verified attributes win over self-asserted traits");
  assert.equal(full.id_token.fiscal_number, "TSTDAA85T50H501R");
  assert.equal(full.access_token.token_kind, "user");
  assert.equal(full.access_token.auth_time, Math.floor(Date.parse("2026-11-14T09:59:00Z") / 1000));
  const noVerified = buildSessionClaims(["openid", "fiscal_number"], identity, {}, ctx);
  assert.equal(noVerified.id_token.fiscal_number, undefined);
});
