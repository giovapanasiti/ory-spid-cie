import { test } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, generateKeyPair, exportJWK, createLocalJWKSet, type JWK } from "jose";
import { createTokenValidator, authorize, AuthError, type Principal } from "./index.js";

const ISS = "http://localhost:4444/";
const AUD = "demo-api";

async function setup() {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" } as JWK;
  const v = createTokenValidator({ issuer: ISS, jwksUrl: "http://unused", audience: AUD, keySet: createLocalJWKSet({ keys: [jwk] }) });
  const sign = (claims: Record<string, unknown>, opts: { alg?: string; key?: CryptoKey; exp?: string } = {}) =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: opts.alg ?? "RS256", kid: "k1" })
      .setIssuer((claims.iss as string) ?? ISS)
      .setAudience((claims.aud as string[]) ?? [AUD])
      .setIssuedAt()
      .setExpirationTime(opts.exp ?? "5m")
      .setSubject((claims.sub as string) ?? "user-1")
      .sign(opts.key ?? privateKey);
  return { v, sign };
}

test("accepts a valid user token and maps assurance", async () => {
  const { v, sign } = await setup();
  const tok = await sign({ client_id: "demo-web", scp: ["profile.read"], ext: { token_kind: "user", loa: "urn:iam:loa:high", auth_time: 1, amr: ["spid"] } });
  const p = await v.validate(tok);
  assert.equal(p.kind, "user");
  assert.equal(p.loa, "urn:iam:loa:high");
  assert.deepEqual(p.scopes, ["profile.read"]);
});

test("rejects wrong issuer, audience, expired and foreign-key tokens", async () => {
  const { v, sign } = await setup();
  await assert.rejects(v.validate(await sign({ client_id: "c", iss: "http://evil/" })), AuthError);
  await assert.rejects(v.validate(await sign({ client_id: "c", aud: ["other-api"] })), AuthError);
  await assert.rejects(v.validate(await sign({ client_id: "c" }, { exp: "-10m" })), /expired/);
  const other = await generateKeyPair("RS256");
  await assert.rejects(v.validate(await sign({ client_id: "c" }, { key: other.privateKey })), AuthError);
});

test("rejects HS256 (algorithm confusion) and alg none", async () => {
  const { v } = await setup();
  const secret = new TextEncoder().encode("x".repeat(64));
  const hs = await new SignJWT({ client_id: "c", sub: "u" }).setProtectedHeader({ alg: "HS256", kid: "k1" }).setIssuer(ISS).setAudience(AUD).setIssuedAt().setExpirationTime("5m").sign(secret);
  await assert.rejects(v.validate(hs), AuthError);
  const none = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url") + "." + Buffer.from(JSON.stringify({ iss: ISS, aud: AUD, sub: "u", client_id: "c", exp: 9e9, iat: 1 })).toString("base64url") + ".";
  await assert.rejects(v.validate(none), AuthError);
});

test("machine tokens are distinguished from user tokens", async () => {
  const { v, sign } = await setup();
  const p = await v.validate(await sign({ client_id: "svc", sub: "svc", scp: ["reports.read"] }));
  assert.equal(p.kind, "machine");
  assert.throws(() => authorize(p, { kind: "user" }), AuthError);
});

test("authorize enforces scopes, LoA and authentication age (step-up)", () => {
  const p: Principal = { subject: "u", clientId: "c", scopes: ["a"], kind: "user", loa: "urn:iam:loa:substantial", authTime: 1000, claims: {} };
  assert.throws(() => authorize(p, { scopes: ["b"] }), (e: AuthError) => e.status === 403 && e.code === "insufficient_scope");
  assert.throws(() => authorize(p, { minLoA: "urn:iam:loa:high" }), (e: AuthError) => e.code === "insufficient_user_authentication" && e.extra.acr_values === "urn:iam:loa:high");
  assert.throws(() => authorize(p, { maxAuthAgeSeconds: 60 }, 2000 * 1000), (e: AuthError) => e.extra.max_age === "60");
  authorize(p, { scopes: ["a"], minLoA: "urn:iam:loa:low", maxAuthAgeSeconds: 60 }, 1030 * 1000);
});
