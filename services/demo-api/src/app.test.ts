import { test } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, generateKeyPair, exportJWK, createLocalJWKSet, type JWK } from "jose";
import { createTokenValidator } from "@iam/auth-sdk";
import { buildApp } from "./app.js";

const ISS = "http://localhost:4444/";

async function setup() {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k", alg: "RS256" } as JWK;
  const app = buildApp(createTokenValidator({ issuer: ISS, jwksUrl: "http://x", audience: "demo-api", keySet: createLocalJWKSet({ keys: [jwk] }) }), { logger: false });
  const tok = (c: Record<string, unknown>) =>
    new SignJWT(c).setProtectedHeader({ alg: "RS256", kid: "k" }).setIssuer(ISS).setAudience(["demo-api"]).setIssuedAt().setExpirationTime("5m").sign(privateKey);
  return { app, tok };
}

test("protected API returns correct status codes", async () => {
  const { app, tok } = await setup();
  const now = Math.floor(Date.now() / 1000);
  const user = await tok({ sub: "u1", client_id: "demo-web", scp: ["profile.read"], ext: { token_kind: "user", loa: "urn:iam:loa:substantial", auth_time: now } });
  const high = await tok({ sub: "u1", client_id: "demo-web", scp: ["profile.read"], ext: { token_kind: "user", loa: "urn:iam:loa:high", auth_time: now } });
  const stale = await tok({ sub: "u1", client_id: "demo-web", scp: ["profile.read"], ext: { token_kind: "user", loa: "urn:iam:loa:high", auth_time: now - 3600 } });
  const machine = await tok({ sub: "svc", client_id: "svc", scp: ["reports.read"] });
  const get = (url: string, t?: string) => app.inject({ url, headers: t ? { authorization: `Bearer ${t}` } : {} });

  assert.equal((await get("/api/public")).statusCode, 200);
  assert.equal((await get("/api/profile")).statusCode, 401);
  assert.equal((await get("/api/profile", "garbage.token.x")).statusCode, 401);
  assert.equal((await get("/api/profile", user)).statusCode, 200);
  assert.equal((await get("/api/profile", machine)).statusCode, 403, "machine token on user endpoint");
  const insufficient = await get("/api/sensitive", user);
  assert.equal(insufficient.statusCode, 401);
  assert.match(String(insufficient.headers["www-authenticate"]), /insufficient_user_authentication.*acr_values="urn:iam:loa:high"/);
  assert.equal((await get("/api/sensitive", stale)).statusCode, 401, "stale authentication");
  assert.equal((await get("/api/sensitive", high)).statusCode, 200);
  assert.equal((await get("/api/reports", machine)).statusCode, 200);
  assert.equal((await get("/api/reports", user)).statusCode, 403, "user token on machine endpoint");
});
