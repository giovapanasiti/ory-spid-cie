import { test } from "node:test";
import assert from "node:assert/strict";
import { renderFlow, scriptNodes } from "./kratos-form.js";
import type { UiContainer } from "@iam/shared";

const ui: UiContainer = {
  action: "http://localhost:4433/self-service/login?flow=1",
  method: "POST",
  messages: [{ id: 1, text: "<img src=x onerror=alert(1)>", type: "error" }],
  nodes: [
    { type: "input", group: "default", attributes: { node_type: "input", name: "csrf_token", type: "hidden", value: "tok" }, messages: [], meta: {} },
    { type: "input", group: "oidc", attributes: { node_type: "input", name: "provider", type: "submit", value: "spid" }, messages: [], meta: { label: { id: 1, text: "Sign in with spid", type: "info" } } },
    { type: "input", group: "oidc", attributes: { node_type: "input", name: "provider", type: "submit", value: "cie" }, messages: [], meta: {} },
    { type: "input", group: "password", attributes: { node_type: "input", name: "password", type: "password", required: true }, messages: [], meta: { label: { id: 1, text: "Password", type: "info" } } },
    { type: "input", group: "passkey", attributes: { node_type: "input", name: "passkey_login_trigger", type: "button", onclickTrigger: "oryPasskeyLogin" }, messages: [], meta: { label: { id: 1, text: "Sign in with passkey", type: "info" } } },
    { type: "script", group: "passkey", attributes: { node_type: "script", src: "http://localhost:4433/.well-known/ory/webauthn.js", nonce: "n1", async: true }, messages: [], meta: {} },
  ],
};

test("renders SPID/CIE buttons with Italian labels and escapes messages", () => {
  const out = renderFlow(ui).toString();
  assert.match(out, /Accedi con SPID/);
  assert.match(out, /Entra con CIE/);
  assert.match(out, /Accedi con passkey/);
  assert.match(out, /data-ory-onclick="oryPasskeyLogin"/);
  assert.doesNotMatch(out, /<img src=x/);
  assert.ok(out.indexOf("btn-spid") < out.indexOf('name="password"'), "federated first");
});

test("provider filter hides non-compliant methods for step-up", () => {
  const out = renderFlow(ui, { groups: ["oidc"], providers: ["cie"] }).toString();
  assert.doesNotMatch(out, /Accedi con SPID/);
  assert.match(out, /Entra con CIE/);
  assert.doesNotMatch(out, /password/);
});

test("script nodes are extracted for CSP", () => {
  assert.deepEqual(scriptNodes(ui).map((s) => s.nonce), ["n1"]);
});
