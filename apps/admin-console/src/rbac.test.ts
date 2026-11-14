import { test } from "node:test";
import assert from "node:assert/strict";
import { can } from "./rbac.js";

test("least privilege role matrix", () => {
  assert.ok(can(["viewer"], "federation.read"));
  assert.ok(!can(["viewer"], "federation.write"), "viewer cannot change federation");
  assert.ok(!can(["client-admin"], "federation.read"));
  assert.ok(!can(["federation-admin"], "roles.manage"), "no privilege escalation via federation-admin");
  assert.ok(!can(["support"], "clients.write"));
  assert.ok(can(["support"], "sessions.revoke"));
  assert.ok(!can([], "dashboard"));
  assert.ok(can(["superadmin"], "roles.manage"));
});
