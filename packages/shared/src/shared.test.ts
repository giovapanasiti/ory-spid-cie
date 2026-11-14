import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { html, raw, safeUrl, escapeHtml } from "./html.js";
import { Sealer } from "./seal.js";
import { Csrf, originAllowed } from "./csrf.js";
import { requestedLoA, satisfies, LOA } from "./loa.js";
import { scrubContext } from "./audit.js";

test("html escapes interpolations (XSS)", () => {
  const evil = `<script>alert("x")</script>`;
  assert.equal(html`<p>${evil}</p>`.toString(), "<p>&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;</p>");
  assert.equal(html`<p>${raw("<b>ok</b>")}</p>`.toString(), "<p><b>ok</b></p>");
  assert.equal(escapeHtml("'`"), "&#39;&#96;");
});

test("safeUrl blocks javascript: and protocol-relative URLs", () => {
  assert.equal(safeUrl("javascript:alert(1)"), "#");
  assert.equal(safeUrl("//evil.example"), "#");
  assert.equal(safeUrl("/ok"), "/ok");
  assert.equal(safeUrl("https://ok.example/x"), "https://ok.example/x");
});

test("sealer round-trips, binds purpose, rejects tampering and supports rotation", () => {
  const k1 = randomBytes(32).toString("base64");
  const k2 = randomBytes(32).toString("base64");
  const s = new Sealer(`a:${k1}`);
  const v = s.seal({ x: 1 }, "session", 60);
  assert.deepEqual(s.open(v, "session"), { x: 1 });
  assert.equal(s.open(v, "other"), null);
  assert.equal(s.open(v.slice(0, -3) + "AAA", "session"), null);
  const rotated = new Sealer(`b:${k2},a:${k1}`);
  assert.deepEqual(rotated.open(v, "session"), { x: 1 });
  assert.equal(s.open(s.seal(1, "p", -1), "p"), null, "expired values rejected");
});

test("csrf tokens are bound to the session", () => {
  const c = new Csrf("x".repeat(40));
  const t = c.issue("sess-1");
  assert.ok(c.verify("sess-1", t));
  assert.ok(!c.verify("sess-2", t));
  assert.ok(!c.verify("sess-1", "garbage"));
  assert.ok(originAllowed({ origin: "http://localhost:3100" }, ["http://localhost:3100"]));
  assert.ok(!originAllowed({ origin: "http://evil.example" }, ["http://localhost:3100"]));
  assert.ok(!originAllowed({}, ["http://localhost:3100"]));
});

test("LoA ordering and requested level", () => {
  assert.equal(requestedLoA([LOA.LOW, LOA.HIGH, "other"]), LOA.HIGH);
  assert.ok(satisfies(LOA.HIGH, LOA.SUBSTANTIAL));
  assert.ok(!satisfies(LOA.NONE, LOA.LOW));
  assert.ok(!satisfies(LOA.HIGH, "bogus"));
});

test("audit context scrubbing removes secrets and PII", () => {
  const out = scrubContext({ access_token: "x", fiscal_number: "y", email: "z", provider: "spid", reason: "ok" });
  assert.deepEqual(out, { provider: "spid", reason: "ok" });
});
