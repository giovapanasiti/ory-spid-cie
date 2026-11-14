import type { FastifyInstance, FastifyReply } from "fastify";
import cookie from "@fastify/cookie";
import formbody from "@fastify/formbody";
import { APP_CSS, ORY_TRIGGERS_JS } from "./css.js";
import { csp } from "./layout.js";

declare module "fastify" {
  interface FastifyReply {
    cspOverride?: string;
  }
}

/** Common web hardening for server-rendered apps: cookies, forms, security headers, static assets. */
export async function registerWebDefaults(app: FastifyInstance, opts: { secureCookies: boolean; defaultCsp?: string }): Promise<void> {
  await app.register(cookie);
  await app.register(formbody, { bodyLimit: 64 * 1024 });
  app.addHook("onSend", async (_req, reply) => {
    reply.header("x-content-type-options", "nosniff");
    reply.header("x-frame-options", "DENY");
    reply.header("referrer-policy", "same-origin"); // no-referrer would make browsers send "Origin: null" on POST
    reply.header("permissions-policy", "camera=(), microphone=(), geolocation=()");
    reply.header("cross-origin-opener-policy", "same-origin");
    if (opts.secureCookies) reply.header("strict-transport-security", "max-age=63072000; includeSubDomains");
    const ct = String(reply.getHeader("content-type") ?? "");
    if (ct.startsWith("text/html")) {
      reply.header("content-security-policy", reply.cspOverride ?? opts.defaultCsp ?? csp());
      reply.header("cache-control", "no-store");
    }
  });
  app.get("/assets/app.css", async (_req, reply) => reply.type("text/css").header("cache-control", "public, max-age=3600").send(APP_CSS));
  app.get("/assets/ory-triggers.js", async (_req, reply) =>
    reply.type("application/javascript").header("cache-control", "public, max-age=3600").send(ORY_TRIGGERS_JS),
  );
  app.get("/healthz", async () => ({ ok: true }));
}

export function sendHtml(reply: FastifyReply, body: string, status = 200): FastifyReply {
  return reply.code(status).type("text/html; charset=utf-8").send(body);
}
