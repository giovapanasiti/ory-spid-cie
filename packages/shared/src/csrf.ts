import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Stateless CSRF tokens bound to a session identifier: token = nonce.HMAC(secret, binding.nonce).
 * Combined with SameSite cookies and Origin checks (see originAllowed).
 */
export class Csrf {
  constructor(private readonly secret: string) {
    if (secret.length < 32) throw new Error("CSRF secret too short");
  }

  issue(binding: string): string {
    const nonce = randomBytes(16).toString("base64url");
    return `${nonce}.${this.mac(binding, nonce)}`;
  }

  verify(binding: string, token: unknown): boolean {
    if (typeof token !== "string") return false;
    const [nonce, mac] = token.split(".");
    if (!nonce || !mac) return false;
    const want = Buffer.from(this.mac(binding, nonce));
    const got = Buffer.from(mac);
    return want.length === got.length && timingSafeEqual(want, got);
  }

  private mac(binding: string, nonce: string): string {
    return createHmac("sha256", this.secret).update(`${binding}.${nonce}`).digest("base64url");
  }
}

/** Origin/Referer check for state-changing requests. */
export function originAllowed(headers: Record<string, string | string[] | undefined>, allowed: string[]): boolean {
  const origin = headers.origin;
  const value = typeof origin === "string" ? origin : typeof headers.referer === "string" ? headers.referer : undefined;
  if (!value) return false;
  try {
    const o = new URL(value).origin;
    return allowed.some((a) => new URL(a).origin === o);
  } catch {
    return false;
  }
}
