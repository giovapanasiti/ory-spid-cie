import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * AES-256-GCM sealing for stateless encrypted cookies. Keys: "kid:base64[,kid:base64]";
 * the first key seals, all keys open (rotation).
 */
export class Sealer {
  private readonly keys = new Map<string, Buffer>();
  private readonly primary: string;

  constructor(spec: string) {
    let first: string | undefined;
    for (const part of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
      const i = part.indexOf(":");
      if (i <= 0) throw new Error("seal key spec must be kid:base64key");
      const kid = part.slice(0, i);
      const key = Buffer.from(part.slice(i + 1), "base64");
      if (key.length !== 32) throw new Error(`seal key ${kid} must be 32 bytes`);
      this.keys.set(kid, key);
      first ??= kid;
    }
    if (!first) throw new Error("no seal key configured");
    this.primary = first;
  }

  seal(value: unknown, purpose: string, ttlSeconds: number): string {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", this.keys.get(this.primary)!, iv);
    c.setAAD(Buffer.from(purpose));
    const payload = JSON.stringify({ v: value, exp: Math.floor(Date.now() / 1000) + ttlSeconds });
    const ct = Buffer.concat([c.update(payload, "utf8"), c.final()]);
    return [this.primary, iv.toString("base64url"), ct.toString("base64url"), c.getAuthTag().toString("base64url")].join(".");
  }

  open<T>(sealed: string | undefined, purpose: string): T | null {
    if (!sealed) return null;
    const [kid, iv, ct, tag] = sealed.split(".");
    const key = kid ? this.keys.get(kid) : undefined;
    if (!key || !iv || !ct || !tag) return null;
    try {
      const d = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
      d.setAAD(Buffer.from(purpose));
      d.setAuthTag(Buffer.from(tag, "base64url"));
      const pt = Buffer.concat([d.update(Buffer.from(ct, "base64url")), d.final()]).toString("utf8");
      const parsed = JSON.parse(pt) as { v: T; exp: number };
      if (parsed.exp < Math.floor(Date.now() / 1000)) return null;
      return parsed.v;
    } catch {
      return null;
    }
  }
}
