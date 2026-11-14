import { HttpError, requestJson } from "@iam/shared";

/** Client for the federation broker admin API (internal listener only). */
export class BrokerAdmin {
  constructor(
    private readonly base: string,
    private readonly token: string,
  ) {}

  async call<T>(method: string, path: string, actor: { id: string; roles: string[] }, body?: unknown): Promise<T> {
    const res = await requestJson<T>(this.base.replace(/\/$/, "") + path, {
      method,
      json: body,
      headers: { authorization: `Bearer ${this.token}`, "x-actor": actor.id, "x-actor-roles": actor.roles.join(",") },
      allowError: true,
      timeoutMs: 20_000,
    });
    if (res.status >= 300) {
      const msg = (res.data as { error?: string } | undefined)?.error ?? `status ${res.status}`;
      throw new HttpError(res.status, res.data, msg);
    }
    return res.data;
  }
}
