/** Small fetch wrapper with timeouts and typed errors for service-to-service calls. */
export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly body: unknown,
    message: string,
  ) {
    super(message);
  }
}

export interface RequestOptions {
  method?: string;
  headers?: Record<string, string>;
  json?: unknown;
  form?: Record<string, string>;
  timeoutMs?: number;
  /** Return the response even for non-2xx statuses. */
  allowError?: boolean;
}

export interface JsonResponse<T> {
  status: number;
  headers: Headers;
  data: T;
}

export async function requestJson<T>(url: string, opts: RequestOptions = {}): Promise<JsonResponse<T>> {
  const headers: Record<string, string> = { accept: "application/json", ...opts.headers };
  let body: string | undefined;
  if (opts.json !== undefined) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(opts.json);
  } else if (opts.form) {
    headers["content-type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(opts.form).toString();
  }
  const res = await fetch(url, {
    method: opts.method ?? (body ? "POST" : "GET"),
    headers,
    body,
    redirect: "manual",
    signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000),
  });
  const text = await res.text();
  let data: unknown = undefined;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!opts.allowError && (res.status < 200 || res.status >= 300)) {
    throw new HttpError(res.status, data, `${opts.method ?? "GET"} ${new URL(url).pathname} -> ${res.status}`);
  }
  return { status: res.status, headers: res.headers, data: data as T };
}
