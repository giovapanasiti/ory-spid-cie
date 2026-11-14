/** HTML output encoding helpers. Every interpolated value is escaped unless wrapped in `raw()`. */
const ESC: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" };

export class SafeHtml {
  constructor(readonly value: string) {}
  toString(): string {
    return this.value;
  }
}

export function escapeHtml(v: unknown): string {
  return String(v ?? "").replace(/[&<>"'`]/g, (c) => ESC[c] ?? c);
}

/** Marks trusted, already-encoded HTML. Never pass user input. */
export function raw(v: string): SafeHtml {
  return new SafeHtml(v);
}

function render(v: unknown): string {
  if (v instanceof SafeHtml) return v.value;
  if (Array.isArray(v)) return v.map(render).join("");
  if (v === null || v === undefined || v === false) return "";
  return escapeHtml(v);
}

/** Tagged template that escapes interpolations. */
export function html(strings: TemplateStringsArray, ...values: unknown[]): SafeHtml {
  let out = "";
  strings.forEach((s, i) => {
    out += s;
    if (i < values.length) out += render(values[i]);
  });
  return new SafeHtml(out);
}

/** Allows only http(s) or relative URLs in href/src attributes. */
export function safeUrl(u: string | undefined | null): string {
  if (!u) return "#";
  if (u.startsWith("/") && !u.startsWith("//")) return u;
  try {
    const p = new URL(u);
    return p.protocol === "https:" || p.protocol === "http:" ? p.toString() : "#";
  } catch {
    return "#";
  }
}
