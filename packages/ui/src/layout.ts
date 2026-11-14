import { html, raw, type SafeHtml } from "@iam/shared";

export interface LayoutOptions {
  title: string;
  body: SafeHtml;
  nav?: SafeHtml;
  narrow?: boolean;
  brand?: string;
  scripts?: { src: string; nonce?: string; async?: boolean; id?: string; crossorigin?: string; integrity?: string; referrerpolicy?: string; type?: string }[];
  lang?: string;
}

export function layout(o: LayoutOptions): string {
  return html`<!doctype html>
<html lang="${o.lang ?? "it"}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<title>${o.title}</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<header class="top"><span class="brand">${o.brand ?? "IAM Platform"}</span>${o.nav ?? ""}</header>
<main class="${o.narrow ? "narrow" : ""}">
${o.body}
</main>
${(o.scripts ?? []).map(
  (s) =>
    html`<script src="${s.src}"${s.nonce ? raw(` nonce="${escapeAttr(s.nonce)}"`) : ""}${s.async ? raw(" async") : ""}${s.id ? raw(` id="${escapeAttr(s.id)}"`) : ""}${s.crossorigin ? raw(` crossorigin="${escapeAttr(s.crossorigin)}"`) : ""}${s.integrity ? raw(` integrity="${escapeAttr(s.integrity)}"`) : ""}${s.referrerpolicy ? raw(` referrerpolicy="${escapeAttr(s.referrerpolicy)}"`) : ""}${s.type ? raw(` type="${escapeAttr(s.type)}"`) : ""}></script>`,
)}
<script src="/assets/ory-triggers.js"></script>
</body>
</html>`.toString();
}

function escapeAttr(v: string): string {
  return v.replace(/[&<>"'`]/g, (c) => `&#${c.charCodeAt(0)};`);
}

export function messages(list: { text: string; type: string }[] | undefined): SafeHtml {
  return html`${(list ?? []).map((m) => html`<div class="msg ${m.type === "error" ? "error" : m.type === "success" ? "success" : ""}" role="${m.type === "error" ? "alert" : "status"}">${m.text}</div>`)}`;
}

/**
 * Content-Security-Policy builder. `formAction: null` omits the directive: browsers
 * apply form-action to every redirect hop after a form POST, which breaks OAuth2
 * logout/consent chains (app -> Hydra -> login UI -> client). Pages that only post
 * to themselves without cross-origin redirects should keep the default ('self').
 */
export function csp(opts: { scriptSrc?: string[]; formAction?: string[] | null; connectSrc?: string[]; imgSrc?: string[] } = {}): string {
  return [
    "default-src 'self'",
    `script-src 'self' ${(opts.scriptSrc ?? []).join(" ")}`.trim(),
    "style-src 'self'",
    `img-src 'self' data: ${(opts.imgSrc ?? []).join(" ")}`.trim(),
    `connect-src 'self' ${(opts.connectSrc ?? []).join(" ")}`.trim(),
    opts.formAction === null ? "" : `form-action 'self' ${(opts.formAction ?? []).join(" ")}`.trim(),
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
  ]
    .filter(Boolean)
    .join("; ");
}
