import { html, raw, safeUrl, type SafeHtml } from "@iam/shared";
import type { UiContainer, UiNode } from "@iam/shared";
import { messages } from "./layout.js";

/** Labels for federated providers; official SPID/CIE graphic assets must follow AgID / MinInterno rules. */
const PROVIDER_LABEL: Record<string, string> = { spid: "Accedi con SPID", cie: "Entra con CIE" };

function label(n: UiNode): string {
  return n.meta?.label?.text ?? n.attributes.name ?? "";
}

function renderInput(n: UiNode, extraHidden: SafeHtml): SafeHtml {
  const a = n.attributes;
  const name = a.name ?? "";
  const value = a.value === undefined || a.value === null ? "" : String(a.value);
  const nodeMsgs = messages(n.messages);
  if (a.type === "hidden") {
    return html`<input type="hidden" name="${name}" value="${value}">`;
  }
  if (a.type === "submit" || a.type === "button") {
    if (n.group === "oidc" && name === "provider") {
      const cls = value === "cie" ? "btn-cie" : value === "spid" ? "btn-spid" : "secondary";
      return html`<button type="submit" name="${name}" value="${value}" class="${cls}" data-provider="${value}">${PROVIDER_LABEL[value] ?? label(n)}</button>${nodeMsgs}`;
    }
    if (a.onclickTrigger) {
      const cls = n.group === "passkey" || n.group === "webauthn" ? "btn-passkey" : "";
      const text = n.group === "passkey" && /login|sign in|accedi/i.test(label(n)) ? "Accedi con passkey" : label(n);
      return html`<button type="${a.type}" name="${name}" value="${value}" class="${cls}" data-ory-onclick="${a.onclickTrigger}"${a.disabled ? raw(" disabled") : ""}>${text}</button>${nodeMsgs}`;
    }
    const cls = name === "link" || name === "unlink" ? "secondary" : "";
    return html`<button type="${a.type}" name="${name}" value="${value}" class="${cls}"${a.disabled ? raw(" disabled") : ""}>${label(n)}</button>${nodeMsgs}`;
  }
  if (a.type === "checkbox") {
    return html`<label><input type="checkbox" name="${name}" value="true"${value === "true" ? raw(" checked") : ""}> ${label(n)}</label>${nodeMsgs}`;
  }
  const id = `f_${name.replace(/[^a-zA-Z0-9_]/g, "_")}`;
  const onload = a.onloadTrigger ? html` data-ory-onload="${a.onloadTrigger}"` : "";
  void extraHidden;
  return html`<label for="${id}">${label(n)}</label>
<input id="${id}" type="${a.type ?? "text"}" name="${name}" value="${value}"${a.required ? raw(" required") : ""}${a.disabled ? raw(" disabled") : ""}${a.autocomplete ? html` autocomplete="${a.autocomplete}"` : ""}${a.pattern ? html` pattern="${a.pattern}"` : ""}${onload}>${nodeMsgs}`;
}

function renderNode(n: UiNode): SafeHtml {
  const a = n.attributes;
  switch (a.node_type) {
    case "input":
      return renderInput(n, html``);
    case "img":
      return html`<figure><img src="${safeUrl(a.src)}" alt="${label(n)}" width="${a.width ?? 200}" height="${a.height ?? 200}"><figcaption class="muted">${label(n)}</figcaption></figure>`;
    case "a":
      return html`<p><a href="${safeUrl(a.href)}">${a.title?.text ?? label(n)}</a></p>`;
    case "text":
      return html`<div class="msg"><strong>${label(n)}</strong><pre>${a.text?.text ?? ""}</pre></div>`;
    default:
      return html``;
  }
}

export interface FlowRenderOptions {
  /** Only render these groups (e.g. ["default","oidc"]); others hidden. */
  groups?: string[];
  /** Restrict oidc buttons to these providers (assurance policy). */
  providers?: string[];
  /** Extra hidden fields added to the oidc form (e.g. upstream_parameters.acr_values). */
  oidcHidden?: Record<string, string>;
}

/** Collects script nodes (Kratos webauthn.js) to be added to the page and CSP. */
export function scriptNodes(ui: UiContainer) {
  return ui.nodes
    .filter((n) => n.attributes.node_type === "script" && n.attributes.src)
    .map((n) => ({
      src: n.attributes.src!,
      nonce: n.attributes.nonce,
      async: n.attributes.async,
      id: n.attributes.id,
      crossorigin: n.attributes.crossorigin,
      integrity: n.attributes.integrity,
      referrerpolicy: n.attributes.referrerpolicy,
      type: n.attributes.type,
    }));
}

/**
 * Renders a Kratos flow. Federated (oidc) buttons are rendered first, then
 * passkey, then the remaining methods, each as a separate form posting to the
 * Kratos action URL (as recommended by Ory for multi-method UIs).
 */
export function renderFlow(ui: UiContainer, opts: FlowRenderOptions = {}): SafeHtml {
  const nodes = ui.nodes.filter((n) => n.attributes.node_type !== "script");
  const hidden = nodes.filter((n) => n.group === "default" && n.attributes.type === "hidden");
  const visibleDefault = nodes.filter((n) => n.group === "default" && n.attributes.type !== "hidden");
  const byGroup = new Map<string, UiNode[]>();
  for (const n of nodes) {
    if (n.group === "default") continue;
    if (opts.groups && !opts.groups.includes(n.group)) continue;
    if (n.group === "oidc" && opts.providers && n.attributes.name === "provider" && !opts.providers.includes(String(n.attributes.value))) continue;
    const list = byGroup.get(n.group) ?? [];
    list.push(n);
    byGroup.set(n.group, list);
  }
  const order = ["oidc", "passkey", "webauthn", "identifier_first", "password", "code", "profile", "totp", "lookup_secret", "link"];
  const groups = [...byGroup.keys()].sort((a, b) => (order.indexOf(a) + 100) % 100 - (order.indexOf(b) + 100) % 100);
  const hiddenHtml = html`${hidden.map(renderNode)}`;
  const forms = groups.map((g, i) => {
    const groupNodes = byGroup.get(g) ?? [];
    const needsDefault = g === "password" || g === "profile" || g === "code" || g === "identifier_first" || g === "passkey" || g === "webauthn";
    return html`${i > 0 ? raw('<div class="sep">oppure / or</div>') : ""}
<form method="${ui.method}" action="${safeUrl(ui.action)}" class="stack" data-group="${g}">
${hiddenHtml}${g === "oidc" ? html`${Object.entries(opts.oidcHidden ?? {}).map(([k, v]) => html`<input type="hidden" name="${k}" value="${v}">`)}` : ""}${needsDefault ? html`${visibleDefault.map(renderNode)}` : ""}${groupNodes.map(renderNode)}
</form>`;
  });
  return html`${messages(ui.messages)}${forms}`;
}
