export const APP_CSS = `
:root{--fg:#17324d;--bg:#f5f7fa;--card:#fff;--accent:#0066cc;--accent-fg:#fff;--muted:#5c6f82;--danger:#d9364f;--ok:#008055;--warn:#a66300;--border:#c5d0db}
*{box-sizing:border-box}html{font-size:16px}
body{margin:0;font-family:system-ui,-apple-system,"Titillium Web",Segoe UI,sans-serif;background:var(--bg);color:var(--fg);line-height:1.5}
a{color:var(--accent)}header.top{background:var(--fg);color:#fff;padding:.6rem 1rem;display:flex;gap:1rem;align-items:center;flex-wrap:wrap}
header.top a{color:#fff;text-decoration:none;margin-right:.75rem}header.top .brand{font-weight:700;margin-right:auto}
main{max-width:64rem;margin:1.5rem auto;padding:0 1rem}main.narrow{max-width:30rem}
.card{background:var(--card);border-radius:8px;padding:1.5rem;box-shadow:0 1px 4px rgba(0,0,0,.08);margin-bottom:1rem}
h1{font-size:1.5rem;margin:.2rem 0 1rem}h2{font-size:1.2rem;margin:1.2rem 0 .6rem}
label{display:block;font-weight:600;margin:.75rem 0 .25rem}
input[type=text],input[type=email],input[type=password],input[type=url],input[type=number],input[type=search],select,textarea{width:100%;padding:.55rem .6rem;border:1px solid var(--border);border-radius:4px;font:inherit;background:#fff;color:inherit}
textarea{font-family:ui-monospace,Menlo,monospace;font-size:.85rem;min-height:6rem}
button,.btn{display:inline-block;padding:.55rem 1rem;border-radius:4px;border:1px solid var(--accent);background:var(--accent);color:var(--accent-fg);font:inherit;font-weight:600;cursor:pointer;text-decoration:none}
button.secondary,.btn.secondary{background:#fff;color:var(--accent)}button.danger,.btn.danger{background:var(--danger);border-color:var(--danger)}
button.link{background:none;border:none;color:var(--accent);padding:0;text-decoration:underline;font-weight:400}
.btn-spid,.btn-cie{width:100%;margin:.35rem 0;text-align:left;padding:.75rem 1rem;font-size:1.05rem}
.btn-spid{background:#06c;border-color:#06c}.btn-cie{background:#0b3d6b;border-color:#0b3d6b}
.btn-passkey{width:100%;background:#fff;color:var(--fg);border-color:var(--border)}
.stack>*+*{margin-top:.6rem}.row{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}
.msg{padding:.6rem .8rem;border-radius:4px;margin:.5rem 0;border-left:4px solid var(--accent);background:#eef5fc}
.msg.error{border-color:var(--danger);background:#fdecef}.msg.success{border-color:var(--ok);background:#e6f5ef}.msg.warn{border-color:var(--warn);background:#fff4e0}
.muted{color:var(--muted);font-size:.9rem}.sep{display:flex;align-items:center;gap:.6rem;color:var(--muted);margin:1rem 0}.sep:before,.sep:after{content:"";flex:1;border-top:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:.92rem}th,td{text-align:left;padding:.45rem .5rem;border-bottom:1px solid #e3e9ef;vertical-align:top}th{background:#f0f4f8}
code,pre{font-family:ui-monospace,Menlo,monospace;font-size:.85rem}pre{background:#0f2234;color:#e6edf3;padding:1rem;border-radius:6px;overflow:auto;max-height:28rem}
.badge{display:inline-block;padding:.05rem .45rem;border-radius:999px;font-size:.78rem;font-weight:700;background:#e3e9ef}
.badge.ok{background:#d4f0e4;color:#005a3c}.badge.bad{background:#fbd5dc;color:#8a1328}.badge.warn{background:#ffe9c2;color:#6b4100}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(18rem,1fr));gap:1rem}
nav.tabs{display:flex;gap:.25rem;border-bottom:2px solid var(--border);margin-bottom:1rem;flex-wrap:wrap}nav.tabs a{padding:.45rem .8rem;text-decoration:none;border-radius:4px 4px 0 0}nav.tabs a.active{background:var(--fg);color:#fff}
details{margin:.5rem 0}summary{cursor:pointer;font-weight:600}
@media (max-width:40rem){main{margin:.75rem auto}.card{padding:1rem}}
`;

/** Binds Kratos onclickTrigger/onloadTrigger attributes to the functions defined by webauthn.js (CSP-friendly, no inline handlers). */
export const ORY_TRIGGERS_JS = `
(function(){
  function call(name){ var f = window[name]; if (typeof f === "function") { f(); } }
  document.addEventListener("click", function(e){
    var el = e.target.closest ? e.target.closest("[data-ory-onclick]") : null;
    if (el) { e.preventDefault(); call(el.getAttribute("data-ory-onclick")); }
  });
  window.addEventListener("load", function(){
    document.querySelectorAll("[data-ory-onload]").forEach(function(el){ call(el.getAttribute("data-ory-onload")); });
  });
  document.querySelectorAll("form[data-confirm]").forEach(function(f){
    f.addEventListener("submit", function(e){ if(!window.confirm(f.getAttribute("data-confirm"))){ e.preventDefault(); } });
  });
})();
`;
