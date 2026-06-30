export const OIDC_CONSENT_MARKER = "openclaw-oidc-consent-v1";

/** Platform brand shown on the hosted consent page. */
export const DEFAULT_OIDC_CONSENT_APP_NAME = "Glance";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function oidcAppName(): string {
  const raw = process.env.OPENCLAW_OIDC_APP_NAME?.trim();
  return escapeHtml(raw && raw.length > 0 ? raw : DEFAULT_OIDC_CONSENT_APP_NAME);
}

export function renderOidcConsentPage(): string {
  const appName = oidcAppName();
  return `<!doctype html>
<html lang="en" data-openclaw-page="${OIDC_CONSENT_MARKER}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize ${appName}</title>
<style>
:root{--oc-accent:172 76% 42%;--primary:172 76% 42%;--primary-foreground:0 0% 100%;--ring:172 76% 42%;--background:240 11% 99%;--foreground:220 13% 4%;--muted:220 9% 46%;--border:220 13% 91%;--danger:4 74% 42%}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:hsl(var(--background));color:hsl(var(--foreground));font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{width:min(100% - 32px,440px)}
h1{margin:0 0 8px;font-size:26px;line-height:1.15;font-weight:700;letter-spacing:0}
p{margin:0 0 20px;color:hsl(var(--muted));line-height:1.5}
.client{font-weight:700;color:hsl(var(--foreground))}
.scope-list{display:grid;gap:8px;margin:0 0 22px;padding:0;list-style:none}
.scope-list li{padding:10px 12px;border:1px solid hsl(var(--border));border-radius:8px;background:white;font-size:14px}
.actions{display:grid;grid-template-columns:1fr 1fr;gap:10px}
button{height:44px;border:0;border-radius:8px;font:inherit;font-weight:700;cursor:pointer}
button:disabled{opacity:.65;cursor:wait}
.approve{background:hsl(var(--primary));color:hsl(var(--primary-foreground))}
.deny{background:white;color:hsl(var(--danger));border:1px solid hsl(var(--border))}
.error{display:none;margin-top:14px;color:hsl(var(--danger));font-size:14px;line-height:1.4}
.error[data-visible="true"]{display:block}
</style>
</head>
<body>
<main>
<h1>Authorize ${appName}</h1>
<p><span class="client" id="client-name">This connector</span> is requesting access to your account.</p>
<ul class="scope-list" id="scope-list" aria-label="Requested access">
<li>Review your basic profile</li>
</ul>
<div class="actions">
<button class="deny" type="button" data-consent="deny">Deny</button>
<button class="approve" type="button" data-consent="approve" autofocus>Approve</button>
</div>
<p class="error" id="consent-error" role="alert"></p>
</main>
<script>
const params=new URLSearchParams(window.location.search);
const clientName=document.getElementById("client-name");
const scopeList=document.getElementById("scope-list");
const errorEl=document.getElementById("consent-error");
const scopeLabels=new Map([
  ["openid","Confirm your identity"],
  ["profile","Read your profile"],
  ["email","Read your email address"],
  ["offline_access","Keep the connector authorized"]
]);
const displayName=params.get("client_name")||params.get("client_id")||"This connector";
clientName.textContent=displayName;
const scopes=String(params.get("scope")||"openid").split(/\\s+/).filter(Boolean);
scopeList.replaceChildren(...scopes.map((scope)=>{
  const item=document.createElement("li");
  item.textContent=scopeLabels.get(scope)||scope;
  return item;
}));
async function submitConsent(accept){
  errorEl.dataset.visible="false";
  errorEl.textContent="";
  for(const button of document.querySelectorAll("button")) button.disabled=true;
  try{
    const res=await fetch("/api/auth/oauth2/consent"+window.location.search,{
      method:"POST",
      headers:{"content-type":"application/json","accept":"application/json"},
      credentials:"include",
      body:JSON.stringify({accept,oauth_query:window.location.search.slice(1)})
    });
    const data=await res.json().catch(()=>({}));
    if(!res.ok) throw new Error(data?.message||data?.error_description||data?.error||"Unable to record consent.");
    window.location.href=data?.url||data?.redirectTo||data?.redirect_uri||"/";
  }catch(error){
    errorEl.textContent=error?.message||"Unable to record consent.";
    errorEl.dataset.visible="true";
    for(const button of document.querySelectorAll("button")) button.disabled=false;
  }
}
document.querySelector('[data-consent="approve"]').addEventListener("click",()=>submitConsent(true));
document.querySelector('[data-consent="deny"]').addEventListener("click",()=>submitConsent(false));
</script>
</body>
</html>`;
}
