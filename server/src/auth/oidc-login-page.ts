export const OIDC_LOGIN_TEAL_HSL = "172 76% 42%";

/** Platform brand shown on the hosted login page. */
export const DEFAULT_OIDC_APP_NAME = "Glance";

/** Escape a value before interpolating it into the login HTML (env-sourced
 *  strings must not be able to inject markup). */
function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Brand name in the title + heading. Env-overridable (OPENCLAW_OIDC_APP_NAME)
 *  so the shared IdP login can be rebranded per deployment without a code
 *  change; defaults to the platform brand. */
function oidcAppName(): string {
  const raw = process.env.OPENCLAW_OIDC_APP_NAME?.trim();
  return escapeHtml(raw && raw.length > 0 ? raw : DEFAULT_OIDC_APP_NAME);
}

/** Optional subtitle under the heading. Empty by default - the internal IdP
 *  name is not surfaced to end users. Set OPENCLAW_OIDC_SUBTITLE to show one. */
function oidcSubtitle(): string {
  const raw = process.env.OPENCLAW_OIDC_SUBTITLE?.trim();
  return raw ? `\n<p>${escapeHtml(raw)}</p>` : "";
}

export function renderOidcLoginPage(): string {
  const appName = oidcAppName();
  const subtitle = oidcSubtitle();
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to ${appName}</title>
<style>
:root{--oc-accent:${OIDC_LOGIN_TEAL_HSL};--primary:${OIDC_LOGIN_TEAL_HSL};--primary-foreground:0 0% 100%;--ring:${OIDC_LOGIN_TEAL_HSL};--blue-9:hsl(${OIDC_LOGIN_TEAL_HSL});--background:240 11% 99%;--foreground:220 13% 4%;--muted:220 9% 46%;--border:220 13% 91%;}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:hsl(var(--background));color:hsl(var(--foreground));font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{width:min(100% - 32px,420px)}
h1{margin:0 0 8px;font-size:26px;line-height:1.15;font-weight:700;letter-spacing:0}
p{margin:0 0 24px;color:hsl(var(--muted));line-height:1.5}
form{display:grid;gap:14px}
label{display:grid;gap:7px;font-size:13px;font-weight:600}
input{width:100%;height:44px;border:1px solid hsl(var(--border));border-radius:8px;padding:0 12px;background:white;color:hsl(var(--foreground));font:inherit}
input:focus{outline:2px solid hsl(var(--ring) / .28);border-color:hsl(var(--ring))}
button{height:44px;border:0;border-radius:8px;background:hsl(var(--primary));color:hsl(var(--primary-foreground));font:inherit;font-weight:700;cursor:pointer}
button:disabled{opacity:.65;cursor:wait}
.tabs{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:18px 0}
.tab{background:white;color:hsl(var(--foreground));border:1px solid hsl(var(--border));font-weight:700}
.tab[aria-selected="true"]{background:hsl(var(--primary));color:hsl(var(--primary-foreground));border-color:hsl(var(--primary))}
.panel[hidden]{display:none}
.secondary{background:transparent;color:hsl(var(--foreground));border:1px solid hsl(var(--border))}
.link-button{height:auto;border:0;background:transparent;color:hsl(var(--primary));padding:0;font-weight:700;text-align:left}
.state{border:1px solid hsl(var(--border));border-radius:8px;background:white;padding:18px;margin-top:16px}
.state h2{font-size:18px;line-height:1.25;margin:0 0 8px}
.error{display:none;margin-top:14px;color:#b42318;font-size:14px;line-height:1.4}
.error[data-visible="true"]{display:block}
</style>
</head>
<body>
<main>
<h1>Sign in to ${appName}</h1>${subtitle}
<div class="tabs" role="tablist" aria-label="Sign-in options">
<button class="tab" id="magic-tab" type="button" role="tab" aria-controls="magic-panel" aria-selected="true">Email link</button>
<button class="tab" id="password-tab" type="button" role="tab" aria-controls="password-panel" aria-selected="false">Password</button>
</div>
<section class="panel" id="magic-panel" role="tabpanel" aria-labelledby="magic-tab">
<form id="magic-form">
<label>Email<input name="email" type="email" autocomplete="email" required autofocus></label>
<button type="submit">Email me a link</button>
</form>
</section>
<section class="panel" id="password-panel" role="tabpanel" aria-labelledby="password-tab" hidden>
<form id="password-form">
<label>Email<input name="email" type="email" autocomplete="email" required></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button>
<button class="link-button" id="forgot-open" type="button">Forgot password?</button>
</form>
</section>
<section class="panel state" id="forgot-panel" aria-labelledby="forgot-heading" hidden>
<h2 id="forgot-heading">Reset your password</h2>
<p>Enter your email and we will send a reset link if an account exists.</p>
<form id="forgot-form">
<label>Email<input name="email" type="email" autocomplete="email" required></label>
<button type="submit">Send reset link</button>
<button class="secondary" id="forgot-back" type="button">Back to sign in</button>
</form>
</section>
<section class="state" id="check-email-panel" role="status" hidden>
<h2>Check your email</h2>
<p>Open the secure link we sent to continue.</p>
<button class="secondary" id="check-back" type="button">Back to sign in</button>
</section>
<section class="panel state" id="reset-panel" aria-labelledby="reset-heading" hidden>
<h2 id="reset-heading">Choose a new password</h2>
<form id="reset-form">
<label>New password<input name="newPassword" type="password" autocomplete="new-password" minlength="8" required></label>
<label>Confirm password<input name="confirmPassword" type="password" autocomplete="new-password" minlength="8" required></label>
<button type="submit">Update password</button>
</form>
</section>
<section class="state" id="reset-complete-panel" role="status" hidden>
<h2>Password updated</h2>
<p>You can now sign in with your new password.</p>
<button class="secondary" id="reset-complete-back" type="button">Back to sign in</button>
</section>
<section class="state" id="expired-panel" role="alert" hidden>
<h2>Link expired</h2>
<p>This link can no longer be used. Request a new sign-in link to continue.</p>
<button class="secondary" id="expired-back" type="button">Back to sign in</button>
</section>
<p class="error" id="login-error" role="alert"></p>
</main>
<script>
const magicForm=document.getElementById("magic-form");
const passwordForm=document.getElementById("password-form");
const forgotForm=document.getElementById("forgot-form");
const resetForm=document.getElementById("reset-form");
const errorEl=document.getElementById("login-error");
const panels=["magic-panel","password-panel","forgot-panel","check-email-panel","reset-panel","reset-complete-panel","expired-panel"].map((id)=>document.getElementById(id));
function showPanel(id){
  panels.forEach((panel)=>{ panel.hidden=panel.id!==id; });
  document.getElementById("magic-tab").setAttribute("aria-selected", id==="magic-panel" ? "true" : "false");
  document.getElementById("password-tab").setAttribute("aria-selected", id==="password-panel" ? "true" : "false");
  errorEl.dataset.visible="false";
  errorEl.textContent="";
}
function setBusy(form,busy){
  const button=form.querySelector('button[type="submit"]');
  if(button) button.disabled=busy;
}
async function postJson(path, form){
  errorEl.dataset.visible="false";
  errorEl.textContent="";
  setBusy(form,true);
  try{
    const body=Object.fromEntries(new FormData(form).entries());
    if(path==="/api/auth/sign-in/magic-link"){
      body.callbackURL=window.location.origin+"/api/auth/oauth2/authorize"+window.location.search;
    }
    if(path==="/api/auth/request-password-reset"){
      body.redirectTo=window.location.origin+"/oidc-login?state=reset-password";
    }
    if(path==="/api/auth/reset-password"){
      const params=new URLSearchParams(window.location.search);
      const token=params.get("token");
      if(body.newPassword!==body.confirmPassword){
        throw new Error("Passwords do not match.");
      }
      if(!token){
        throw new Error("Reset token is missing.");
      }
      body.token=token;
      delete body.confirmPassword;
    }
    const res=await fetch(path+window.location.search,{
      method:"POST",
      headers:{"content-type":"application/json","accept":"application/json"},
      credentials:"include",
      body:JSON.stringify(body)
    });
    const data=await res.json().catch(()=>({}));
    if(!res.ok){
      throw new Error(data?.message||data?.error||"Unable to sign in.");
    }
    return data;
  }catch(error){
    errorEl.textContent=error?.message||"Unable to sign in.";
    errorEl.dataset.visible="true";
    setBusy(form,false);
    return null;
  }
}
document.getElementById("magic-tab").addEventListener("click",()=>showPanel("magic-panel"));
document.getElementById("password-tab").addEventListener("click",()=>showPanel("password-panel"));
document.getElementById("forgot-open").addEventListener("click",()=>showPanel("forgot-panel"));
document.getElementById("forgot-back").addEventListener("click",()=>showPanel("password-panel"));
document.getElementById("check-back").addEventListener("click",()=>showPanel("magic-panel"));
document.getElementById("expired-back").addEventListener("click",()=>showPanel("magic-panel"));
document.getElementById("reset-complete-back").addEventListener("click",()=>showPanel("password-panel"));
magicForm.addEventListener("submit",async(event)=>{
  event.preventDefault();
  const data=await postJson("/api/auth/sign-in/magic-link", magicForm);
  if(data) showPanel("check-email-panel");
  setBusy(magicForm,false);
});
passwordForm.addEventListener("submit",async(event)=>{
  event.preventDefault();
  const data=await postJson("/api/auth/sign-in/email", passwordForm);
  if(!data){ setBusy(passwordForm,false); return; }
  const authorizeUrl="/api/auth/oauth2/authorize"+window.location.search;
  window.location.href=data?.url||authorizeUrl;
});
forgotForm.addEventListener("submit",async(event)=>{
  event.preventDefault();
  const data=await postJson("/api/auth/request-password-reset", forgotForm);
  if(data) showPanel("check-email-panel");
  setBusy(forgotForm,false);
});
resetForm.addEventListener("submit",async(event)=>{
  event.preventDefault();
  const data=await postJson("/api/auth/reset-password", resetForm);
  if(data) showPanel("reset-complete-panel");
  setBusy(resetForm,false);
});
const params=new URLSearchParams(window.location.search);
if(params.get("state")==="reset-password"||params.has("token")){
  showPanel("reset-panel");
}else if(params.get("state")==="expired-link"){
  showPanel("expired-panel");
}
</script>
</body>
</html>`;
}
