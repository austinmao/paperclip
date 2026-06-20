export const OIDC_LOGIN_TEAL_HSL = "172 76% 42%";

export function renderOidcLoginPage(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to OpenClaw</title>
<style>
:root{--oc-accent:${OIDC_LOGIN_TEAL_HSL};--primary:${OIDC_LOGIN_TEAL_HSL};--primary-foreground:0 0% 100%;--ring:${OIDC_LOGIN_TEAL_HSL};--blue-9:hsl(${OIDC_LOGIN_TEAL_HSL});--background:240 11% 99%;--foreground:220 13% 4%;--muted:220 9% 46%;--border:220 13% 91%;}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:hsl(var(--background));color:hsl(var(--foreground));font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{width:min(100% - 32px,400px)}
h1{margin:0 0 8px;font-size:26px;line-height:1.15;font-weight:700;letter-spacing:0}
p{margin:0 0 24px;color:hsl(var(--muted));line-height:1.5}
form{display:grid;gap:14px}
label{display:grid;gap:7px;font-size:13px;font-weight:600}
input{width:100%;height:44px;border:1px solid hsl(var(--border));border-radius:8px;padding:0 12px;background:white;color:hsl(var(--foreground));font:inherit}
input:focus{outline:2px solid hsl(var(--ring) / .28);border-color:hsl(var(--ring))}
button{height:44px;border:0;border-radius:8px;background:hsl(var(--primary));color:hsl(var(--primary-foreground));font:inherit;font-weight:700;cursor:pointer}
button:disabled{opacity:.65;cursor:wait}
.error{display:none;margin-top:14px;color:#b42318;font-size:14px;line-height:1.4}
.error[data-visible="true"]{display:block}
</style>
</head>
<body>
<main>
<h1>Sign in to OpenClaw</h1>
<p>Use your Paperclip account to continue.</p>
<form id="login-form">
<label>Email<input name="email" type="email" autocomplete="email" required autofocus></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button>
</form>
<p class="error" id="login-error" role="alert"></p>
</main>
<script>
const form=document.getElementById("login-form");
const errorEl=document.getElementById("login-error");
form.addEventListener("submit",async(event)=>{
  event.preventDefault();
  errorEl.dataset.visible="false";
  errorEl.textContent="";
  const button=form.querySelector("button");
  button.disabled=true;
  try{
    const body=Object.fromEntries(new FormData(form).entries());
    const res=await fetch("/api/auth/sign-in/email"+window.location.search,{
      method:"POST",
      headers:{"content-type":"application/json","accept":"application/json"},
      credentials:"include",
      body:JSON.stringify(body)
    });
    const data=await res.json().catch(()=>({}));
    if(!res.ok){
      throw new Error(data?.message||data?.error||"Unable to sign in.");
    }
    const fallback="/api/auth/oauth2/authorize"+window.location.search;
    window.location.href=data?.url||fallback;
  }catch(error){
    errorEl.textContent=error?.message||"Unable to sign in.";
    errorEl.dataset.visible="true";
    button.disabled=false;
  }
});
</script>
</body>
</html>`;
}
