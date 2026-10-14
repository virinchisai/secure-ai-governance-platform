"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError("");
    const form = new FormData(event.currentTarget);
    try {
      const result = await api<{ access_token: string }>("/api/auth/login", { method: "POST", body: JSON.stringify({ username: form.get("username"), password: form.get("password") }) });
      localStorage.setItem("governance_token", result.access_token); router.push("/workspace");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Authentication failed"); setBusy(false); }
  }
  return <main className="login-page"><section className="login-copy"><div className="brand hero"><span className="brand-mark">A</span><span><b>AEGIS</b><small>SECURE AI GOVERNANCE</small></span></div><div><span className="eyebrow">CONTROL THE BOUNDARY</span><h1>AI that earns<br />enterprise trust.</h1><p>Identity-aware controls for every prompt, source, policy decision, approval, and action.</p></div><div className="assurance-row"><span>◆ Deterministic DLP</span><span>◆ Human approval gates</span><span>◆ Full audit lineage</span></div></section><section className="login-panel"><form onSubmit={submit}><div><span className="eyebrow">LOCAL DEMONSTRATION</span><h2>Access the workspace</h2><p>Authenticate with a synthetic demo identity.</p></div><label>Email<input name="username" type="email" defaultValue="analyst@acme.test" required /></label><label>Password<input name="password" type="password" defaultValue="Demo-Analyst-2026!" required /></label>{error && <div className="error">{error}</div>}<button className="primary" disabled={busy}>{busy ? "Authenticating…" : "Continue securely →"}</button><div className="notice"><b>LocalIdentityProvider</b><span>Credentials are synthetic. Microsoft Entra is integration-ready, not connected.</span></div></form></section></main>;
}
