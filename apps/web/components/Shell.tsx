"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ReactNode, useEffect } from "react";

const nav = [
  ["AI Workspace", "/workspace", "✦"],
  ["Documents", "/documents", "▤"],
  ["Classification", "/classification", "◇"],
  ["DLP Policies", "/policies", "⬡"],
  ["Approvals", "/approvals", "✓"],
  ["Risk Dashboard", "/risk", "◉"],
  ["Audit Events", "/audit", "⌁"],
  ["Security Events", "/security-events", "△"],
  ["Integrations", "/settings/integrations", "⚙"],
] as const;

export function Shell({ title, eyebrow, children }: { title: string; eyebrow: string; children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  useEffect(() => {
    if (!localStorage.getItem("governance_token")) router.replace("/");
  }, [router]);
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Link href="/workspace" className="brand"><span className="brand-mark">A</span><span><b>AEGIS</b><small>AI GOVERNANCE</small></span></Link>
        <div className="tenant-card"><span className="status-dot" /><div><small>WORKSPACE</small><strong>Acme Labs</strong></div><span className="chevron">⌄</span></div>
        <nav>{nav.map(([label, href, icon]) => <Link key={href} href={href} className={pathname === href ? "active" : ""}><span>{icon}</span>{label}</Link>)}</nav>
        <div className="sidebar-foot"><div className="simulation"><span>LOCAL</span><b>Simulation mode</b><small>No cloud credentials active</small></div><button onClick={() => { localStorage.removeItem("governance_token"); router.push("/"); }}>Sign out</button></div>
      </aside>
      <main className="main"><header className="topbar"><div><span className="eyebrow">{eyebrow}</span><h1>{title}</h1></div><div className="identity"><span>AN</span><div><b>Demo Analyst</b><small>analyst · acme-labs</small></div></div></header>{children}</main>
    </div>
  );
}

export function Pill({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "good" | "warn" | "bad" | "info" }) {
  return <span className={`pill ${tone}`}>{children}</span>;
}

export function Empty({ children }: { children: ReactNode }) { return <div className="empty">{children}</div>; }
