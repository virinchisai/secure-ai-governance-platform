"use client";

import { useEffect, useState } from "react";
import { Empty, Pill, Shell } from "@/components/Shell";
import { api } from "@/lib/api";

type Risk = { score: number; signals: { signal_id: string; name: string; score: number; reason: string }[] };
export default function RiskPage() {
  const [risk, setRisk] = useState<Risk | null>(null); useEffect(() => { api<Risk>("/api/risk").then(setRisk); }, []);
  const score = risk?.score ?? 0;
  return <Shell title="Risk Dashboard" eyebrow="INSIDER-RISK STYLE ANALYTICS"><section className="risk-hero card"><div className="risk-gauge" style={{ "--score": `${score * 3.6}deg` } as React.CSSProperties}><div><strong>{score}</strong><span>/100</span></div></div><div><Pill tone={score >= 50 ? "bad" : score >= 20 ? "warn" : "good"}>{score >= 50 ? "Elevated" : score >= 20 ? "Review" : "Low"} risk</Pill><h2>Explainable behavioral score</h2><p>Local thresholds evaluate access, blocked exports, external sharing, authorization failures, sensitive enumeration, privilege-sensitive actions, and unusual time.</p></div></section><section className="card"><div className="card-head"><h2>Contributing signals</h2><span className="mono">{risk?.signals.length ?? 0} ACTIVE</span></div>{risk?.signals.length ? <div className="signal-list">{risk.signals.map(signal => <div key={signal.signal_id}><span>+{signal.score}</span><div><b>{signal.name.replaceAll("_", " ")}</b><p>{signal.reason}</p></div></div>)}</div> : <Empty>No behavioral threshold is currently active. This is observed data, not a fabricated metric.</Empty>}</section></Shell>;
}
