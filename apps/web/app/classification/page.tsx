"use client";

import { FormEvent, useState } from "react";
import { Empty, Pill, Shell } from "@/components/Shell";
import { api } from "@/lib/api";

type Result = { classification: string; sensitivity_label: string; confidence: number; reasons: string[]; applicable_policies: string[]; entities: { entity_type: string; masked_value: string; confidence: number }[] };
export default function ClassificationPage() {
  const [text, setText] = useState("Synthetic customer CUST-DEMO001 can be reached at customer@example.test."); const [result, setResult] = useState<Result | null>(null);
  async function submit(event: FormEvent) { event.preventDefault(); setResult(await api<Result>("/api/classify", { method: "POST", body: JSON.stringify({ content: text }) })); }
  return <Shell title="Data Classification" eyebrow="PURVIEW-STYLE LOCAL SIMULATION"><div className="split-page"><section className="card"><div className="card-head"><div><h2>Inspect content</h2><p>No content leaves the local API.</p></div><Pill tone="info">Deterministic</Pill></div><form onSubmit={submit} className="classifier-form"><textarea value={text} onChange={event => setText(event.target.value)} /><button className="primary">Classify content</button></form></section><section className="card"><div className="card-head"><h2>Classification result</h2>{result && <Pill tone={result.classification.includes("HIGHLY") ? "bad" : result.classification === "CONFIDENTIAL" ? "warn" : "good"}>{result.classification}</Pill>}</div>{result ? <div className="classification-result"><div className="label-block"><small>SENSITIVITY LABEL</small><b>{result.sensitivity_label}</b><span>{Math.round(result.confidence * 100)}% rule confidence</span></div><h3>Detected entities</h3>{result.entities.map((entity, index) => <div className="entity" key={`${entity.entity_type}-${index}`}><Pill tone="warn">{entity.entity_type}</Pill><code>{entity.masked_value}</code><span>{Math.round(entity.confidence * 100)}%</span></div>)}<h3>Applicable policies</h3><div className="policy-links">{result.applicable_policies.map(policy => <code key={policy}>{policy}</code>)}</div></div> : <Empty>Submit text to inspect entities and labels.</Empty>}</section></div></Shell>;
}
