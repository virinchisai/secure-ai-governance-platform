"use client";

import { useEffect, useState } from "react";
import { Empty, Pill, Shell } from "@/components/Shell";
import { api } from "@/lib/api";

type Row = Record<string, unknown>;

function value(row: Row, key: string) {
  const item = row[key];
  if (Array.isArray(item)) return item.join(", ");
  if (typeof item === "object" && item !== null) return JSON.stringify(item);
  return String(item ?? "—");
}

export function ResourceView({ title, eyebrow, path, columns, description }: { title: string; eyebrow: string; path: string; columns: [string, string][]; description: string }) {
  const [rows, setRows] = useState<Row[]>([]); const [error, setError] = useState("");
  useEffect(() => { api<Row[]>(path).then(setRows).catch((reason: Error) => setError(reason.message)); }, [path]);
  return <Shell title={title} eyebrow={eyebrow}><section className="page-intro"><p>{description}</p><Pill tone="info">Live local data</Pill></section><section className="card table-card"><div className="card-head"><div><h2>{title}</h2><p>{rows.length} records visible in this workspace</p></div><button className="secondary" onClick={() => window.location.reload()}>Refresh</button></div>{error ? <div className="error">{error}</div> : rows.length ? <div className="table-wrap"><table><thead><tr>{columns.map(([key, label]) => <th key={key}>{label}</th>)}</tr></thead><tbody>{rows.map((row, index) => <tr key={String(row.event_id ?? row.approval_id ?? row.document_id ?? row.policy_id ?? index)}>{columns.map(([key]) => <td key={key}>{key.includes("decision") || key === "status" || key === "effect" ? <Pill tone={value(row, key).includes("BLOCK") || value(row, key).includes("REJECT") ? "bad" : value(row, key).includes("APPROVAL") || value(row, key).includes("PENDING") ? "warn" : "good"}>{value(row, key)}</Pill> : value(row, key)}</td>)}</tr>)}</tbody></table></div> : <Empty>No records yet. Exercise the AI workspace to generate governance events.</Empty>}</section></Shell>;
}
