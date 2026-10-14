import { ResourceView } from "@/components/ResourceView";

export default function AuditPage() { return <ResourceView title="Audit Events" eyebrow="IMMUTABLE DECISION LINEAGE" path="/api/audit" description="Normalized, tenant-scoped event history without raw sensitive payloads." columns={[["timestamp", "Time"], ["event_type", "Event"], ["action", "Action"], ["policy_decision", "Decision"], ["policy_id", "Policy"], ["reason", "Reason"]]} />; }
