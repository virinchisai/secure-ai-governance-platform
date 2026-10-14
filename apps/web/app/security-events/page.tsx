import { ResourceView } from "@/components/ResourceView";

export default function SecurityEventsPage() { return <ResourceView title="Security Events" eyebrow="SIEM-READY TELEMETRY" path="/api/audit" description="DLP, injection, authorization, approval, and risk signals ready for a forwarding adapter." columns={[["timestamp", "Time"], ["event_type", "Normalized type"], ["tool", "Control / tool"], ["result", "Result"], ["risk_score", "Risk"], ["request_id", "Request ID"]]} />; }
