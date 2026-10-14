import { ResourceView } from "@/components/ResourceView";

export default function ApprovalsPage() { return <ResourceView title="Approvals" eyebrow="HUMAN-IN-THE-LOOP" path="/api/approvals" description="Single-use grants cryptographically bound to exact action arguments and expiration." columns={[["approval_id", "Approval"], ["action", "Action"], ["requester_id", "Requester"], ["status", "Status"], ["expires_at", "Expires"]]} />; }
