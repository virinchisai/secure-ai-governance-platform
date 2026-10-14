import { ResourceView } from "@/components/ResourceView";

export default function DocumentsPage() { return <ResourceView title="Documents" eyebrow="WORKSPACE INVENTORY" path="/api/documents" description="Tenant-scoped synthetic files exposed by LocalGraphSimulator." columns={[["name", "Document"], ["document_id", "Resource ID"], ["workspace_id", "Workspace"]]} />; }
