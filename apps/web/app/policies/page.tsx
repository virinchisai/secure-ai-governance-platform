import { ResourceView } from "@/components/ResourceView";

export default function PoliciesPage() { return <ResourceView title="DLP Policies" eyebrow="DETERMINISTIC ENFORCEMENT" path="/api/policies" description="Ordered rules execute in application code. Model output cannot override these decisions." columns={[["policy_id", "Policy"], ["effect", "Effect"], ["description", "Enforcement"]]} />; }
