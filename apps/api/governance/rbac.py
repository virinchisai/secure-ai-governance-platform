from __future__ import annotations

from .domain import Role, UserContext


class AuthorizationError(PermissionError):
    pass


TOOL_ROLES: dict[str, frozenset[Role]] = {
    "search_documents": frozenset(Role),
    "get_document": frozenset(Role),
    "list_files": frozenset(Role),
    "query_safe_database": frozenset({Role.ANALYST, Role.SECURITY_ADMIN, Role.COMPLIANCE_ADMIN}),
    "draft_email": frozenset(Role),
    "send_email": frozenset({Role.ANALYST, Role.SECURITY_ADMIN, Role.COMPLIANCE_ADMIN}),
    "classify_document": frozenset(Role),
    "check_dlp_policy": frozenset(Role),
}


class RBACAuthorizer:
    def authorize_tool(self, context: UserContext, tool: str) -> None:
        allowed_roles = TOOL_ROLES.get(tool)
        if allowed_roles is None:
            raise AuthorizationError(f"Unknown tool denied: {tool}")
        if not context.roles.intersection(allowed_roles):
            raise AuthorizationError(f"Role is not authorized for tool: {tool}")

    @staticmethod
    def authorize_workspace(context: UserContext, resource_workspace_id: str) -> None:
        if context.workspace_id != resource_workspace_id:
            raise AuthorizationError("Cross-tenant resource access denied")
