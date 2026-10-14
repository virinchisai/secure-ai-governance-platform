from __future__ import annotations

from dataclasses import dataclass

from .agent import SecureAgent
from .ai import MockAIProvider, OllamaProvider
from .approvals import ApprovalService
from .audit import AuditSink, InMemoryAuditSink
from .cache import SemanticCache
from .classification import DataClassifier
from .config import Settings
from .connectors import GraphProvider, LocalGraphSimulator, MicrosoftGraphProvider, SafeDatabase
from .demo import demo_documents, demo_users
from .dlp import DLPEngine
from .identity import LocalIdentityProvider, TokenService
from .injection import PromptInjectionDetector
from .rbac import RBACAuthorizer
from .risk import InsiderRiskEngine


@dataclass
class Runtime:
    identity: LocalIdentityProvider
    tokens: TokenService
    graph: GraphProvider
    classifier: DataClassifier
    dlp: DLPEngine
    approvals: ApprovalService
    audit: AuditSink
    risk: InsiderRiskEngine
    authorizer: RBACAuthorizer
    safe_database: SafeDatabase
    cache: SemanticCache
    agent: SecureAgent


def build_runtime(settings: Settings, *, audit: AuditSink | None = None) -> Runtime:
    graph: GraphProvider
    if settings.graph_provider == "microsoft":
        graph = MicrosoftGraphProvider()
    else:
        graph = LocalGraphSimulator(demo_documents())
    ai = (
        OllamaProvider(settings.ollama_base_url, settings.ollama_model)
        if settings.ai_provider == "ollama"
        else MockAIProvider()
    )
    actual_audit = audit or InMemoryAuditSink()
    classifier = DataClassifier()
    dlp = DLPEngine()
    approvals = ApprovalService(settings.jwt_secret.encode(), settings.approval_ttl_minutes)
    risk = InsiderRiskEngine()
    authorizer = RBACAuthorizer()
    cache = SemanticCache(settings.cache_ttl_seconds)
    agent = SecureAgent(
        graph=graph,
        ai=ai,
        classifier=classifier,
        dlp=dlp,
        injection=PromptInjectionDetector(),
        authorizer=authorizer,
        approvals=approvals,
        audit=actual_audit,
        risk=risk,
        cache=cache,
    )
    return Runtime(
        identity=LocalIdentityProvider(demo_users()),
        tokens=TokenService(settings.jwt_secret, settings.jwt_issuer, settings.jwt_ttl_minutes),
        graph=graph,
        classifier=classifier,
        dlp=dlp,
        approvals=approvals,
        audit=actual_audit,
        risk=risk,
        authorizer=authorizer,
        safe_database=SafeDatabase(),
        cache=cache,
        agent=agent,
    )
