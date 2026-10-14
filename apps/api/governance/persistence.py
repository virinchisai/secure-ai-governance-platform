from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .audit import AuditSink
from .domain import AuditEvent


class Base(DeclarativeBase):
    pass


class AuditEventRow(Base):
    __tablename__ = "audit_events"

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str] = mapped_column(String(64), index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(128))
    tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource: Mapped[str | None] = mapped_column(String(256), nullable=True)
    classification: Mapped[str | None] = mapped_column(String(32), nullable=True)
    policy_decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    policy_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approval_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    result: Mapped[str] = mapped_column(String(64))
    risk_score: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text)
    event_type: Mapped[str] = mapped_column(String(64), index=True)


class DatabaseAuditSink(AuditSink):
    def __init__(self, database_url: str) -> None:
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        self.engine = create_engine(database_url, connect_args=connect_args)
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(self.engine)

    def emit(self, event: AuditEvent) -> None:
        data = event.model_dump(mode="json")
        row = AuditEventRow(**data)
        with self.sessions.begin() as session:
            session.add(row)

    def list_events(self, workspace_id: str) -> list[AuditEvent]:
        with self.sessions() as session:
            rows = (
                session.query(AuditEventRow)
                .filter(AuditEventRow.workspace_id == workspace_id)
                .order_by(AuditEventRow.timestamp.desc())
                .all()
            )
            return [
                AuditEvent.model_validate(
                    {
                        column.name: getattr(row, column.name)
                        for column in AuditEventRow.__table__.columns
                    }
                )
                for row in rows
            ]
