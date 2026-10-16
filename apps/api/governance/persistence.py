from __future__ import annotations

from datetime import datetime
from typing import Any, cast

from sqlalchemy import DateTime, Integer, String, Text, create_engine, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .approvals import ApprovalStore
from .audit import AuditSink, logger
from .domain import ApprovalRecord, ApprovalStatus, AuditEvent


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


class ApprovalRecordRow(Base):
    __tablename__ = "approval_records"

    approval_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), index=True)
    requester_id: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(128))
    arguments_digest: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)


def build_session_factory(database_url: str) -> sessionmaker[Session]:
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, connect_args=connect_args)
    Base.metadata.create_all(engine)
    return sessionmaker(engine, expire_on_commit=False)


class DatabaseAuditSink(AuditSink):
    def __init__(self, database_url: str, sessions: sessionmaker[Session] | None = None) -> None:
        self.sessions = sessions or build_session_factory(database_url)

    def emit(self, event: AuditEvent) -> None:
        data = event.model_dump(mode="python")
        row = AuditEventRow(**data)
        with self.sessions.begin() as session:
            session.add(row)
        logger.info("security_event", **event.model_dump(mode="json"))

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


class DatabaseApprovalStore(ApprovalStore):
    def __init__(self, database_url: str, sessions: sessionmaker[Session] | None = None) -> None:
        self.sessions = sessions or build_session_factory(database_url)

    @staticmethod
    def _record(row: ApprovalRecordRow) -> ApprovalRecord:
        return ApprovalRecord.model_validate(
            {
                column.name: getattr(row, column.name)
                for column in ApprovalRecordRow.__table__.columns
                if column.name != "version"
            }
        )

    def put(self, record: ApprovalRecord) -> None:
        with self.sessions.begin() as session:
            session.add(ApprovalRecordRow(**record.model_dump(mode="python")))

    def get(self, approval_id: str) -> ApprovalRecord | None:
        with self.sessions() as session:
            row = session.get(ApprovalRecordRow, approval_id)
            return self._record(row) if row else None

    def replace(self, record: ApprovalRecord, expected: ApprovalStatus) -> bool:
        values = record.model_dump(mode="python")
        values.pop("approval_id")
        with self.sessions.begin() as session:
            result = cast(
                CursorResult[Any],
                session.execute(
                    update(ApprovalRecordRow)
                    .where(
                        ApprovalRecordRow.approval_id == record.approval_id,
                        ApprovalRecordRow.status == expected.value,
                    )
                    .values(**values, version=ApprovalRecordRow.version + 1)
                ),
            )
            return bool(result.rowcount == 1)

    def list_for_workspace(self, workspace_id: str) -> list[ApprovalRecord]:
        with self.sessions() as session:
            rows = session.scalars(
                select(ApprovalRecordRow)
                .where(ApprovalRecordRow.workspace_id == workspace_id)
                .order_by(ApprovalRecordRow.created_at.desc())
            ).all()
            return [self._record(row) for row in rows]
