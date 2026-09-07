from uuid import UUID
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.db.models import Report

def add(db: Session, report: Report) -> None: db.add(report)
def by_id(db: Session, report_id: UUID, organization_id: UUID) -> Report | None:
    return db.scalar(select(Report).where(Report.report_id == report_id, Report.organization_id == organization_id))
def by_id_for_update(db: Session, report_id: UUID) -> Report | None:
    return db.scalar(select(Report).where(Report.report_id == report_id).with_for_update())
