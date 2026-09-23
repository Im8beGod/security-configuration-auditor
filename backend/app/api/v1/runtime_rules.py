from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.compliance.runtime_rules import RuntimeRuleError, publish_runtime_rule, validate_runtime_rule
from app.db.models import User, UserRole
from app.db.session import get_db


router = APIRouter(prefix="/runtime-rules", tags=["runtime-rules"])
Admin = Annotated[User, Depends(require_roles(UserRole.ADMIN))]


def _response(row):
    return {"runtime_rule_version_id": str(row.runtime_rule_version_id), "rule_id": row.rule_id, "version": row.version, "content_digest": row.content_digest, "status": row.status}


@router.post("/preview")
def preview(payload: dict[str, Any], user: Admin, db: Annotated[Session, Depends(get_db)]):
    try:
        rule = validate_runtime_rule(db, user.organization_id, payload)
    except RuntimeRuleError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"rule_id": rule.rule_id, "profile_version_ids": list(rule.applicability["profile_version_ids"]), "canonical_field": rule.required_effective_states[0], "operator": rule.condition["operator"]}


@router.post("/publish", status_code=201)
def publish(payload: dict[str, Any], user: Admin, db: Annotated[Session, Depends(get_db)]):
    try:
        row = publish_runtime_rule(db, user.organization_id, payload)
        db.commit(); db.refresh(row)
    except RuntimeRuleError as exc:
        db.rollback()
        raise HTTPException(422, str(exc)) from exc
    return _response(row)
