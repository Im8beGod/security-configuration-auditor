from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Artifact, Audit, EffectiveState, Finding, SecurityFact, User
from app.ingestion.storage import ArtifactStorage, ArtifactStorageError

MAX_EXCERPT_BYTES = 64 * 1024
MAX_EXCERPT_LINES = 200


class FindingNotFoundError(ValueError): pass
class FindingProvenanceError(ValueError): pass


def _finding(db: Session, user: User, finding_id: UUID) -> Finding:
    finding = db.scalar(select(Finding).join(Audit, Audit.audit_id == Finding.audit_id).where(
        Finding.finding_id == finding_id, Audit.organization_id == user.organization_id
    ))
    if finding is None: raise FindingNotFoundError("Finding not found")
    return finding

def list_findings(db: Session, user: User, audit_id: UUID, *, verdict=None, severity=None, security_domain=None, rule_id=None, framework=None, offset=0, limit=50):
    audit = db.scalar(select(Audit).where(Audit.audit_id == audit_id, Audit.organization_id == user.organization_id))
    if audit is None: raise FindingNotFoundError("Audit not found")
    statement = select(Finding).where(Finding.audit_id == audit_id)
    for column, value in ((Finding.verdict, verdict), (Finding.severity, severity), (Finding.security_domain, security_domain), (Finding.rule_id, rule_id)):
        if value is not None: statement = statement.where(column == value)
    if framework: statement = statement.where(Finding.framework_references.contains([{"framework": framework}]))
    total = db.scalar(select(func.count()).select_from(statement.subquery())) or 0
    return list(db.scalars(statement.order_by(Finding.created_at, Finding.finding_id).offset(offset).limit(limit))), total

def get_finding(db: Session, user: User, finding_id: UUID) -> Finding: return _finding(db, user, finding_id)

def _excerpt(storage, artifact, ref):
    try:
        data = storage.read_prefix(artifact.storage_reference, MAX_EXCERPT_BYTES)
        text = data.decode(artifact.encoding or "utf-8")
    except (ArtifactStorageError, UnicodeError): return None, False, False
    lines = text.splitlines()
    start, end = ref.get("start_line"), ref.get("end_line")
    if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start: return None, False, True
    selected = lines[start - 1:min(end, start - 1 + MAX_EXCERPT_LINES)]
    return "\n".join(selected), end - start + 1 > MAX_EXCERPT_LINES or len(data) == MAX_EXCERPT_BYTES, True

def resolve_evidence(db: Session, user: User, finding_id: UUID, storage: ArtifactStorage):
    finding = _finding(db, user, finding_id)
    audit = db.scalar(select(Audit).where(Audit.audit_id == finding.audit_id, Audit.organization_id == user.organization_id))
    states=[]
    for state_id in finding.effective_state_refs:
        state = db.get(EffectiveState, UUID(state_id))
        if state is None or state.audit_id != finding.audit_id or state.device_id != finding.device_id: raise FindingProvenanceError("Finding provenance is invalid")
        facts=[]
        for fact_id in state.source_fact_ids:
            fact=db.get(SecurityFact, UUID(fact_id))
            if fact is None or fact.audit_id != audit.audit_id or fact.device_id != finding.device_id or fact.snapshot_id != audit.snapshot_id: raise FindingProvenanceError("Finding provenance is invalid")
            artifacts=[]
            for ref in fact.evidence_refs:
                artifact=db.scalar(select(Artifact).where(Artifact.artifact_id == UUID(ref["artifact_id"]), Artifact.organization_id == user.organization_id, Artifact.snapshot_id == audit.snapshot_id))
                if artifact is None: raise FindingProvenanceError("Finding provenance is invalid")
                excerpt,truncated,available=_excerpt(storage,artifact,ref)
                artifacts.append({"artifact_id":artifact.artifact_id,"original_filename":artifact.original_filename,"evidence_type":artifact.evidence_type.value,"content_family":artifact.content_family.value,"sha256":artifact.sha256,"excerpt":excerpt,"truncated":truncated,"available":available})
            facts.append({"fact_id":fact.fact_id,"field_id":fact.field_id,"value":fact.value,"scope":fact.scope,"state":fact.state.value,"extraction_method":fact.extraction_method.value,"mapping_id":fact.mapping_id,"mapping_version_id":fact.mapping_version_id,"knowledge_pack_version_id":fact.knowledge_pack_version_id,"validation_status":fact.validation_status.value,"interpretation_confidence":fact.interpretation_confidence.value,"evidence_refs":fact.evidence_refs,"artifacts":artifacts})
        states.append({"effective_state_id":state.effective_state_id,"field_id":state.field_id,"scope":state.scope,"effective_value":state.effective_value,"resolution_status":state.resolution_status,"resolution_trace":state.resolution_trace,"inherited_from":state.inherited_from,"default_reference":state.default_reference,"referenced_objects":state.referenced_objects,"precedence_applied":state.precedence_applied,"unresolved_reason":state.unresolved_reason,"facts":facts})
    return {"finding_id":finding.finding_id,"states":states,"status":"resolved" if states else "no_evidence"}
