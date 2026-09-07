"""Add immutable, versioned remediation procedures."""
from collections.abc import Sequence
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "20260907_0008"
down_revision: str | Sequence[str] | None = "20260907_0007"
branch_labels = depends_on = None

def upgrade() -> None:
    op.create_table("remediation_procedures", sa.Column("procedure_id", sa.Uuid(), primary_key=True), sa.Column("procedure_key", sa.String(255), nullable=False), sa.Column("version", sa.Integer(), nullable=False), sa.Column("previous_procedure_id", sa.Uuid(), sa.ForeignKey("remediation_procedures.procedure_id", ondelete="RESTRICT")), sa.Column("rule_id", sa.String(255), nullable=False), sa.Column("title", sa.String(255), nullable=False), sa.Column("security_objective", sa.String(1024), nullable=False), sa.Column("description", sa.String(2048), nullable=False), sa.Column("status", sa.String(16), nullable=False), *[sa.Column(name, postgresql.JSONB(), nullable=False) for name in ("profile_applicability", "prerequisites", "safety_warnings", "required_parameters", "configuration_context", "ordered_steps", "verification_steps", "rollback_steps", "validation_results", "source_references")], sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("reviewed_at", sa.DateTime(timezone=True)), sa.Column("validated_at", sa.DateTime(timezone=True)), sa.Column("published_at", sa.DateTime(timezone=True)), sa.Column("schema_version", sa.String(32), nullable=False), sa.CheckConstraint("version > 0", name="ck_remediation_procedures_version_positive"))
    op.create_unique_constraint("uq_remediation_procedures_procedure_key", "remediation_procedures", ["procedure_key", "version"])
    for column in ("rule_id", "procedure_key", "status"): op.create_index(f"ix_remediation_procedures_{column}", "remediation_procedures", [column])
def downgrade() -> None:
    op.drop_table("remediation_procedures")
