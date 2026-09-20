"""Correct FortiOS and Junos remediation rule bindings."""

from collections.abc import Sequence
from uuid import UUID

from alembic import op
import sqlalchemy as sa


revision = "20260920_0021"
down_revision: str | Sequence[str] | None = "20260909_0020"
branch_labels = depends_on = None

FORTIOS_PROCEDURE_ID = "20000000-0000-0000-0000-000000000003"
JUNOS_PROCEDURE_ID = "20000000-0000-0000-0000-000000000005"
GENERATED_TELNET_RULE_ID = "management.telnet.disabled"
LEGACY_TELNET_RULE_ID = "management.remote.telnet.enabled"


def _set_rule_id(rule_id: str) -> None:
    op.execute(sa.text("""
        UPDATE remediation_procedures
        SET rule_id = :rule_id
        WHERE procedure_id IN (:fortios_id, :junos_id)
    """).bindparams(
        sa.bindparam("rule_id", value=rule_id, type_=sa.String()),
        sa.bindparam("fortios_id", value=UUID(FORTIOS_PROCEDURE_ID), type_=sa.Uuid()),
        sa.bindparam("junos_id", value=UUID(JUNOS_PROCEDURE_ID), type_=sa.Uuid()),
    ))


def upgrade() -> None:
    op.execute(
        "ALTER TABLE remediation_procedures "
        "DISABLE TRIGGER trg_remediation_published_immutable"
    )
    _set_rule_id(GENERATED_TELNET_RULE_ID)
    op.execute(
        "ALTER TABLE remediation_procedures "
        "ENABLE TRIGGER trg_remediation_published_immutable"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE remediation_procedures "
        "DISABLE TRIGGER trg_remediation_published_immutable"
    )
    _set_rule_id(LEGACY_TELNET_RULE_ID)
    op.execute(
        "ALTER TABLE remediation_procedures "
        "ENABLE TRIGGER trg_remediation_published_immutable"
    )
