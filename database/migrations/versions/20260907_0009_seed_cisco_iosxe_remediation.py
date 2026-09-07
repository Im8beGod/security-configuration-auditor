"""Seed reviewed Cisco IOS XE 17 remediation procedures."""

from collections.abc import Sequence
from datetime import datetime, timezone
from uuid import UUID

from alembic import op
import sqlalchemy as sa


revision: str = "20260907_0009"
down_revision: str | Sequence[str] | None = "20260907_0008"
branch_labels = depends_on = None

TABLE = sa.table(
    "remediation_procedures",
    sa.column("procedure_id", sa.Uuid()), sa.column("procedure_key", sa.String()),
    sa.column("version", sa.Integer()), sa.column("previous_procedure_id", sa.Uuid()),
    sa.column("rule_id", sa.String()), sa.column("title", sa.String()),
    sa.column("security_objective", sa.String()), sa.column("description", sa.String()),
    sa.column("status", sa.String()), sa.column("profile_applicability", sa.JSON()),
    sa.column("prerequisites", sa.JSON()), sa.column("safety_warnings", sa.JSON()),
    sa.column("required_parameters", sa.JSON()), sa.column("configuration_context", sa.JSON()),
    sa.column("ordered_steps", sa.JSON()), sa.column("verification_steps", sa.JSON()),
    sa.column("rollback_steps", sa.JSON()), sa.column("validation_results", sa.JSON()),
    sa.column("source_references", sa.JSON()), sa.column("created_at", sa.DateTime(timezone=True)),
    sa.column("schema_version", sa.String()),
)
IDS = [UUID("10000000-0000-0000-0000-000000000001"), UUID("10000000-0000-0000-0000-000000000002"), UUID("10000000-0000-0000-0000-000000000003")]


def _row(identifier, key, rule, title, command, verification, rollback, parameters=None):
    return {
        "procedure_id": identifier, "procedure_key": key, "version": 1, "previous_procedure_id": None,
        "rule_id": rule, "title": title, "security_objective": title,
        "description": "Reviewed Cisco IOS XE 17.x recommendation.", "status": "published",
        "profile_applicability": {"profile_version_ids": ["cisco.ios_xe.17@1.0.0"]},
        "prerequisites": [{"text": "Use normal change control."}],
        "safety_warnings": ["Confirm an alternate administrative access path before applying changes."],
        "required_parameters": parameters or [], "configuration_context": [],
        "ordered_steps": [{"text": command}], "verification_steps": [{"text": value} for value in verification],
        "rollback_steps": [{"text": rollback}],
        "validation_results": [{"schema_validated": True, "template_placeholders_validated": True, "parameter_validation_tested": True, "profile_applicability_tested": True}],
        "source_references": [{"publisher": "Cisco", "title": "Cisco IOS XE 17.x configuration documentation"}],
        "created_at": datetime(2026, 9, 7, tzinfo=timezone.utc), "schema_version": "1.0.0",
    }


def upgrade():
    op.bulk_insert(TABLE, [
        _row(IDS[0], "cisco_iosxe_17.ssh.require_v2", "management.ssh.version_2", "Require SSH version 2", "ip ssh version 2", ["show ip ssh"], "Restore the exact pre-change SSH version configuration through normal change control."),
        _row(IDS[1], "cisco_iosxe_17.logging.configure_remote_host", "logging.remote.destination.configured", "Configure remote logging host", "logging host {syslog_hostname}", ["show logging"], "no logging host {syslog_hostname}", [{"name": "syslog_hostname", "label": "Syslog hostname", "type": "hostname", "required": True}]),
        _row(IDS[2], "cisco_iosxe_17.ntp.configure_server", "time.ntp.server.configured", "Configure NTP server", "ntp server {ntp_server}", ["show ntp associations", "show ntp status"], "no ntp server {ntp_server}", [{"name": "ntp_server", "label": "NTP server", "type": "ip_address", "required": True}]),
    ])


def downgrade():
    op.execute(sa.delete(TABLE).where(TABLE.c.procedure_id.in_(IDS)))
