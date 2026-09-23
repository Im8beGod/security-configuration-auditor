"""Protect published runtime rule versions from direct mutation."""

from alembic import op


revision = "20260924_0027"
down_revision = "20260923_0026"
branch_labels = depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE FUNCTION prevent_runtime_rule_mutation() RETURNS trigger AS $$
        BEGIN
          IF OLD.status IN ('published', 'retired') THEN
            RAISE EXCEPTION 'published runtime rule versions are immutable';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_runtime_rule_versions_immutable
        BEFORE UPDATE OR DELETE ON runtime_rule_versions
        FOR EACH ROW EXECUTE FUNCTION prevent_runtime_rule_mutation()
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS trg_runtime_rule_versions_immutable ON runtime_rule_versions"
    )
    op.execute("DROP FUNCTION IF EXISTS prevent_runtime_rule_mutation()")
