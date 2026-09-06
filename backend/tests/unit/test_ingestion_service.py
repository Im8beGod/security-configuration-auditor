from unittest.mock import Mock
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.ingestion.errors import IngestionInfrastructureError
from app.ingestion.service import ingest_artifact


def test_database_failure_compensates_stored_bytes():
    organization_id, user_id = uuid4(), uuid4()
    user = Mock(organization_id=organization_id, user_id=user_id)
    db = Mock()
    db.commit.side_effect = SQLAlchemyError("private database detail")
    storage = Mock()
    storage.write.return_value = (
        f"organizations/{organization_id}/artifacts/{uuid4()}"
    )

    with pytest.raises(IngestionInfrastructureError) as exc_info:
        ingest_artifact(db, storage, user, b"hostname edge\n", "edge.cfg", "text/plain")

    assert exc_info.value.code == "persistence_failed"
    assert "private" not in exc_info.value.message
    db.rollback.assert_called_once_with()
    storage.delete.assert_called_once_with(storage.write.return_value)
