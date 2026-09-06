import os
from pathlib import Path
import subprocess
import sys


def test_import_and_health_need_no_database_or_secrets():
    environment = {
        key: value for key, value in os.environ.items()
        if not key.upper().startswith(("POSTGRES_", "JWT_", "AUTH_COOKIE_"))
    }
    environment["API_PREFIX"] = "/api/v1"
    result = subprocess.run(
        [sys.executable, "-c", """
from unittest.mock import patch
from fastapi.testclient import TestClient

with patch('sqlalchemy.create_engine', side_effect=AssertionError('Unexpected DB setup')):
    from app.main import app
    with TestClient(app) as client:
        assert client.get('/health').json() == {'status': 'healthy'}
"""],
        cwd=Path(__file__).resolve().parents[2], env=environment,
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
