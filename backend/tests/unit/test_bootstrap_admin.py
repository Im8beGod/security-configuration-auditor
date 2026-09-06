from importlib import import_module
from unittest.mock import Mock

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.cli.bootstrap_admin import BootstrapConflict, bootstrap_admin
from app.core.security import verify_password
from app.db.models import Organization, User, UserRole


def counts(factory):
    with factory() as db:
        return tuple(db.scalar(select(func.count()).select_from(model)) for model in (
            Organization, User
        ))


def test_bootstrap_hashes_and_duplicate_failures_are_atomic(identity_factory):
    password = "bootstrap-test-password"
    org_id, user_id = bootstrap_admin(
        identity_factory, " Test Organization ", " Test Org ", " ADMIN@EXAMPLE.INVALID ", password
    )
    with identity_factory() as db:
        user = db.get(User, user_id)
        assert db.get(Organization, org_id).slug == "test-org"
        assert user.email == "admin@example.invalid"
        assert user.role is UserRole.ADMIN
        assert user.password_hash.startswith("$argon2id$")
        assert verify_password(password, user.password_hash)
    with pytest.raises(BootstrapConflict, match="Email already exists"):
        bootstrap_admin(
            identity_factory, "New", "new", "admin@example.invalid", "different"
        )
    with pytest.raises(BootstrapConflict, match="slug already exists"):
        bootstrap_admin(
            identity_factory, "New", "test-org", "other@example.invalid", "different"
        )
    assert counts(identity_factory) == (1, 1)
    with identity_factory() as db:
        assert verify_password(password, db.get(User, user_id).password_hash)


def test_bootstrap_invalid_password_leaves_no_partial_records(identity_factory):
    with pytest.raises(ValueError):
        bootstrap_admin(identity_factory, "Test", "test", "a@example.invalid", "x" * 1025)
    assert counts(identity_factory) == (0, 0)


def test_bootstrap_transaction_rolls_back_after_flush_failure(identity_factory, monkeypatch):
    session_class = identity_factory.class_
    original_flush = session_class.flush

    def failing_flush(session, *args, **kwargs):
        original_flush(session, *args, **kwargs)
        raise IntegrityError("test statement", {}, Exception("simulated conflict"))

    with monkeypatch.context() as patch:
        patch.setattr(session_class, "flush", failing_flush)
        with pytest.raises(BootstrapConflict):
            bootstrap_admin(identity_factory, "Test", "test", "a@example.invalid", "test-password")
    assert counts(identity_factory) == (0, 0)


def test_cli_prompts_without_password_argument(identity_factory, monkeypatch, capsys):
    module = import_module("app.cli.bootstrap_admin")
    monkeypatch.setattr(module, "get_session_factory", lambda: identity_factory)
    prompt = Mock(side_effect=["interactive-test-password", "interactive-test-password"])
    monkeypatch.setattr(module.getpass, "getpass", prompt)
    result = module.main([
        "--organization-name", "CLI Org", "--organization-slug", "cli-org",
        "--email", "cli@example.invalid",
    ])
    assert result == 0
    assert prompt.call_count == 2
    output = capsys.readouterr().out
    assert "interactive-test-password" not in output
    assert "$argon2" not in output
    assert counts(identity_factory) == (1, 1)


def test_cli_mismatch_does_not_create_identity(identity_factory, monkeypatch, capsys):
    module = import_module("app.cli.bootstrap_admin")
    monkeypatch.setattr(module, "get_session_factory", lambda: identity_factory)
    monkeypatch.setattr(module.getpass, "getpass", Mock(side_effect=["one", "two"]))
    assert module.main([
        "--organization-name", "CLI Org", "--organization-slug", "cli-org",
        "--email", "cli@example.invalid",
    ]) == 1
    assert counts(identity_factory) == (0, 0)
