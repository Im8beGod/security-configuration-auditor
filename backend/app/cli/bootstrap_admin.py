import argparse
import getpass
import warnings
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.security import hash_password
from app.db.models import Organization, User, UserRole
from app.db.session import get_session_factory


class BootstrapConflict(ValueError):
    """Bootstrap never modifies an existing identity."""


def bootstrap_admin(
    factory: sessionmaker[Session],
    organization_name: str,
    organization_slug: str,
    email: str,
    password: str,
) -> tuple[UUID, UUID]:
    # Reuse persistence normalization before duplicate checks.
    organization = Organization(name=organization_name, slug=organization_slug)
    if len(organization.name) > 200 or len(organization.slug) > 100:
        raise ValueError("Organization name or slug exceeds its supported length")
    normalized_email = email.strip().lower()
    if not normalized_email or len(normalized_email) > 320:
        raise ValueError("Email must contain 1 to 320 characters")
    try:
        with factory.begin() as db:
            if db.scalar(select(User.user_id).where(User.email == normalized_email)):
                raise BootstrapConflict("Email already exists")
            if db.scalar(
                select(Organization.organization_id)
                .where(Organization.slug == organization.slug)
            ):
                raise BootstrapConflict("Organization slug already exists")
            user = User(
                organization=organization,
                email=normalized_email,
                password_hash=hash_password(password),
                role=UserRole.ADMIN,
            )
            db.add_all([organization, user])
            db.flush()
            result = organization.organization_id, user.user_id
        return result
    except IntegrityError:
        # Handle concurrent duplicate creation without SQL/parameter disclosure.
        raise BootstrapConflict("Email or organization slug already exists") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create one organization and initial admin")
    parser.add_argument("--organization-name", required=True)
    parser.add_argument("--organization-slug", required=True)
    parser.add_argument("--email", required=True)
    args = parser.parse_args(argv)
    try:
        # Fail rather than falling back to echoed input when no safe terminal exists.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Admin password: ")
            confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            raise ValueError("Passwords do not match")
        organization_id, user_id = bootstrap_admin(
            get_session_factory(),
            args.organization_name,
            args.organization_slug,
            args.email,
            password,
        )
    except (getpass.GetPassWarning, EOFError, KeyboardInterrupt):
        print("Bootstrap cancelled; use a terminal that supports hidden password entry.")
        return 1
    except (BootstrapConflict, ValueError):
        print("Bootstrap failed: check identity values, password input, and duplicate email/slug.")
        return 1
    except SQLAlchemyError:
        print("Bootstrap failed: database operation unsuccessful; no identity was committed.")
        return 1
    print(f"Created organization {organization_id} and admin {user_id}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
