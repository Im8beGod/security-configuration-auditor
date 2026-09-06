from datetime import datetime, timedelta, timezone
from functools import lru_cache
from secrets import token_urlsafe
from uuid import UUID

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.core.config import Settings


MAX_PASSWORD_LENGTH = 1024
_password_hasher = PasswordHasher()


class InvalidAccessToken(ValueError):
    """An access token could not be validated."""


def hash_password(password: str) -> str:
    """Hash the complete password with the library's default Argon2id profile."""
    if not 1 <= len(password) <= MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must contain 1 to {MAX_PASSWORD_LENGTH} characters")
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    if not 1 <= len(password) <= MAX_PASSWORD_LENGTH:
        return False
    try:
        return _password_hasher.verify(password_hash, password)
    except (InvalidHashError, VerificationError, UnicodeError):
        return False


@lru_cache(maxsize=1)
def dummy_password_hash() -> str:
    """Spend Argon2 verification work even when an email has no account."""
    return hash_password(token_urlsafe(32))


def create_access_token(user_id: UUID, settings: Settings) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": str(user_id),
            "iat": now,
            "exp": now + timedelta(minutes=settings.jwt_access_token_expire_minutes),
            "type": "access",
        },
        settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str, settings: Settings) -> UUID:
    """Validate required claims and return only the authenticated subject."""
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            options={"require": ["sub", "iat", "exp", "type"]},
        )
        if claims["type"] != "access" or not isinstance(claims["sub"], str):
            raise InvalidAccessToken("Invalid access token")
        if (
            type(claims["iat"]) is not int
            or type(claims["exp"]) is not int
            or claims["exp"] <= claims["iat"]
        ):
            raise InvalidAccessToken("Invalid access token")
        return UUID(claims["sub"])
    except (jwt.InvalidTokenError, ValueError, TypeError, OverflowError):
        raise InvalidAccessToken("Invalid access token") from None
