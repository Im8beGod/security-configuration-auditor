from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth.service import resolve_current_user
from app.core.config import Settings, get_settings
from app.core.security import InvalidAccessToken, decode_access_token
from app.db.models import User, UserRole
from app.db.session import get_db


def get_current_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> User:
    """Future tenant queries must derive organization_id from this identity."""
    token = request.cookies.get(settings.auth_cookie_name)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    try:
        user_id = decode_access_token(token, settings)
    except InvalidAccessToken:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Authentication required"
        ) from None
    user = resolve_current_user(db, user_id)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    return user


def require_roles(*roles: UserRole) -> Callable[..., User]:
    allowed = frozenset(roles)
    if not allowed or any(not isinstance(role, UserRole) for role in allowed):
        raise ValueError("At least one explicit UserRole is required")

    def check_role(user: Annotated[User, Depends(get_current_user)]) -> User:
        if user.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user

    return check_role
