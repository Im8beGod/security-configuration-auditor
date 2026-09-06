from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.auth.schemas import AuthUser, LoginRequest
from app.auth.service import authenticate_user
from app.core.config import Settings, get_settings
from app.core.security import create_access_token
from app.db.models import User
from app.db.session import get_db


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=AuthUser)
def login(
    credentials: LoginRequest,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthUser:
    user = authenticate_user(db, credentials.email, credentials.password.get_secret_value())
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    response.set_cookie(
        key=settings.auth_cookie_name,
        value=create_access_token(user.user_id, settings),
        max_age=settings.jwt_access_token_expire_minutes * 60,
        path=settings.auth_cookie_path,
        secure=settings.auth_cookie_secure,
        httponly=True,
        samesite=settings.auth_cookie_samesite,
    )
    response.headers["Cache-Control"] = "no-store"
    return AuthUser.model_validate(user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(settings: Annotated[Settings, Depends(get_settings)]) -> Response:
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(
        key=settings.auth_cookie_name,
        path=settings.auth_cookie_path,
        secure=settings.auth_cookie_secure,
        httponly=True,
        samesite=settings.auth_cookie_samesite,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/me", response_model=AuthUser)
def me(
    response: Response,
    user: Annotated[User, Depends(get_current_user)],
) -> AuthUser:
    response.headers["Cache-Control"] = "no-store"
    return AuthUser.model_validate(user)
