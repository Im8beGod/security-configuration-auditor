from typing import Annotated
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.auth.dependencies import get_current_user
from app.dashboard.schemas import DashboardResponse
from app.dashboard.service import get_dashboard
from app.db.models import User
from app.db.session import get_db

router=APIRouter(tags=["dashboard"])

@router.get("/dashboard",response_model=DashboardResponse)
def dashboard(user:Annotated[User,Depends(get_current_user)],db:Annotated[Session,Depends(get_db)]):
    return get_dashboard(db,user)
