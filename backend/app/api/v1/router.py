from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.artifacts import router as artifacts_router
from app.api.v1.audits import router as audits_router
from app.api.v1.devices import router as devices_router
from app.api.v1.jobs import router as jobs_router
from app.api.v1.snapshots import router as snapshots_router


router = APIRouter()
router.include_router(auth_router)
router.include_router(artifacts_router)
router.include_router(audits_router)
router.include_router(devices_router)
router.include_router(jobs_router)
router.include_router(snapshots_router)
