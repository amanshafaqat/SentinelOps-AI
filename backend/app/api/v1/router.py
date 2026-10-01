"""API Version 1 Router Aggregator."""

from fastapi import APIRouter
from backend.app.api.v1.endpoints.health import router as health_router
from backend.app.api.v1.endpoints.system import router as system_router
from backend.app.api.v1.endpoints.events import router as events_router
from backend.app.api.v1.endpoints.detection import router as detection_router
from backend.app.api.v1.endpoints.alerts import router as alerts_router
from backend.app.api.v1.endpoints.incidents import router as incidents_router
from backend.app.api.v1.endpoints.investigation import router as investigation_router
from backend.app.api.v1.endpoints.audit import router as audit_router

api_v1_router = APIRouter()
api_v1_router.include_router(health_router)
api_v1_router.include_router(system_router)
api_v1_router.include_router(events_router)
api_v1_router.include_router(detection_router, prefix="/detection", tags=["detection"])
api_v1_router.include_router(alerts_router, prefix="/alerts", tags=["alerts"])
api_v1_router.include_router(incidents_router, prefix="/incidents", tags=["incidents"])
api_v1_router.include_router(investigation_router)
api_v1_router.include_router(audit_router)

