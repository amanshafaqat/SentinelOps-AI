"""API Version 1 Router Aggregator."""

from fastapi import APIRouter
from backend.app.api.v1.endpoints.health import router as health_router
from backend.app.api.v1.endpoints.system import router as system_router
from backend.app.api.v1.endpoints.events import router as events_router

api_v1_router = APIRouter()
api_v1_router.include_router(health_router)
api_v1_router.include_router(system_router)
api_v1_router.include_router(events_router)
