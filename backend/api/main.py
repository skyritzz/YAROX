from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from core.health import check_health, probe_postgres
from websocket.investigation_ws import investigation_event_bridge
from core.config import settings, validate_production_settings
from core.events import event_bus
from consumers.db_writer import register_consumers
from consumers.detection_consumer import register_detection_consumers
from database.session import engine, AsyncSessionLocal
from models.base import Base
import models.user
import models.event
import models.replay
import models.investigation
import models.mitre
import models.entity
from core.auth import seed_initial_users
from memory.service import memory_service

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Autonomous Multi-Agent Security Investigation Platform API",
)

@app.on_event("startup")
async def startup_event():
    # Production secret safety check: Prevents booting with insecure dev placeholders in production
    validate_production_settings()

    # The schema is owned by migrations (scripts/migrate.py), never created implicitly here.
    # Refuse to serve against a schema that does not match the migration head.
    status, detail = await probe_postgres()
    if status != "up":
        raise RuntimeError(f"Database schema not ready: {detail}. Run `python -m scripts.migrate`.")

    # Pre-seed initial default accounts for ADMIN, ANALYST, and VIEWER
    async with AsyncSessionLocal() as session:
        await seed_initial_users(session)
        
    event_bus.start()
    register_consumers()
    register_detection_consumers()

    # Deliver investigation events published by any process to this process's WebSocket clients
    await investigation_event_bridge.start()
    
    # Initialize Authoritative Investigation Memory Service
    await memory_service.initialize()

@app.on_event("shutdown")
async def shutdown_event():
    event_bus.stop()
    await investigation_event_bridge.stop()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

from api.auth import router as auth_router
from api.ingest import router as ingest_router
from api.replay import router as replay_router
from api.events import router as events_router
from api.dashboard import router as dashboard_router
from api.investigations import router as investigations_router
from websocket.investigation_ws import router as ws_router
from api.memory import router as memory_router

app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(ingest_router, prefix="/events/ingest", tags=["Live Telemetry Ingestion"])
app.include_router(replay_router, prefix="/replay", tags=["Replay Engine"])
app.include_router(events_router, prefix="/events", tags=["Events"])
app.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
app.include_router(investigations_router, prefix="/investigations", tags=["Investigations"])
app.include_router(ws_router, prefix="/ws/investigations", tags=["WebSockets"])
app.include_router(memory_router, prefix="/memory", tags=["Memory"])

@app.get("/health", tags=["System"])
async def health_check():
    """
    Live component health. Every status is produced by a probe at request time
    (see core/health.py). Returns HTTP 503 when a required component is down.
    """
    report = await check_health()
    body = {
        "status": report["status"],
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "components": report["components"],
    }
    return JSONResponse(status_code=503 if report["status"] == "down" else 200, content=body)
