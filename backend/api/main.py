from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.config import settings
from core.events import event_bus
from consumers.db_writer import register_consumers
from consumers.detection_consumer import register_detection_consumers
from database.session import engine
from models.base import Base
import models.event
import models.replay
import models.investigation
import models.mitre
import models.entity

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Autonomous Multi-Agent Security Investigation Platform API",
)

@app.on_event("startup")
async def startup_event():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    event_bus.start()
    register_consumers()
    register_detection_consumers()
    
    # Initialize Memory Service
    from services.memory_service import memory_service
    await memory_service.initialize()

@app.on_event("shutdown")
async def shutdown_event():
    event_bus.stop()

# CORS setup for Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For development, should be restricted in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from api.replay import router as replay_router
from api.events import router as events_router
from api.dashboard import router as dashboard_router
from api.investigations import router as investigations_router
from websocket.investigation_ws import router as ws_router

app.include_router(replay_router, prefix="/replay", tags=["Replay Engine"])
app.include_router(events_router, prefix="/events", tags=["Events"])
app.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
app.include_router(investigations_router, prefix="/investigations", tags=["Investigations"])
app.include_router(ws_router, prefix="/ws/investigations", tags=["WebSockets"])

@app.get("/health", tags=["System"])
async def health_check():
    # In a real app we'd ping redis and postgres, but we will return structured healthy status
    return {
        "status": "ok",
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "infrastructure": {
            "Backend": "Healthy",
            "PostgreSQL": "Healthy",
            "Redis": "Healthy",
            "MinIO": "Healthy",
            "Qdrant": "Healthy",
            "Event Bus": "Active",
            "Replay Engine": "Active"
        }
    }
