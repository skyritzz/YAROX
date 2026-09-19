import secrets
from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, Header, HTTPException, status, Depends, Request
from fastapi.security import APIKeyHeader

from core.config import settings
from core.events import event_bus
from core.rate_limiter import ingestion_rate_limiter
from core.auth import require_authenticated
from models.user import User
from schemas.ingest import IngestEventRequest, IngestEventResponse, IngestMetricsResponse
from plugins.parsers.generic import generic_parser

router = APIRouter()

# Observability metrics counters for live ingestion
class IngestionMetricsTracker:
    def __init__(self):
        self.events_received: int = 0
        self.events_accepted: int = 0
        self.events_rejected: int = 0
        self.rate_limit_rejections: int = 0
        self.auth_failures: int = 0
        self.last_event_timestamp: str = None

    def record_received(self):
        self.events_received += 1

    def record_accepted(self):
        self.events_accepted += 1
        self.last_event_timestamp = datetime.now(timezone.utc).isoformat()

    def record_rejected(self):
        self.events_rejected += 1

    def record_rate_limited(self):
        self.rate_limit_rejections += 1
        self.events_rejected += 1

    def record_auth_failure(self):
        self.auth_failures += 1
        self.events_rejected += 1

metrics_tracker = IngestionMetricsTracker()

# Dedicated API Key header dependency for machine-to-machine ingestion
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_ingestion_api_key(x_api_key: str = Depends(api_key_header), request: Request = None) -> str:
    """
    Validates machine-to-machine X-API-Key header using constant-time comparison.
    Logs audit events on failure without leaking key contents.
    """
    if not x_api_key:
        metrics_tracker.record_auth_failure()
        client_ip = request.client.host if request and request.client else "unknown"
        print(f"[SECURITY AUDIT] Telemetry ingestion rejected: Missing X-API-Key header from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required 'X-API-Key' authentication header."
        )

    # Constant-time comparison to prevent timing side-channel attacks
    is_valid = secrets.compare_digest(x_api_key.strip(), settings.INGESTION_API_KEY.strip())
    if not is_valid:
        metrics_tracker.record_auth_failure()
        client_ip = request.client.host if request and request.client else "unknown"
        print(f"[SECURITY AUDIT] Telemetry ingestion rejected: Invalid X-API-Key from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 'X-API-Key' authentication header."
        )

    return x_api_key

@router.post("", response_model=IngestEventResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(
    request: IngestEventRequest,
    raw_request: Request,
    api_key: str = Depends(verify_ingestion_api_key)
):
    """
    Live Telemetry Ingestion Gateway:
    1. Authenticates machine sender via X-API-Key
    2. Enforces fail-closed Redis rate limiting
    3. Validates and normalizes raw telemetry payload
    4. Publishes to the central 'EventNormalized' topic for downstream DB & Detection processing
    """
    metrics_tracker.record_received()

    # 1. Rate limiting check (using client IP or API key hash)
    client_ip = raw_request.client.host if raw_request.client else "default_shipper"
    is_allowed, retry_after = await ingestion_rate_limiter.check_rate_limit(f"{client_ip}:{api_key[:8]}")
    if not is_allowed:
        metrics_tracker.record_rate_limited()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Telemetry ingestion rate limit exceeded (Max {settings.RATE_LIMIT_INGEST_PER_MINUTE} events/min). Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

    try:
        # 2. Normalize event into standard YAROX Event ORM representation.
        # The canonical event contract (schemas.canonical_event) assigns event_id
        # itself, once, at normalization time — reuse it rather than minting a
        # second, different UUID here (Phase 11 fix: these previously diverged).
        normalized_dict = generic_parser.parse(request.model_dump())
        event_id = str(normalized_dict["id"])

        # 3. Publish to central Event Bus ('EventNormalized' topic)
        await event_bus.publish("EventNormalized", normalized_dict)
        
        metrics_tracker.record_accepted()

        return IngestEventResponse(
            status="accepted",
            event_id=event_id,
            timestamp=normalized_dict["timestamp"].isoformat() if isinstance(normalized_dict["timestamp"], datetime) else str(normalized_dict["timestamp"]),
            source=normalized_dict["source"],
            event_type=normalized_dict["event_type"],
            ingest_mode="LIVE"
        )

    except Exception as e:
        metrics_tracker.record_rejected()
        print(f"[INGEST ERROR] Failed to process incoming telemetry: {e}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to normalize and process telemetry event: {str(e)}"
        )

@router.get("/metrics", response_model=IngestMetricsResponse)
async def get_ingest_metrics(current_user: User = Depends(require_authenticated)):
    """
    Observability endpoint providing ingestion statistics (requires human JWT authentication).
    """
    return IngestMetricsResponse(
        events_received=metrics_tracker.events_received,
        events_accepted=metrics_tracker.events_accepted,
        events_rejected=metrics_tracker.events_rejected,
        rate_limit_rejections=metrics_tracker.rate_limit_rejections,
        auth_failures=metrics_tracker.auth_failures,
        last_event_timestamp=metrics_tracker.last_event_timestamp,
        rate_limit_per_minute=settings.RATE_LIMIT_INGEST_PER_MINUTE
    )
