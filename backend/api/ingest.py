import secrets
from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, Header, HTTPException, status, Depends, Request
from fastapi.security import APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.events import event_bus
from core.integrity import compute_event_hash, find_duplicate_event_id
from core.rate_limiter import ingestion_rate_limiter
from core.auth import require_authenticated
from database.session import get_db
from models.user import User
from schemas.canonical_event import CanonicalEventValidationError
from schemas.ingest import (
    IngestEventRequest,
    IngestEventResponse,
    IngestMetricsResponse,
    SysmonIngestRequest,
    SysmonIngestResponse,
    SuricataIngestRequest,
    SuricataIngestResponse,
)
from plugins.parsers.generic import generic_parser
from plugins.parsers.sysmon import sysmon_parser
from plugins.parsers.suricata import suricata_parser

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

@router.post("/sysmon", response_model=SysmonIngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_sysmon_event(
    request: SysmonIngestRequest,
    raw_request: Request,
    api_key: str = Depends(verify_ingestion_api_key),
    db: AsyncSession = Depends(get_db),
):
    """
    Sysmon Connector (Phase 11): accepts one raw Sysmon event (the flattened
    JSON shape Winlogbeat/NXLog-style shippers produce), normalizes it through
    plugins.parsers.sysmon.SysmonParser into the same canonical contract every
    other source uses, and publishes it on the same 'EventNormalized' topic —
    reusing live ingestion's auth, rate limiting, durable event bus, storage
    and detection pipeline unchanged.

    Supports Sysmon EventID 1 (Process Create), 3 (Network Connect), 11 (File
    Create). Any other EventID, or a missing/non-integer EventID, is rejected
    with 422 — see plugins/parsers/sysmon.py for the full mapping and
    docs/CANONICAL_EVENT_MODEL.md "Connectors" for why 4624/4625/4672 (a
    different provider, not Sysmon) are intentionally not accepted here.
    """
    metrics_tracker.record_received()

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
        canonical_event = sysmon_parser.to_canonical(request.event)
    except CanonicalEventValidationError as e:
        metrics_tracker.record_rejected()
        print(f"[INGEST ERROR] Sysmon event rejected: {e}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to normalize Sysmon event: {str(e)}"
        )

    normalized_dict = canonical_event.to_orm_kwargs()

    # Best-effort duplicate suppression: a redelivered identical record (e.g. a
    # shipper resending after a restart) is acknowledged idempotently instead of
    # being stored twice. See core.integrity.find_duplicate_event_id for the
    # race-window caveat (no DB uniqueness constraint backs this).
    content_hash = compute_event_hash(normalized_dict)
    existing_id = await find_duplicate_event_id(db, content_hash)
    if existing_id is not None:
        metrics_tracker.record_accepted()
        return SysmonIngestResponse(
            status="duplicate",
            event_id=str(existing_id),
            timestamp=normalized_dict["timestamp"].isoformat(),
            hostname=normalized_dict["hostname"],
            event_type=normalized_dict["event_type"],
            canonical_event_type=canonical_event.canonical_event_type.value,
            ingest_mode="LIVE",
        )

    try:
        await event_bus.publish("EventNormalized", normalized_dict)
        metrics_tracker.record_accepted()
    except Exception as e:
        metrics_tracker.record_rejected()
        print(f"[INGEST ERROR] Failed to publish Sysmon event: {e}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to process Sysmon event: {str(e)}"
        )

    return SysmonIngestResponse(
        status="accepted",
        event_id=str(normalized_dict["id"]),
        timestamp=normalized_dict["timestamp"].isoformat(),
        hostname=normalized_dict["hostname"],
        event_type=normalized_dict["event_type"],
        canonical_event_type=canonical_event.canonical_event_type.value,
        ingest_mode="LIVE",
    )


@router.post("/suricata", response_model=SuricataIngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_suricata_event(
    request: SuricataIngestRequest,
    raw_request: Request,
    api_key: str = Depends(verify_ingestion_api_key),
    db: AsyncSession = Depends(get_db),
):
    """
    Suricata EVE connector (Phase 11, connector #2): accepts one raw Suricata
    EVE JSON record, normalizes it through plugins.parsers.suricata.SuricataParser
    into the same canonical contract every other source uses, and publishes it
    on the same 'EventNormalized' topic — reusing live ingestion's auth, rate
    limiting, durable event bus, storage and detection pipeline unchanged.

    Supports EVE 'event_type' values 'alert' (a NIDS signature match) and
    'flow' (a connection record). Any other EVE event_type, or a
    missing/unsupported one, is rejected with 422 — see
    plugins/parsers/suricata.py for the full mapping and
    docs/CANONICAL_EVENT_MODEL.md "Connectors" for why the other EVE record
    types ('dns', 'http', 'tls', 'fileinfo', ...) are intentionally not
    accepted here yet.
    """
    metrics_tracker.record_received()

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
        canonical_event = suricata_parser.to_canonical(request.event)
    except CanonicalEventValidationError as e:
        metrics_tracker.record_rejected()
        print(f"[INGEST ERROR] Suricata event rejected: {e}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to normalize Suricata event: {str(e)}"
        )

    normalized_dict = canonical_event.to_orm_kwargs()

    # Best-effort duplicate suppression, same rationale as the Sysmon endpoint:
    # a redelivered identical EVE record (e.g. a shipper resending after a
    # restart) is acknowledged idempotently instead of being stored twice.
    content_hash = compute_event_hash(normalized_dict)
    existing_id = await find_duplicate_event_id(db, content_hash)
    if existing_id is not None:
        metrics_tracker.record_accepted()
        return SuricataIngestResponse(
            status="duplicate",
            event_id=str(existing_id),
            timestamp=normalized_dict["timestamp"].isoformat(),
            hostname=normalized_dict["hostname"],
            event_type=normalized_dict["event_type"],
            canonical_event_type=canonical_event.canonical_event_type.value,
            ingest_mode="LIVE",
        )

    try:
        await event_bus.publish("EventNormalized", normalized_dict)
        metrics_tracker.record_accepted()
    except Exception as e:
        metrics_tracker.record_rejected()
        print(f"[INGEST ERROR] Failed to publish Suricata event: {e}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to process Suricata event: {str(e)}"
        )

    return SuricataIngestResponse(
        status="accepted",
        event_id=str(normalized_dict["id"]),
        timestamp=normalized_dict["timestamp"].isoformat(),
        hostname=normalized_dict["hostname"],
        event_type=normalized_dict["event_type"],
        canonical_event_type=canonical_event.canonical_event_type.value,
        ingest_mode="LIVE",
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
