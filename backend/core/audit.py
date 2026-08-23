import inspect
from sqlalchemy.ext.asyncio import AsyncSession
from models.investigation import AuditLog
import uuid
from typing import Dict, Any, Optional

async def record_audit_log(
    db: AsyncSession,
    case_id: uuid.UUID | str,
    user_id: Optional[uuid.UUID | str],
    action: str,
    details: Dict[str, Any]
) -> AuditLog:
    """
    Appends an immutable audit log entry for an investigation case.
    """
    c_uuid = uuid.UUID(str(case_id)) if isinstance(case_id, str) else case_id
    u_uuid = uuid.UUID(str(user_id)) if user_id else None
    log_entry = AuditLog(
        case_id=c_uuid,
        user_id=u_uuid,
        action=action,
        details=details
    )
    add_res = db.add(log_entry)
    if inspect.isawaitable(add_res):
        await add_res

    if hasattr(db, "flush") and callable(db.flush):
        flush_res = db.flush()
        if inspect.isawaitable(flush_res):
            await flush_res

    return log_entry

