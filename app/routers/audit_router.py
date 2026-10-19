from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models import User, AuditLog, Document
from app.schemas import AuditLogOut, AuditVerifyResponse
from app.auth import get_current_user
from app.audit import verify_audit_integrity

router = APIRouter(prefix="/api/audit", tags=["Audit Trail"])

@router.get("", response_model=List[AuditLogOut])
def get_audit_trail(
    action: Optional[str] = Query(None, description="Filter by action name"),
    actor_email: Optional[str] = Query(None, description="Filter by actor email"),
    target_id: Optional[str] = Query(None, description="Filter by document or target ID"),
    status_filter: Optional[str] = Query(None, description="Filter by status (SUCCESS / REFUSED)"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Query the tamper-evident audit ledger.
    - Administrators can view the entire system-wide audit trail.
    - Document Owners can view audit records related to documents they own.
    - Viewers are forbidden from viewing audit records.
    """
    if current_user.role not in ("admin", "owner"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Only administrators and document owners may view the audit trail.",
        )

    q = db.query(AuditLog)

    # Document Owners only see events related to their owned documents or their own actions
    if current_user.role == "owner":
        owned_doc_ids = [d.id for d in db.query(Document.id).filter(Document.owner_id == current_user.id).all()]
        q = q.filter(
            (AuditLog.target_id.in_(owned_doc_ids)) | (AuditLog.actor_id == current_user.id)
        )

    if action and action != "ALL":
        q = q.filter(AuditLog.action == action)

    if actor_email:
        q = q.filter(AuditLog.actor_email.ilike(f"%{actor_email}%"))

    if target_id:
        q = q.filter(AuditLog.target_id == target_id)

    if status_filter and status_filter != "ALL":
        q = q.filter(AuditLog.status == status_filter)

    logs = q.order_by(desc(AuditLog.id)).offset(offset).limit(limit).all()
    return logs

@router.get("/verify", response_model=AuditVerifyResponse)
def verify_audit_trail_integrity(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Cryptographic Audit Ledger Verification Engine:
    Validates every single record from genesis to current head:
    1. Verifies prev_hash cryptographic chaining.
    2. Recalculates canonical SHA-256 hash for every record.
    3. Re-verifies HMAC-SHA256 signatures against server secret.
    Proves whether the audit trail has been tampered with or modified.
    """
    is_valid, total_records, tampered_at_id, message = verify_audit_integrity(db)

    return AuditVerifyResponse(
        is_valid=is_valid,
        total_records=total_records,
        tampered_at_id=tampered_at_id,
        verification_time_utc=datetime.now(timezone.utc).isoformat(),
        message=message,
    )
