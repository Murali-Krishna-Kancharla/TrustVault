from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models import User, Document, AuditLog
from app.schemas import AdminDashboardOut, UserStatusUpdate, UserOut
from app.auth import get_current_user, require_role
from app.audit import record_audit_event, verify_audit_integrity

router = APIRouter(prefix="/api/admin", tags=["Administration"])

@router.get("/dashboard", response_model=AdminDashboardOut)
def get_admin_dashboard(
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """
    Administrative overview of security activity, permission changes, and refused access attempts.
    Highlights anomalies, refused access attempts, and verifies cryptographic ledger state.
    """
    total_docs = db.query(Document).filter(Document.is_deleted == False).count()
    total_users = db.query(User).count()
    total_audit = db.query(AuditLog).count()
    total_refused = db.query(AuditLog).filter(AuditLog.status == "REFUSED").count()

    is_intact, _, _, _ = verify_audit_integrity(db)

    # Fetch recent security-relevant events (refused attempts or permission changes)
    recent_events = (
        db.query(AuditLog)
        .filter(
            (AuditLog.status == "REFUSED")
            | (AuditLog.action.in_(["PERMISSION_GRANT", "PERMISSION_REVOKE", "USER_DEACTIVATED", "DOCUMENT_DELETE"]))
        )
        .order_by(desc(AuditLog.id))
        .limit(20)
        .all()
    )

    return AdminDashboardOut(
        total_documents=total_docs,
        total_users=total_users,
        total_audit_events=total_audit,
        total_refused_attempts=total_refused,
        ledger_intact=is_intact,
        recent_security_events=recent_events,
    )

@router.post("/users/{user_id}/status", response_model=UserOut)
def update_user_status(
    user_id: str,
    status_in: UserStatusUpdate,
    request: Request,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """
    Administrator deactivation/activation of a user.
    IMMEDIATE REVOCATION:
    Incrementing token_version immediately invalidates all active JWT tokens held by that user.
    """
    client_ip = request.client.host if request.client else "unknown"
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    target_user.is_active = status_in.is_active
    target_user.token_version += 1  # Invalidate all existing tokens
    db.commit()
    db.refresh(target_user)

    action_name = "USER_ACTIVATED" if status_in.is_active else "USER_DEACTIVATED"
    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        actor_id=current_user.id,
        action=action_name,
        target_type="USER",
        target_id=target_user.id,
        ip_address=client_ip,
        status="SUCCESS",
        details={
            "target_email": target_user.email,
            "is_active": target_user.is_active,
            "new_token_version": target_user.token_version,
            "revocation_effect": "All active sessions immediately revoked",
        },
    )

    return target_user
