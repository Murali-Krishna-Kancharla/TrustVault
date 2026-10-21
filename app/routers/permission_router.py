from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, Document, Permission
from app.schemas import PermissionCreate, PermissionOut, AISuggestionOut
from app.auth import get_current_user
from app.rbac import verify_document_access
from app.audit import record_audit_event

router = APIRouter(prefix="/api/documents/{document_id}/permissions", tags=["Permissions"])

@router.get("", response_model=List[PermissionOut])
def get_document_permissions(
    document_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    List permissions for a document. Owner or Admin only.
    """
    client_ip = request.client.host if request.client else "unknown"
    doc, perm_level = verify_document_access(
        document_id=document_id,
        required_level="owner",
        user=current_user,
        db=db,
        client_ip=client_ip,
        action_name="PERMISSION_LIST",
    )

    perms = db.query(Permission).filter(Permission.document_id == doc.id).all()
    result = []
    for p in perms:
        result.append(
            PermissionOut(
                id=p.id,
                document_id=p.document_id,
                user_id=p.user_id,
                user_email=p.user.email if p.user else "Unknown",
                user_name=p.user.full_name if p.user else "Unknown",
                permission_level=p.permission_level,
                granted_by=p.granted_by,
                granter_email=p.granter.email if p.granter else "Unknown",
                granted_at=p.granted_at,
            )
        )
    return result

@router.post("", response_model=PermissionOut, status_code=status.HTTP_201_CREATED)
def grant_permission(
    document_id: str,
    perm_in: PermissionCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Grant named user 'read' or 'edit' access to a document.
    Enforces that only the Document Owner can grant permissions.
    Immediately recorded in the cryptographic audit ledger.
    """
    client_ip = request.client.host if request.client else "unknown"
    doc, perm_level = verify_document_access(
        document_id=document_id,
        required_level="owner",
        user=current_user,
        db=db,
        client_ip=client_ip,
        action_name="PERMISSION_GRANT",
    )

    # Verify target user exists
    target_user = db.query(User).filter(User.id == perm_in.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Target user does not exist")

    if target_user.id == doc.owner_id:
        raise HTTPException(status_code=400, detail="Cannot assign permission to document owner (owner already has full rights)")

    # Check if permission already exists
    existing = db.query(Permission).filter(
        Permission.document_id == doc.id,
        Permission.user_id == target_user.id,
    ).first()

    if existing:
        existing.permission_level = perm_in.permission_level
        existing.granted_by = current_user.id
        perm = existing
    else:
        perm = Permission(
            document_id=doc.id,
            user_id=target_user.id,
            permission_level=perm_in.permission_level,
            granted_by=current_user.id,
        )
        db.add(perm)

    db.commit()
    db.refresh(perm)

    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        actor_id=current_user.id,
        action="PERMISSION_GRANT",
        target_type="PERMISSION",
        target_id=perm.id,
        ip_address=client_ip,
        status="SUCCESS",
        details={
            "document_id": doc.id,
            "document_title": doc.title,
            "target_user_id": target_user.id,
            "target_user_email": target_user.email,
            "permission_level": perm.permission_level,
        },
    )

    return PermissionOut(
        id=perm.id,
        document_id=perm.document_id,
        user_id=perm.user_id,
        user_email=target_user.email,
        user_name=target_user.full_name,
        permission_level=perm.permission_level,
        granted_by=perm.granted_by,
        granter_email=current_user.email,
        granted_at=perm.granted_at,
    )

@router.delete("/{user_id}", status_code=status.HTTP_200_OK)
def revoke_permission(
    document_id: str,
    user_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    IMMEDIATE REVOCATION:
    Takes access away immediately. The permission row is deleted in the database transaction,
    ensuring any subsequent or concurrent request from that user is instantly blocked.
    """
    client_ip = request.client.host if request.client else "unknown"
    doc, perm_level = verify_document_access(
        document_id=document_id,
        required_level="owner",
        user=current_user,
        db=db,
        client_ip=client_ip,
        action_name="PERMISSION_REVOKE",
    )

    perm = db.query(Permission).filter(
        Permission.document_id == doc.id,
        Permission.user_id == user_id,
    ).first()

    if not perm:
        raise HTTPException(status_code=404, detail="Permission grant not found")

    revoked_user = db.query(User).filter(User.id == user_id).first()
    revoked_email = revoked_user.email if revoked_user else "unknown"

    db.delete(perm)
    db.commit()

    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        actor_id=current_user.id,
        action="PERMISSION_REVOKE",
        target_type="PERMISSION",
        target_id=f"{doc.id}:{user_id}",
        ip_address=client_ip,
        status="SUCCESS",
        details={
            "document_id": doc.id,
            "document_title": doc.title,
            "revoked_from_user_id": user_id,
            "revoked_from_email": revoked_email,
        },
    )

    return {"message": "Permission successfully revoked with immediate effect", "revoked_from": revoked_email}

@router.post("/ai-recommend", response_model=AISuggestionOut)
def get_ai_permission_recommendations(
    document_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    AI Permission Advisory Assistant.
    Provides intelligent recommendations on who should receive access.
    CRITICAL SECURITY INVARIANT:
    The AI NEVER widens access autonomously. It only suggests candidates.
    A human owner must review and confirm, and both the AI recommendation
    and the human decision are permanently captured in the audit trail.
    """
    client_ip = request.client.host if request.client else "unknown"
    doc, perm_level = verify_document_access(
        document_id=document_id,
        required_level="owner",
        user=current_user,
        db=db,
        client_ip=client_ip,
        action_name="AI_PERMISSION_ADVISORY",
    )

    category = (doc.category or "").lower()
    title = (doc.title or "").lower()

    # Query candidate users excluding owner
    all_users = db.query(User).filter(User.id != current_user.id, User.is_active == True).all()
    suggestions = []
    rationale = ""

    if "salary" in title or "hr" in category or "employee" in title:
        rationale = "Document classified as HR/Compensation. Recommended for Finance Analyst with Read-only access for payroll reconciliation."
        for u in all_users:
            if "analyst" in u.full_name.lower() or "dave" in u.email.lower() or "hr" in u.email.lower():
                suggestions.append({"user_id": u.id, "email": u.email, "name": u.full_name, "suggested_level": "read"})
    elif "contract" in title or "legal" in category or "termsheet" in title:
        rationale = "Document classified as Legal Agreement / M&A. Recommended for External Legal Counsel / Auditor with Edit/Review access."
        for u in all_users:
            if "auditor" in u.full_name.lower() or "bob" in u.email.lower() or "legal" in u.email.lower():
                suggestions.append({"user_id": u.id, "email": u.email, "name": u.full_name, "suggested_level": "edit"})
    else:
        rationale = "General business document. Recommended for cross-functional stakeholders with Read access."
        for u in all_users[:2]:
            suggestions.append({"user_id": u.id, "email": u.email, "name": u.full_name, "suggested_level": "read"})

    # Record AI suggestion event in audit ledger
    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        actor_id=current_user.id,
        action="AI_PERMISSION_SUGGESTION",
        target_type="DOCUMENT",
        target_id=doc.id,
        ip_address=client_ip,
        status="SUCCESS",
        details={
            "document_title": doc.title,
            "suggested_count": len(suggestions),
            "rationale": rationale,
            "machine_widened_access": False,
        },
    )

    return AISuggestionOut(
        document_id=doc.id,
        suggested_users=suggestions,
        rationale=rationale,
    )
