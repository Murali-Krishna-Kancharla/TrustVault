from typing import Optional, Tuple
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models import User, Document, Permission
from app.audit import record_audit_event

def verify_document_access(
    document_id: str,
    required_level: str,  # 'read', 'edit', 'owner'
    user: User,
    db: Session,
    client_ip: str = "127.0.0.1",
    action_name: str = "DOCUMENT_ACCESS",
) -> Tuple[Document, str]:
    """
    Core Server-Side Authorization Engine for TrustVault.
    
    Invariants enforced:
    1. The server checks the live database state on every single request.
    2. If the user is the Document Owner, full access ('owner') is granted.
    3. If the user has an explicit Permission row:
       - 'read' requested requires permission_level in ('read', 'edit')
       - 'edit' requested requires permission_level == 'edit'
       - 'owner' requested requires user to be document owner.
    4. Administrators DO NOT automatically inherit document access.
       (Separation of Duties / Zero Trust: Admins manage users and audit logs,
       not confidential document contents without explicit grant).
    5. ANY refused access attempt is immediately written to the tamper-evident
       audit log with status='REFUSED' before raising HTTP 403 Forbidden.
    """
    doc = db.query(Document).filter(Document.id == document_id, Document.is_deleted == False).first()
    if not doc:
        # Prevent document existence oracle by logging refused attempt if ID was attempted
        record_audit_event(
            db=db,
            actor_email=user.email,
            actor_role=user.role,
            actor_id=user.id,
            action=action_name,
            target_type="DOCUMENT",
            target_id=document_id,
            ip_address=client_ip,
            status="REFUSED",
            details={"error": "Document not found or deleted", "required_level": required_level},
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found or access denied",
        )

    # 1. Check if user is Document Owner
    if doc.owner_id == user.id:
        return doc, "owner"

    # 2. Check for explicit permission grant in database
    perm = db.query(Permission).filter(
        Permission.document_id == doc.id,
        Permission.user_id == user.id,
    ).first()

    # Determine granted level
    effective_permission: Optional[str] = None
    if perm:
        effective_permission = perm.permission_level

    # 3. Evaluate requested level vs effective permission
    is_allowed = False
    if required_level == "read" and effective_permission in ("read", "edit"):
        is_allowed = True
    elif required_level == "edit" and effective_permission == "edit":
        is_allowed = True
    elif required_level == "owner":
        is_allowed = False  # Only document owner can perform owner actions (delete, grant/revoke permissions)

    if not is_allowed:
        # Log refusing the request to the tamper-evident audit ledger
        record_audit_event(
            db=db,
            actor_email=user.email,
            actor_role=user.role,
            actor_id=user.id,
            action=action_name,
            target_type="DOCUMENT",
            target_id=doc.id,
            ip_address=client_ip,
            status="REFUSED",
            details={
                "error": "Forbidden: insufficient permissions",
                "required_level": required_level,
                "current_permission": effective_permission,
                "document_title": doc.title,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: You do not have permission to access this document.",
        )

    return doc, effective_permission or "read"
