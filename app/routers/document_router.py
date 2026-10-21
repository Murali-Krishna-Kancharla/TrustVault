import os
import uuid
from typing import List, Optional
from datetime import datetime
from io import BytesIO

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Form,
    Request,
    status,
    Query,
)
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from app.database import get_db
from app.models import User, Document, Permission
from app.schemas import DocumentOut, DocumentDetailOut, DocumentUpdate
from app.auth import get_current_user, require_role
from app.rbac import verify_document_access
from app.security import (
    sanitize_filename,
    validate_uploaded_content,
    encrypt_file_data,
    decrypt_file_data,
    compute_sha256,
)
from app.audit import record_audit_event
from app.config import VAULT_STORAGE_DIR

router = APIRouter(prefix="/api/documents", tags=["Documents"])

@router.post("/upload", response_model=DocumentOut, status_code=status.HTTP_201_CREATED)
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    title: str = Form(...),
    description: str = Form(""),
    category: str = Form("General"),
    classification: str = Form("Confidential"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Secure document upload with validation, AES-256-GCM encryption, and tamper logging.
    Allowed roles: Document Owner or Administrator.
    """
    client_ip = request.client.host if request.client else "unknown"

    if current_user.role not in ("owner", "admin"):
        record_audit_event(
            db=db,
            actor_email=current_user.email,
            actor_role=current_user.role,
            actor_id=current_user.id,
            action="DOCUMENT_UPLOAD",
            target_type="DOCUMENT",
            target_id="new",
            ip_address=client_ip,
            status="REFUSED",
            details={"error": "Viewers are not permitted to upload documents"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Viewers are not permitted to upload documents.",
        )

    # Read file content into memory
    content = await file.read()
    raw_filename = file.filename or "uploaded_file"
    safe_filename = sanitize_filename(raw_filename)

    # Multi-layer content validation (magic bytes, size, script/executable checks)
    is_valid, validated_mime, error_reason = validate_uploaded_content(
        filename=safe_filename,
        content=content,
        declared_mime_type=file.content_type or "application/octet-stream",
    )

    if not is_valid:
        record_audit_event(
            db=db,
            actor_email=current_user.email,
            actor_role=current_user.role,
            actor_id=current_user.id,
            action="DOCUMENT_UPLOAD",
            target_type="DOCUMENT",
            target_id=safe_filename,
            ip_address=client_ip,
            status="REFUSED",
            details={"error": "File validation failed", "reason": error_reason, "filename": safe_filename},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Upload rejected by security validation: {error_reason}",
        )

    # Compute SHA-256 of plaintext for cryptographic verification
    file_sha256 = compute_sha256(content)
    doc_id = str(uuid.uuid4())

    # Encrypt file at rest using AES-256-GCM
    encrypted_payload = encrypt_file_data(content)
    storage_filename = f"{doc_id}.enc"
    storage_filepath = VAULT_STORAGE_DIR / storage_filename

    with open(storage_filepath, "wb") as f:
        f.write(encrypted_payload)

    # Create document record in database
    doc = Document(
        id=doc_id,
        title=title.strip(),
        description=description.strip(),
        category=category.strip(),
        classification=classification.strip(),
        owner_id=current_user.id,
        original_filename=safe_filename,
        storage_path=str(storage_filepath),
        file_size_bytes=len(content),
        mime_type=validated_mime,
        sha256_hash=file_sha256,
        is_deleted=False,
    )

    db.add(doc)
    db.commit()
    db.refresh(doc)

    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        actor_id=current_user.id,
        action="DOCUMENT_UPLOAD",
        target_type="DOCUMENT",
        target_id=doc.id,
        ip_address=client_ip,
        status="SUCCESS",
        details={
            "title": doc.title,
            "filename": safe_filename,
            "category": doc.category,
            "classification": doc.classification,
            "sha256": file_sha256,
            "file_size_bytes": len(content),
        },
    )

    return DocumentOut(
        id=doc.id,
        title=doc.title,
        description=doc.description,
        category=doc.category,
        classification=doc.classification,
        owner_id=doc.owner_id,
        owner_name=current_user.full_name,
        owner_email=current_user.email,
        original_filename=doc.original_filename,
        file_size_bytes=doc.file_size_bytes,
        mime_type=doc.mime_type,
        sha256_hash=doc.sha256_hash,
        user_permission="owner",
        created_at=doc.created_at,
        updated_at=doc.updated_at,
    )

@router.get("", response_model=List[DocumentOut])
def list_and_search_documents(
    query: Optional[str] = Query(None, description="Search term across title and description"),
    category: Optional[str] = Query(None, description="Filter by category"),
    classification: Optional[str] = Query(None, description="Filter by classification"),
    from_date: Optional[str] = Query(None, description="ISO format start date"),
    to_date: Optional[str] = Query(None, description="ISO format end date"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Search and retrieve documents.
    STRICT SECURITY INVARIANT:
    Returns ONLY documents that the requesting user owns or has an active explicit permission for.
    Zero metadata or existence leakage of unpermitted documents.
    """
    # 1. Base query: not deleted
    q = db.query(Document).filter(Document.is_deleted == False)

    # 2. Strict Object-Level Filter
    # A user can only see documents if they are the owner OR have a permission grant.
    shared_doc_ids = db.query(Permission.document_id).filter(Permission.user_id == current_user.id).all()
    permitted_ids = [p[0] for p in shared_doc_ids]
    
    q = q.filter(
        or_(
            Document.owner_id == current_user.id,
            Document.id.in_(permitted_ids),
        )
    )

    # 3. Apply search query
    if query:
        pattern = f"%{query}%"
        q = q.filter(
            or_(
                Document.title.ilike(pattern),
                Document.description.ilike(pattern),
                Document.original_filename.ilike(pattern),
            )
        )

    # 4. Category filter
    if category and category.lower() != "all":
        q = q.filter(Document.category.ilike(category))

    # 5. Classification filter
    if classification and classification.lower() != "all":
        q = q.filter(Document.classification.ilike(classification))

    # 6. Date filters
    if from_date:
        try:
            dt_from = datetime.fromisoformat(from_date)
            q = q.filter(Document.created_at >= dt_from)
        except ValueError:
            pass

    if to_date:
        try:
            dt_to = datetime.fromisoformat(to_date)
            q = q.filter(Document.created_at <= dt_to)
        except ValueError:
            pass

    docs = q.order_by(Document.created_at.desc()).all()

    # Pre-fetch user permissions mapping for fast response
    user_perms = {
        p.document_id: p.permission_level
        for p in db.query(Permission).filter(Permission.user_id == current_user.id).all()
    }

    result = []
    for d in docs:
        if d.owner_id == current_user.id:
            perm_level = "owner"
        else:
            perm_level = user_perms.get(d.id, "none")

        result.append(
            DocumentOut(
                id=d.id,
                title=d.title,
                description=d.description,
                category=d.category,
                classification=d.classification,
                owner_id=d.owner_id,
                owner_name=d.owner.full_name if d.owner else "Unknown",
                owner_email=d.owner.email if d.owner else "Unknown",
                original_filename=d.original_filename,
                file_size_bytes=d.file_size_bytes,
                mime_type=d.mime_type,
                sha256_hash=d.sha256_hash,
                user_permission=perm_level,
                created_at=d.created_at,
                updated_at=d.updated_at,
            )
        )

    return result

@router.get("/{document_id}", response_model=DocumentDetailOut)
def get_document_details(
    document_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get document metadata and access control list.
    Requires at least 'read' permission.
    """
    client_ip = request.client.host if request.client else "unknown"
    doc, perm_level = verify_document_access(
        document_id=document_id,
        required_level="read",
        user=current_user,
        db=db,
        client_ip=client_ip,
        action_name="DOCUMENT_READ_METADATA",
    )

    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        actor_id=current_user.id,
        action="DOCUMENT_READ_METADATA",
        target_type="DOCUMENT",
        target_id=doc.id,
        ip_address=client_ip,
        status="SUCCESS",
        details={"title": doc.title, "user_permission": perm_level},
    )

    # Include permissions list if user is owner or admin
    permissions_out = []
    if perm_level == "owner" or current_user.role == "admin":
        for p in doc.permissions:
            permissions_out.append({
                "id": p.id,
                "document_id": p.document_id,
                "user_id": p.user_id,
                "user_email": p.user.email if p.user else "Unknown",
                "user_name": p.user.full_name if p.user else "Unknown",
                "permission_level": p.permission_level,
                "granted_by": p.granted_by,
                "granter_email": p.granter.email if p.granter else "Unknown",
                "granted_at": p.granted_at,
            })

    return DocumentDetailOut(
        id=doc.id,
        title=doc.title,
        description=doc.description,
        category=doc.category,
        classification=doc.classification,
        owner_id=doc.owner_id,
        owner_name=doc.owner.full_name if doc.owner else "Unknown",
        owner_email=doc.owner.email if doc.owner else "Unknown",
        original_filename=doc.original_filename,
        file_size_bytes=doc.file_size_bytes,
        mime_type=doc.mime_type,
        sha256_hash=doc.sha256_hash,
        user_permission=perm_level,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
        permissions=permissions_out,
    )

@router.get("/{document_id}/download")
def download_document(
    document_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Secure streamed download of confidential document.
    Server-side authorization enforced on every request.
    Decrypted in-memory with AES-256-GCM and streamed with strict security headers.
    """
    client_ip = request.client.host if request.client else "unknown"
    doc, perm_level = verify_document_access(
        document_id=document_id,
        required_level="read",
        user=current_user,
        db=db,
        client_ip=client_ip,
        action_name="DOCUMENT_DOWNLOAD",
    )

    if not os.path.exists(doc.storage_path):
        record_audit_event(
            db=db,
            actor_email=current_user.email,
            actor_role=current_user.role,
            actor_id=current_user.id,
            action="DOCUMENT_DOWNLOAD",
            target_type="DOCUMENT",
            target_id=doc.id,
            ip_address=client_ip,
            status="REFUSED",
            details={"error": "File storage blob missing on server"},
        )
        raise HTTPException(status_code=500, detail="Document storage blob not found on server")

    # Read and decrypt file
    try:
        with open(doc.storage_path, "rb") as f:
            encrypted_data = f.read()
        plaintext = decrypt_file_data(encrypted_data)
    except Exception as e:
        record_audit_event(
            db=db,
            actor_email=current_user.email,
            actor_role=current_user.role,
            actor_id=current_user.id,
            action="DOCUMENT_DOWNLOAD",
            target_type="DOCUMENT",
            target_id=doc.id,
            ip_address=client_ip,
            status="REFUSED",
            details={"error": f"Decryption failure: {str(e)}"},
        )
        raise HTTPException(status_code=500, detail="Failed to decrypt secure document")

    # Verify cryptographic integrity
    download_sha256 = compute_sha256(plaintext)
    if download_sha256 != doc.sha256_hash:
        record_audit_event(
            db=db,
            actor_email=current_user.email,
            actor_role=current_user.role,
            actor_id=current_user.id,
            action="DOCUMENT_DOWNLOAD",
            target_type="DOCUMENT",
            target_id=doc.id,
            ip_address=client_ip,
            status="REFUSED",
            details={"error": "Integrity checksum mismatch"},
        )
        raise HTTPException(status_code=500, detail="Document integrity verification failed")

    # Record successful download in audit trail
    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        actor_id=current_user.id,
        action="DOCUMENT_DOWNLOAD",
        target_type="DOCUMENT",
        target_id=doc.id,
        ip_address=client_ip,
        status="SUCCESS",
        details={
            "filename": doc.original_filename,
            "sha256": doc.sha256_hash,
            "bytes_transferred": len(plaintext),
            "permission_level": perm_level,
        },
    )

    # Return stream with hardened security headers
    headers = {
        "Content-Disposition": f'attachment; filename="{doc.original_filename}"',
        "Content-Security-Policy": "default-src 'none'",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store, no-cache, must-revalidate, private",
        "Pragma": "no-cache",
    }

    return StreamingResponse(
        BytesIO(plaintext),
        media_type=doc.mime_type,
        headers=headers,
    )

@router.put("/{document_id}", response_model=DocumentOut)
def update_document(
    document_id: str,
    update_data: DocumentUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Update document metadata. Requires at least 'edit' permission or owner.
    """
    client_ip = request.client.host if request.client else "unknown"
    doc, perm_level = verify_document_access(
        document_id=document_id,
        required_level="edit",
        user=current_user,
        db=db,
        client_ip=client_ip,
        action_name="DOCUMENT_UPDATE",
    )

    changes = {}
    if update_data.title is not None and update_data.title.strip():
        changes["title"] = {"old": doc.title, "new": update_data.title.strip()}
        doc.title = update_data.title.strip()
    if update_data.description is not None:
        changes["description"] = {"old": doc.description, "new": update_data.description.strip()}
        doc.description = update_data.description.strip()
    if update_data.category is not None and update_data.category.strip():
        changes["category"] = {"old": doc.category, "new": update_data.category.strip()}
        doc.category = update_data.category.strip()
    if update_data.classification is not None and update_data.classification.strip():
        changes["classification"] = {"old": doc.classification, "new": update_data.classification.strip()}
        doc.classification = update_data.classification.strip()

    doc.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(doc)

    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        actor_id=current_user.id,
        action="DOCUMENT_UPDATE",
        target_type="DOCUMENT",
        target_id=doc.id,
        ip_address=client_ip,
        status="SUCCESS",
        details={"changes": changes},
    )

    return DocumentOut(
        id=doc.id,
        title=doc.title,
        description=doc.description,
        category=doc.category,
        classification=doc.classification,
        owner_id=doc.owner_id,
        owner_name=doc.owner.full_name if doc.owner else "Unknown",
        owner_email=doc.owner.email if doc.owner else "Unknown",
        original_filename=doc.original_filename,
        file_size_bytes=doc.file_size_bytes,
        mime_type=doc.mime_type,
        sha256_hash=doc.sha256_hash,
        user_permission=perm_level,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
    )

@router.delete("/{document_id}", status_code=status.HTTP_200_OK)
def delete_document(
    document_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Delete document. Only the Document Owner can delete.
    Removes the encrypted file payload and marks deleted.
    """
    client_ip = request.client.host if request.client else "unknown"
    doc, perm_level = verify_document_access(
        document_id=document_id,
        required_level="owner",
        user=current_user,
        db=db,
        client_ip=client_ip,
        action_name="DOCUMENT_DELETE",
    )

    doc.is_deleted = True
    db.commit()

    # Securely remove disk blob
    if os.path.exists(doc.storage_path):
        try:
            os.remove(doc.storage_path)
        except OSError:
            pass

    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        actor_id=current_user.id,
        action="DOCUMENT_DELETE",
        target_type="DOCUMENT",
        target_id=doc.id,
        ip_address=client_ip,
        status="SUCCESS",
        details={"title": doc.title, "filename": doc.original_filename},
    )

    return {"message": "Document successfully deleted", "document_id": document_id}
