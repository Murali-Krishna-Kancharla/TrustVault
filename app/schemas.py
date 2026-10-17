from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field

# User Schemas
class UserLogin(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserOut"

class UserOut(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class UserStatusUpdate(BaseModel):
    is_active: bool

# Permission Schemas
class PermissionCreate(BaseModel):
    user_id: str
    permission_level: str = Field(..., pattern="^(read|edit)$")

class PermissionOut(BaseModel):
    id: str
    document_id: str
    user_id: str
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    permission_level: str
    granted_by: str
    granter_email: Optional[str] = None
    granted_at: datetime

    class Config:
        from_attributes = True

# Document Schemas
class DocumentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    classification: Optional[str] = None

class DocumentOut(BaseModel):
    id: str
    title: str
    description: str
    category: str
    classification: str
    owner_id: str
    owner_name: Optional[str] = None
    owner_email: Optional[str] = None
    original_filename: str
    file_size_bytes: int
    mime_type: str
    sha256_hash: str
    user_permission: Optional[str] = None  # Current user's permission: 'owner', 'edit', 'read'
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class DocumentDetailOut(DocumentOut):
    permissions: List[PermissionOut] = []

# Audit Schemas
class AuditLogOut(BaseModel):
    id: int
    timestamp: datetime
    actor_id: Optional[str]
    actor_email: str
    actor_role: str
    action: str
    target_type: str
    target_id: str
    ip_address: str
    status: str
    details: str
    prev_hash: str
    record_hash: str
    signature: str

    class Config:
        from_attributes = True

class AuditVerifyResponse(BaseModel):
    is_valid: bool
    total_records: int
    tampered_at_id: Optional[int] = None
    verification_time_utc: str
    message: str

# Admin Dashboard
class AdminDashboardOut(BaseModel):
    total_documents: int
    total_users: int
    total_audit_events: int
    total_refused_attempts: int
    ledger_intact: bool
    recent_security_events: List[AuditLogOut]

# AI Suggestion
class AISuggestionOut(BaseModel):
    document_id: str
    suggested_users: List[dict]
    rationale: str
