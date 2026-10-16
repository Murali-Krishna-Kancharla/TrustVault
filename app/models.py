import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Boolean,
    Integer,
    DateTime,
    ForeignKey,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from app.database import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False)  # 'admin', 'owner', 'viewer'
    is_active = Column(Boolean, default=True, nullable=False)
    token_version = Column(Integer, default=1, nullable=False)  # Incremented on password reset / user revocation
    created_at = Column(DateTime, default=utc_now, nullable=False)

    owned_documents = relationship("Document", back_populates="owner", cascade="all, delete-orphan")
    granted_permissions = relationship("Permission", foreign_keys="Permission.user_id", back_populates="user", cascade="all, delete-orphan")


class Document(Base):
    __tablename__ = "documents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    title = Column(String(255), index=True, nullable=False)
    description = Column(Text, default="", nullable=False)
    category = Column(String(100), index=True, nullable=False)  # e.g., 'Financial', 'Legal', 'HR', 'Engineering', 'Compliance'
    classification = Column(String(50), default="Confidential", nullable=False)  # 'Internal', 'Confidential', 'Restricted'
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    original_filename = Column(String(255), nullable=False)
    storage_path = Column(String(255), nullable=False)
    file_size_bytes = Column(Integer, nullable=False)
    mime_type = Column(String(100), nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    is_deleted = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    owner = relationship("User", back_populates="owned_documents")
    permissions = relationship("Permission", back_populates="document", cascade="all, delete-orphan")


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    document_id = Column(String(36), ForeignKey("documents.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    permission_level = Column(String(50), nullable=False)  # 'read' or 'edit'
    granted_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    granted_at = Column(DateTime, default=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("document_id", "user_id", name="uq_document_user_permission"),
    )

    document = relationship("Document", back_populates="permissions")
    user = relationship("User", foreign_keys=[user_id], back_populates="granted_permissions")
    granter = relationship("User", foreign_keys=[granted_by])


class AuditLog(Base):
    """
    Cryptographically chained, tamper-evident audit ledger.
    Every event contains the SHA-256 hash of the preceding record and an HMAC signature.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False)
    actor_id = Column(String(36), nullable=True)
    actor_email = Column(String(255), nullable=False)
    actor_role = Column(String(50), nullable=False)
    action = Column(String(100), index=True, nullable=False)
    target_type = Column(String(50), nullable=False)  # 'DOCUMENT', 'USER', 'PERMISSION', 'SYSTEM'
    target_id = Column(String(255), nullable=False)
    ip_address = Column(String(100), nullable=False)
    status = Column(String(20), index=True, nullable=False)  # 'SUCCESS' or 'REFUSED'
    details = Column(Text, default="{}", nullable=False)
    prev_hash = Column(String(64), nullable=False)
    record_hash = Column(String(64), nullable=False)
    signature = Column(String(64), nullable=False)
