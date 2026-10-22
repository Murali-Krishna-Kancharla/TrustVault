import os
import uuid
from datetime import datetime, timezone
from app.database import SessionLocal, Base, engine
from app.models import User, Document, Permission, AuditLog
from app.security import hash_password, encrypt_file_data, compute_sha256
from app.audit import record_audit_event
from app.config import VAULT_STORAGE_DIR

def seed_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        # Check if already seeded
        if db.query(User).count() > 0:
            print("Database already seeded. Skipping initial seeding.")
            return

        print("Seeding TrustVault database with users, secure encrypted documents, and cryptographic audit chain...")

        # 1. Create Users
        admin = User(
            id=str(uuid.uuid4()),
            email="admin@trustvault.local",
            hashed_password=hash_password("AdminPass123!"),
            full_name="System Administrator (SecOps)",
            role="admin",
            is_active=True,
            token_version=1,
        )

        alice = User(
            id=str(uuid.uuid4()),
            email="alice.owner@trustvault.local",
            hashed_password=hash_password("AlicePass123!"),
            full_name="Alice Morgan (Head of HR)",
            role="owner",
            is_active=True,
            token_version=1,
        )

        carol = User(
            id=str(uuid.uuid4()),
            email="carol.owner@trustvault.local",
            hashed_password=hash_password("CarolPass123!"),
            full_name="Carol Vance (General Counsel)",
            role="owner",
            is_active=True,
            token_version=1,
        )

        bob = User(
            id=str(uuid.uuid4()),
            email="bob.viewer@trustvault.local",
            hashed_password=hash_password("BobPass123!"),
            full_name="Bob Hastings (External Auditor)",
            role="viewer",
            is_active=True,
            token_version=1,
        )

        dave = User(
            id=str(uuid.uuid4()),
            email="dave.viewer@trustvault.local",
            hashed_password=hash_password("DavePass123!"),
            full_name="Dave Chen (Senior Financial Analyst)",
            role="viewer",
            is_active=True,
            token_version=1,
        )

        db.add_all([admin, alice, carol, bob, dave])
        db.commit()

        # Record User Creation Audit Events
        record_audit_event(
            db=db,
            actor_email="system@trustvault.local",
            actor_role="system",
            action="SYSTEM_INIT",
            target_type="SYSTEM",
            target_id="genesis",
            ip_address="127.0.0.1",
            status="SUCCESS",
            details={"message": "TrustVault Cryptographic Vault Initialized"},
        )

        # 2. Seed Encrypted Confidential Documents
        docs_to_seed = [
            {
                "title": "Executive Salary Review & Compensation 2026",
                "description": "Board-level executive base pay, equity bonuses, and retention allowances for FY2026.",
                "category": "HR",
                "classification": "Confidential",
                "owner": alice,
                "filename": "Executive_Salary_Review_2026.pdf",
                "content": b"%PDF-1.5\n%TrustVault Confidential Executive Payroll Document\nEmployee: CEO - Base: $450,000 Bonus: $250,000\nEmployee: CTO - Base: $400,000 Bonus: $200,000\n%%EOF",
                "shared_with": [(dave, "read")],  # Dave has read access
            },
            {
                "title": "Series C Acquisition Term Sheet",
                "description": "Definitive agreement terms, representations, warranties, and indemnification caps.",
                "category": "Legal",
                "classification": "Restricted",
                "owner": carol,
                "filename": "Series_C_TermSheet_Acquisition.pdf",
                "content": b"%PDF-1.5\n%TrustVault Restricted Legal Acquisition Term Sheet\nValuation: $120,000,000\nInvestor Syndicate: Horizon Capital Partners\n%%EOF",
                "shared_with": [(bob, "edit")],  # Bob has edit access
            },
            {
                "title": "Internal Audit Findings Q3 - SOC2 Compliance",
                "description": "Internal security control gaps, penetration test findings, and remediation plan.",
                "category": "Compliance",
                "classification": "Restricted",
                "owner": carol,
                "filename": "Internal_Audit_Findings_Q3.pdf",
                "content": b"%PDF-1.5\n%TrustVault Internal SOC2 Audit Working Papers\nControls evaluated: 48, Gaps: 0\n%%EOF",
                "shared_with": [],  # Strictly private to Carol
            },
        ]

        for doc_meta in docs_to_seed:
            doc_id = str(uuid.uuid4())
            content = doc_meta["content"]
            sha256_hash = compute_sha256(content)

            # Encrypt and write to vault storage
            encrypted_bytes = encrypt_file_data(content)
            storage_path = VAULT_STORAGE_DIR / f"{doc_id}.enc"
            with open(storage_path, "wb") as f:
                f.write(encrypted_bytes)

            doc = Document(
                id=doc_id,
                title=doc_meta["title"],
                description=doc_meta["description"],
                category=doc_meta["category"],
                classification=doc_meta["classification"],
                owner_id=doc_meta["owner"].id,
                original_filename=doc_meta["filename"],
                storage_path=str(storage_path),
                file_size_bytes=len(content),
                mime_type="application/pdf",
                sha256_hash=sha256_hash,
                is_deleted=False,
            )
            db.add(doc)
            db.commit()

            record_audit_event(
                db=db,
                actor_email=doc_meta["owner"].email,
                actor_role=doc_meta["owner"].role,
                actor_id=doc_meta["owner"].id,
                action="DOCUMENT_UPLOAD",
                target_type="DOCUMENT",
                target_id=doc.id,
                ip_address="127.0.0.1",
                status="SUCCESS",
                details={"title": doc.title, "filename": doc.original_filename, "sha256": sha256_hash},
            )

            # Grant shared permissions
            for target_user, level in doc_meta["shared_with"]:
                perm = Permission(
                    document_id=doc.id,
                    user_id=target_user.id,
                    permission_level=level,
                    granted_by=doc_meta["owner"].id,
                )
                db.add(perm)
                db.commit()

                record_audit_event(
                    db=db,
                    actor_email=doc_meta["owner"].email,
                    actor_role=doc_meta["owner"].role,
                    actor_id=doc_meta["owner"].id,
                    action="PERMISSION_GRANT",
                    target_type="PERMISSION",
                    target_id=perm.id,
                    ip_address="127.0.0.1",
                    status="SUCCESS",
                    details={
                        "document_id": doc.id,
                        "document_title": doc.title,
                        "granted_to": target_user.email,
                        "permission_level": level,
                    },
                )

        print("TrustVault seeding completed successfully.")

    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
