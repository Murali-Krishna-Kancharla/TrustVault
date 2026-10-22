import os
import json
import pytest
from io import BytesIO
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import User, Document, Permission, AuditLog
from app.audit import verify_audit_integrity

def get_auth_token(client: TestClient, email: str, password: str) -> str:
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, f"Failed to login {email}: {res.text}"
    return res.json()["access_token"]

# -------------------------------------------------------------
# 1. AUTHENTICATION & ROLE ENFORCEMENT
# -------------------------------------------------------------

def test_unauthenticated_request_blocked(client: TestClient):
    """Unauthenticated users cannot access documents."""
    res = client.get("/api/documents")
    assert res.status_code == 401

def test_viewer_role_cannot_upload_documents(client: TestClient):
    """Viewers cannot upload documents (only owners and administrators can)."""
    bob_token = get_auth_token(client, "bob.viewer@trustvault.local", "BobPass123!")
    fake_pdf = b"%PDF-1.4\nSample content"
    files = {"file": ("test.pdf", BytesIO(fake_pdf), "application/pdf")}
    data = {"title": "Viewer Upload Attempt", "category": "General", "classification": "Internal"}
    
    res = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {bob_token}"},
        files=files,
        data=data,
    )
    assert res.status_code == 403
    assert "Viewers are not permitted to upload" in res.json()["detail"]

def test_admin_cannot_download_unshared_confidential_document(client: TestClient, db_session: Session):
    """
    Separation of Duties (Zero-Trust):
    Administrators govern the platform and inspect audit logs,
    but CANNOT download confidential documents without an explicit grant.
    """
    admin_token = get_auth_token(client, "admin@trustvault.local", "AdminPass123!")
    
    # Alice's confidential salary review
    salary_doc = db_session.query(Document).filter(Document.title.like("%Salary%")).first()
    assert salary_doc is not None

    res = client.get(
        f"/api/documents/{salary_doc.id}/download",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 403
    assert "Forbidden" in res.json()["detail"]

# -------------------------------------------------------------
# 2. ISOLATION & OBJECT-LEVEL AUTHORIZATION (NEGATIVE TESTS)
# -------------------------------------------------------------

def test_viewer_cannot_view_unshared_document_metadata(client: TestClient, db_session: Session):
    """Bob (Viewer) cannot view metadata of Alice's confidential salary document."""
    bob_token = get_auth_token(client, "bob.viewer@trustvault.local", "BobPass123!")
    salary_doc = db_session.query(Document).filter(Document.title.like("%Salary%")).first()

    res = client.get(
        f"/api/documents/{salary_doc.id}",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert res.status_code == 403

def test_viewer_cannot_download_unshared_document(client: TestClient, db_session: Session):
    """Bob (Viewer) cannot download Alice's salary document via direct IDOR."""
    bob_token = get_auth_token(client, "bob.viewer@trustvault.local", "BobPass123!")
    salary_doc = db_session.query(Document).filter(Document.title.like("%Salary%")).first()

    res = client.get(
        f"/api/documents/{salary_doc.id}/download",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert res.status_code == 403
    assert "Forbidden" in res.json()["detail"]

def test_unauthorized_download_logged_as_refused(client: TestClient, db_session: Session):
    """Every unauthorized access attempt is immutably logged as REFUSED in the audit trail."""
    bob_token = get_auth_token(client, "bob.viewer@trustvault.local", "BobPass123!")
    salary_doc = db_session.query(Document).filter(Document.title.like("%Salary%")).first()

    # Trigger forbidden download
    client.get(
        f"/api/documents/{salary_doc.id}/download",
        headers={"Authorization": f"Bearer {bob_token}"},
    )

    # Check latest audit record
    last_log = db_session.query(AuditLog).order_by(AuditLog.id.desc()).first()
    assert last_log.status == "REFUSED"
    assert last_log.actor_email == "bob.viewer@trustvault.local"
    assert last_log.target_id == salary_doc.id
    assert last_log.action == "DOCUMENT_DOWNLOAD"

def test_read_only_viewer_cannot_edit_document(client: TestClient, db_session: Session):
    """Dave has 'read' permission on Alice's salary document, but cannot edit it."""
    dave_token = get_auth_token(client, "dave.viewer@trustvault.local", "DavePass123!")
    salary_doc = db_session.query(Document).filter(Document.title.like("%Salary%")).first()

    res = client.put(
        f"/api/documents/{salary_doc.id}",
        headers={"Authorization": f"Bearer {dave_token}"},
        json={"title": "Hacked Title"},
    )
    assert res.status_code == 403

def test_non_owner_cannot_delete_document(client: TestClient, db_session: Session):
    """Non-owners cannot delete documents, even if they have edit permission."""
    bob_token = get_auth_token(client, "bob.viewer@trustvault.local", "BobPass123!")
    term_doc = db_session.query(Document).filter(Document.title.like("%Term Sheet%")).first()

    res = client.delete(
        f"/api/documents/{term_doc.id}",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert res.status_code == 403

def test_viewer_cannot_grant_permissions(client: TestClient, db_session: Session):
    """Viewers cannot grant permissions to other users."""
    bob_token = get_auth_token(client, "bob.viewer@trustvault.local", "BobPass123!")
    term_doc = db_session.query(Document).filter(Document.title.like("%Term Sheet%")).first()
    dave = db_session.query(User).filter(User.email.like("%dave%")).first()

    res = client.post(
        f"/api/documents/{term_doc.id}/permissions",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={"user_id": dave.id, "permission_level": "read"},
    )
    assert res.status_code == 403

# -------------------------------------------------------------
# 3. IMMEDIATE REVOCATION
# -------------------------------------------------------------

def test_immediate_revocation_enforced(client: TestClient, db_session: Session):
    """
    Core Invariant: Taking access away works immediately.
    Whatever was issued before that moment stops working instantly.
    """
    carol_token = get_auth_token(client, "carol.owner@trustvault.local", "CarolPass123!")
    dave_token = get_auth_token(client, "dave.viewer@trustvault.local", "DavePass123!")
    dave = db_session.query(User).filter(User.email.like("%dave%")).first()
    term_doc = db_session.query(Document).filter(Document.title.like("%Term Sheet%")).first()

    # Step 1: Carol grants Dave 'read' permission
    grant_res = client.post(
        f"/api/documents/{term_doc.id}/permissions",
        headers={"Authorization": f"Bearer {carol_token}"},
        json={"user_id": dave.id, "permission_level": "read"},
    )
    assert grant_res.status_code == 201

    # Step 2: Dave downloads document successfully
    dl1 = client.get(
        f"/api/documents/{term_doc.id}/download",
        headers={"Authorization": f"Bearer {dave_token}"},
    )
    assert dl1.status_code == 200

    # Step 3: Carol immediately revokes Dave's permission
    revoke_res = client.delete(
        f"/api/documents/{term_doc.id}/permissions/{dave.id}",
        headers={"Authorization": f"Bearer {carol_token}"},
    )
    assert revoke_res.status_code == 200

    # Step 4: Dave IMMEDIATELY attempts to download again with the same token
    dl2 = client.get(
        f"/api/documents/{term_doc.id}/download",
        headers={"Authorization": f"Bearer {dave_token}"},
    )
    assert dl2.status_code == 403, "Revocation failed: user could still download document after access was revoked!"

# -------------------------------------------------------------
# 4. SEARCH ISOLATION & ZERO METADATA LEAKAGE
# -------------------------------------------------------------

def test_search_isolation_prevents_metadata_leakage(client: TestClient, db_session: Session):
    """
    Searching does not reveal titles, owners, or counts of documents
    the user does not have permission to reach.
    """
    bob_token = get_auth_token(client, "bob.viewer@trustvault.local", "BobPass123!")

    # Bob searches for "Salary"
    res = client.get(
        "/api/documents?query=Salary",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert res.status_code == 200
    results = res.json()
    assert len(results) == 0, "Search leaked confidential document title to unpermitted viewer!"

    # Listing all documents as Bob returns ONLY documents shared with Bob
    res_all = client.get(
        "/api/documents",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert res_all.status_code == 200
    all_docs = res_all.json()
    for d in all_docs:
        assert "Salary" not in d["title"]
        assert "Internal SOC2 Audit" not in d["title"]

# -------------------------------------------------------------
# 5. CRYPTOGRAPHIC TAMPER-EVIDENT AUDIT TRAIL
# -------------------------------------------------------------

def test_audit_chain_validity(client: TestClient):
    """Cryptographic verification confirms ledger integrity under normal operations."""
    admin_token = get_auth_token(client, "admin@trustvault.local", "AdminPass123!")
    res = client.get("/api/audit/verify", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["is_valid"] is True
    assert data["total_records"] > 0
    assert data["tampered_at_id"] is None

def test_audit_chain_detects_database_tampering(db_session: Session):
    """
    Tamper Detection:
    If a rogue administrator or attacker directly modifies a row in the database,
    verify_audit_integrity() detects it immediately and identifies the exact row!
    """
    # Verify currently clean
    is_valid_before, _, _, _ = verify_audit_integrity(db_session)
    assert is_valid_before is True

    # Maliciously modify row #2's details directly in SQLite
    target_row = db_session.query(AuditLog).filter(AuditLog.id == 2).first()
    if target_row:
        original_details = target_row.details
        target_row.details = '{"tampered": "hacked_value"}'
        db_session.commit()

        # Re-run verification
        is_valid_after, count, tampered_id, err_msg = verify_audit_integrity(db_session)
        assert is_valid_after is False
        assert tampered_id == 2
        assert "Payload tamper detected" in err_msg

        # Revert change to keep test environment clean
        target_row.details = original_details
        db_session.commit()

# -------------------------------------------------------------
# 6. ENCRYPTION AT REST
# -------------------------------------------------------------

def test_files_stored_encrypted_on_disk(db_session: Session):
    """
    Raw disk inspection proof:
    Files stored on disk are AES-256-GCM ciphertexts; reading them directly
    does not reveal confidential plaintext strings.
    """
    salary_doc = db_session.query(Document).filter(Document.title.like("%Salary%")).first()
    assert os.path.exists(salary_doc.storage_path)

    with open(salary_doc.storage_path, "rb") as f:
        disk_bytes = f.read()

    # Plaintext had "Employee: CEO - Base: $450,000"
    assert b"Employee: CEO" not in disk_bytes
    assert b"Bonus: $250,000" not in disk_bytes

# -------------------------------------------------------------
# 7. UPLOAD VALIDATION & MAGIC BYTES INSPECTION
# -------------------------------------------------------------

def test_upload_blocks_executable_disguised_as_pdf(client: TestClient):
    """Magic byte check prevents PE executables disguised as PDFs."""
    alice_token = get_auth_token(client, "alice.owner@trustvault.local", "AlicePass123!")
    
    # Windows PE executable magic bytes 'MZ'
    malicious_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00FakePEHeader"
    files = {"file": ("malware.pdf", BytesIO(malicious_bytes), "application/pdf")}
    data = {"title": "Invoice Disguise", "category": "Financial", "classification": "Confidential"}

    res = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {alice_token}"},
        files=files,
        data=data,
    )
    assert res.status_code == 400
    assert "executable or script pattern detected" in res.json()["detail"]

def test_upload_blocks_linux_elf_binary(client: TestClient):
    """Blocks ELF binary disguised as PDF."""
    alice_token = get_auth_token(client, "alice.owner@trustvault.local", "AlicePass123!")
    elf_bytes = b"\x7fELF\x02\x01\x01\x00FakeELF"
    files = {"file": ("tool.pdf", BytesIO(elf_bytes), "application/pdf")}
    data = {"title": "Tool Disguise", "category": "Engineering", "classification": "Internal"}

    res = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {alice_token}"},
        files=files,
        data=data,
    )
    assert res.status_code == 400

def test_upload_blocks_script_injection(client: TestClient):
    """Blocks files containing HTML script tags."""
    alice_token = get_auth_token(client, "alice.owner@trustvault.local", "AlicePass123!")
    script_bytes = b"<script>alert(1)</script>"
    files = {"file": ("report.pdf", BytesIO(script_bytes), "application/pdf")}
    data = {"title": "XSS Disguise", "category": "HR", "classification": "Internal"}

    res = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {alice_token}"},
        files=files,
        data=data,
    )
    assert res.status_code == 400

def test_upload_accepts_valid_pdf(client: TestClient):
    """Authentic PDF upload with correct magic bytes succeeds and is encrypted."""
    alice_token = get_auth_token(client, "alice.owner@trustvault.local", "AlicePass123!")
    valid_pdf_bytes = b"%PDF-1.7\nValid authentic confidential PDF content\n%%EOF"
    files = {"file": ("genuine.pdf", BytesIO(valid_pdf_bytes), "application/pdf")}
    data = {"title": "Genuine Strategic Plan", "category": "Legal", "classification": "Confidential"}

    res = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {alice_token}"},
        files=files,
        data=data,
    )
    assert res.status_code == 201
    assert res.json()["title"] == "Genuine Strategic Plan"

# -------------------------------------------------------------
# 8. USER DEACTIVATION & SESSION EPOCH REVOCATION
# -------------------------------------------------------------

def test_user_deactivation_immediately_invalidates_active_token(client: TestClient, db_session: Session):
    """
    Immediate User Revocation:
    When an admin deactivates a user, their existing JWT token is immediately rejected.
    """
    admin_token = get_auth_token(client, "admin@trustvault.local", "AdminPass123!")
    bob_token = get_auth_token(client, "bob.viewer@trustvault.local", "BobPass123!")
    bob = db_session.query(User).filter(User.email.like("%bob%")).first()

    # Bob can initially reach /api/documents
    res1 = client.get("/api/documents", headers={"Authorization": f"Bearer {bob_token}"})
    assert res1.status_code == 200

    # Admin deactivates Bob
    deact_res = client.post(
        f"/api/admin/users/{bob.id}/status",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"is_active": False},
    )
    assert deact_res.status_code == 200

    # Bob's existing token is immediately rejected on the very next request
    res2 = client.get("/api/documents", headers={"Authorization": f"Bearer {bob_token}"})
    assert res2.status_code in (401, 403)

    # Reactivate Bob for downstream tests
    client.post(
        f"/api/admin/users/{bob.id}/status",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"is_active": True},
    )

# -------------------------------------------------------------
# 9. AI ACCESS ADVISORY INVARIANT
# -------------------------------------------------------------

def test_ai_advisory_never_widens_access_autonomously(client: TestClient, db_session: Session):
    """
    AI Safety Invariant:
    Calling AI recommendation endpoint provides suggestions, but NEVER creates
    a row in the permissions table or widens access autonomously.
    """
    carol_token = get_auth_token(client, "carol.owner@trustvault.local", "CarolPass123!")
    term_doc = db_session.query(Document).filter(Document.title.like("%Term Sheet%")).first()

    perms_count_before = db_session.query(Permission).filter(Permission.document_id == term_doc.id).count()

    res = client.post(
        f"/api/documents/{term_doc.id}/permissions/ai-recommend",
        headers={"Authorization": f"Bearer {carol_token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "suggested_users" in data
    assert len(data["suggested_users"]) > 0

    # Verify database permissions table was NOT modified
    perms_count_after = db_session.query(Permission).filter(Permission.document_id == term_doc.id).count()
    assert perms_count_before == perms_count_after

# -------------------------------------------------------------
# 10. ADDITIONAL HIGH-IMPACT THREAT VECTORS
# -------------------------------------------------------------

def test_path_traversal_in_filename_sanitized(client: TestClient):
    """Filename path traversal (../../) is sanitized; does not escape storage directory."""
    alice_token = get_auth_token(client, "alice.owner@trustvault.local", "AlicePass123!")
    pdf_bytes = b"%PDF-1.4\nSafe content\n%%EOF"
    files = {"file": ("../../../../etc/passwd.pdf", BytesIO(pdf_bytes), "application/pdf")}
    data = {"title": "Path Traversal Probe", "category": "General", "classification": "Internal"}

    res = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {alice_token}"},
        files=files,
        data=data,
    )
    assert res.status_code == 201
    # Original filename should not contain path traversal ../ or ..\
    saved_filename = res.json()["original_filename"]
    assert ".." not in saved_filename
    assert "/" not in saved_filename
    assert "\\" not in saved_filename

def test_viewer_forbidden_from_reading_audit_trail(client: TestClient):
    """Viewers are strictly forbidden from inspecting the audit trail."""
    bob_token = get_auth_token(client, "bob.viewer@trustvault.local", "BobPass123!")
    res = client.get("/api/audit", headers={"Authorization": f"Bearer {bob_token}"})
    assert res.status_code == 403
    assert "Only administrators and document owners" in res.json()["detail"]

def test_expired_or_forged_jwt_token_rejected(client: TestClient):
    """A forged or tampered JWT token signature is rejected with 401."""
    tampered_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYiLCJyb2xlIjoiYWRtaW4ifQ.InVaLiD_SiGnAtUrE"
    res = client.get("/api/documents", headers={"Authorization": f"Bearer {tampered_token}"})
    assert res.status_code == 401

def test_audit_chain_detects_hash_link_breakage(db_session: Session):
    """
    If prev_hash of an audit record is altered (e.g. attempting to splice logs),
    verification immediately identifies broken hash chain continuity.
    """
    last_rec = db_session.query(AuditLog).order_by(AuditLog.id.desc()).first()
    if last_rec and last_rec.id > 1:
        orig_prev = last_rec.prev_hash
        last_rec.prev_hash = "f" * 64
        db_session.commit()

        is_valid, count, tampered_id, err = verify_audit_integrity(db_session)
        assert is_valid is False
        assert tampered_id == last_rec.id
        assert "Broken hash chain" in err

        last_rec.prev_hash = orig_prev
        db_session.commit()

def test_cannot_grant_permission_on_unowned_document(client: TestClient, db_session: Session):
    """Owner 2 (Carol) cannot grant permissions on Owner 1's (Alice) confidential document."""
    carol_token = get_auth_token(client, "carol.owner@trustvault.local", "CarolPass123!")
    salary_doc = db_session.query(Document).filter(Document.title.like("%Salary%")).first()
    bob = db_session.query(User).filter(User.email.like("%bob%")).first()

    res = client.post(
        f"/api/documents/{salary_doc.id}/permissions",
        headers={"Authorization": f"Bearer {carol_token}"},
        json={"user_id": bob.id, "permission_level": "read"},
    )
    assert res.status_code == 403

