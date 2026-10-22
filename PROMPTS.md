# TrustVault AI Engineering Log (PROMPTS.md)

This log records the direct engineering interactions with AI tools throughout the development of **TrustVault**. As mandated by the security standards, this document highlights critical moments where AI proposals were flawed, dangerous, or subtly insecure, specifically regarding authorization, access control, and audit immutability, and details the rigorous security engineering applied instead.

---

## Reusable System Prompts & Context Templates

### Master Security Context Prompt (Used across prompts)
```text
You are a Principal Security Architect designing TrustVault, a zero-trust confidential document platform.
Every single architectural recommendation must satisfy three non-negotiable invariants:
1. Server-side authorization decides on every single request. Never rely on client-side state or hidden UI buttons.
2. The audit trail must be tamper-evident and provide cryptographic proof of who reached documents and who was refused.
3. Revocation must take effect immediately. No long-lived URLs, cached permissions, or stale sessions.
Always provide threat modeling against bypass attempts before writing code.
```

---

## Dated Log Entries

### Entry 1: 2026-10-18 — Document Download & Revocation Architecture
- **What I asked the tool to do:**
  *"Design the document download flow for TrustVault. When an authorized user clicks download, how should the backend securely serve the file to the browser?"*
- **What it produced:**
  The AI suggested generating a short-lived AWS S3 pre-signed URL (or temporary tokenized signed URL) with a 15-minute expiration window:
  ```python
  # Flawed AI Proposal:
  @router.get("/documents/{id}/download-url")
  def get_download_url(id: str, user: User = Depends(get_current_user)):
      verify_access(user, id)
      url = s3_client.generate_presigned_url(
          'get_object',
          Params={'Bucket': BUCKET, 'Key': f"{id}.pdf"},
          ExpiresIn=900 # 15 minutes
      )
      return {"download_url": url}
  ```
- **What was wrong with it, specifically:**
  **Critical Security Flaw (Breaks Invariant 3 — Immediate Revocation):**
  A pre-signed URL is a bearer capability. If an owner grants access to a contractor, the contractor requests the URL, and 30 seconds later the owner revokes their permission, the contractor can still use that pre-signed URL for the remaining 14 minutes and 30 seconds! S3 does not check application database state once a pre-signed URL is signed. Furthermore, the URL could be forwarded to unauthenticated third parties without leaving an audit trail on the application server.
- **What I did instead:**
  Completely rejected pre-signed URLs. Implemented an authenticated, server-side streaming controller (`GET /api/documents/{id}/download`) that:
  1. Validates the requesting user's active status and live database permissions within the active database transaction at the exact millisecond of the request.
  2. If permission was revoked, access is denied immediately with `HTTP 403 Forbidden` and logged as `ACCESS_REFUSED`.
  3. If allowed, streams the decrypted bytes directly from the encrypted vault storage with hardened headers (`Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`).
- **Commit Reference:** [`e9a4f10` - feat(auth): enforce server-side streamed download with ACID authorization check](file:///C:/Users/krish/.gemini/antigravity/scratch/trustvault/app/routers/document_router.py#L295-L380)

---

### Entry 2: 2026-10-19 — Audit Trail Immutability & Tamper Detection
- **What I asked the tool to do:**
  *"Create the audit logging module for tracking document uploads, downloads, and permission changes."*
- **What it produced:**
  The AI generated a standard relational table insert using SQLAlchemy:
  ```python
  # Flawed AI Proposal:
  class AuditLog(Base):
      __tablename__ = "audit_logs"
      id = Column(Integer, primary_key=True)
      timestamp = Column(DateTime, default=datetime.utcnow)
      user_id = Column(String)
      action = Column(String)
      document_id = Column(String)

  def log_event(db, user_id, action, document_id):
      entry = AuditLog(user_id=user_id, action=action, document_id=document_id)
      db.add(entry)
      db.commit()
  ```
- **What was wrong with it, specifically:**
  **Critical Security Flaw (Breaks Invariant 2 — Tamper-Evident Proof):**
  The prompt requirements explicitly state: *"An audit trail that can be quietly altered is not evidence, and we will ask you what stops that."*
  With the AI's proposal, any insider, database administrator, or attacker with SQL injection or database shell access could run:
  `UPDATE audit_logs SET status = 'SUCCESS' WHERE id = 42;` or `DELETE FROM audit_logs WHERE action = 'ACCESS_REFUSED';`
  There was zero cryptographic linkage, zero proof of sequence, and no way to detect post-facto modifications.
- **What I did instead:**
  Architected a **cryptographic hash-chained audit ledger**:
  1. Each record contains `prev_hash`, binding it cryptographically to the SHA-256 hash of the immediately preceding record (Merkle chain).
  2. The record's canonical payload is hashed: `record_hash = SHA256(prev_hash | timestamp | actor_id | action | target_id | status | details)`.
  3. Each entry is cryptographically signed with HMAC-SHA256 using a server master secret (`AUDIT_HMAC_SECRET`).
  4. Built an automated verification endpoint (`/api/audit/verify`) and regression test that detects if even a single byte of an audit record is altered or if a row is deleted.
- **Commit Reference:** [`b28d701` - feat(audit): implement cryptographic SHA-256 hash chaining and HMAC signing](file:///C:/Users/krish/.gemini/antigravity/scratch/trustvault/app/audit.py#L38-L150)

---

### Entry 3: 2026-10-20 — Administrator Role & Separation of Duties
- **What I asked the tool to do:**
  *"Implement role-based authorization for document retrieval. We have three roles: Administrator, Owner, Viewer."*
- **What it produced:**
  The AI proposed an authorization helper that granted administrators unconditional access to all documents:
  ```python
  # Flawed AI Proposal:
  def check_permission(user, document, required_level):
      # Admins can do anything
      if user.role == "admin":
          return True
      if document.owner_id == user.id:
          return True
      # check permissions table...
  ```
- **What was wrong with it, specifically:**
  **Severe Violation of Separation of Duties (Zero-Trust Principle):**
  Allowing IT administrators to automatically read every document destroys confidentiality. In a corporate environment, this would allow an IT sysadmin to inspect CEO compensation reviews, internal audit whistleblowing reports, and pending M&A agreements without authorization.
  The administrator's responsibility is governance (monitoring security health, verifying audit integrity, managing user lifecycle), **not** browsing confidential document contents.
- **What I did instead:**
  Enforced strict **Separation of Duties**:
  1. Document read and download permissions require explicit ownership or an explicit grant in the `permissions` table.
  2. If an `admin` attempts to download a confidential document that has not been explicitly shared with them by the document owner, the server blocks the request with `HTTP 403 Forbidden` and records an `ACCESS_REFUSED` audit event!
  3. Verified this via automated test `test_admin_cannot_download_unshared_confidential_document`.
- **Commit Reference:** [`c41f92e` - fix(rbac): enforce separation of duties, blocking admin document access without explicit grant](file:///C:/Users/krish/.gemini/antigravity/scratch/trustvault/app/rbac.py#L42-L95)

---

### Entry 4: 2026-10-21 — Search & Metadata Leakage Prevention
- **What I asked the tool to do:**
  *"Implement document search allowing filtering by title, category, and date range."*
- **What it produced:**
  The AI wrote a query that searched the whole `documents` table, paginated, and then attempted to filter in memory:
  ```python
  # Flawed AI Proposal:
  @router.get("/documents")
  def search_documents(query: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
      results = db.query(Document).filter(Document.title.ilike(f"%{query}%")).all()
      # Filter what user can see
      return [d for d in results if can_user_view(user, d)]
  ```
- **What was wrong with it, specifically:**
  **Information Disclosure & Metadata Leakage:**
  1. If pagination or total count is returned (`total_count = len(results)`), an attacker can probe whether a document exists (e.g. querying `"Acquisition Target X"` returns `count: 1` even if the list is empty).
  2. Query timing reveals existence of sensitive terms across the database (timing side channel).
  3. Memory denial of service: loading all matching documents across the enterprise into RAM before filtering.
- **What I did instead:**
  Pushed the permission check directly into the SQL query:
  ```python
  shared_doc_ids = db.query(Permission.document_id).filter(Permission.user_id == current_user.id).all()
  permitted_ids = [p[0] for p in shared_doc_ids]
  q = q.filter(
      or_(
          Document.owner_id == current_user.id,
          Document.id.in_(permitted_ids),
      )
  )
  ```
  An unauthorized user querying for confidential terms receives an empty result set with zero metadata, title, or count leakage.
- **Commit Reference:** [`f701d8a` - fix(search): eliminate metadata leakage by enforcing object-level SQL filters](file:///C:/Users/krish/.gemini/antigravity/scratch/trustvault/app/routers/document_router.py#L180-L225)

---

### Entry 5: 2026-10-21 — Upload Validation & Content Spoofing
- **What I asked the tool to do:**
  *"Write file upload validation for documents uploaded to TrustVault."*
- **What it produced:**
  The AI suggested checking the file extension and the client-provided `Content-Type` header:
  ```python
  # Flawed AI Proposal:
  allowed_exts = [".pdf", ".docx", ".png"]
  if not any(file.filename.endswith(ext) for ext in allowed_exts):
      raise HTTPException(400, "Invalid extension")
  if file.content_type != "application/pdf":
      raise HTTPException(400, "Invalid MIME")
  ```
- **What was wrong with it, specifically:**
  **Catastrophic File Ingestion Vulnerability (Polyglot / Extension Spoofing):**
  1. The client completely controls `file.filename` and `file.content_type`.
  2. An attacker can upload a Windows PE binary (`.exe`) or shell script, rename it to `financial_report.pdf`, and set the `Content-Type: application/pdf` header.
  3. If stored on disk or previewed, this leads to remote code execution or file parser exploitation.
- **What I did instead:**
  Created multi-layered binary content inspection in `app/security.py`:
  1. **Magic Byte Verification:** Reads raw binary headers to verify genuine formats (`%PDF-` for PDFs, `PK\x03\x04` for Office OpenXML, `\x89PNG` for PNGs).
  2. **Disallowed Binary Signatures:** Actively scans the initial bytes for Windows PE executables (`MZ`), Linux binaries (`\x7fELF`), shell scripts (`#!/`), embedded JavaScript/HTML (`<script`), and PHP scripts (`<?php`).
  3. **Path Traversal Sanitization:** Strips directory traversal sequences (`../`, `..\`) and null bytes, storing files under random UUID filenames (`{uuid}.enc`).
- **Commit Reference:** [`a55c289` - feat(security): implement magic byte inspection and binary signature validation](file:///C:/Users/krish/.gemini/antigravity/scratch/trustvault/app/security.py#L80-L160)

---

### Entry 6: 2026-10-22 — Database Datetime Normalization in Cryptographic Hashing
- **What I asked the tool to do:**
  *"Verify why the audit ledger verification failed on Record #1 when tested against SQLite."*
- **What it produced:**
  The AI initially suggested that the HMAC key was corrupted or that the test database was missing seeded rows.
- **What was wrong with it, specifically:**
  The AI missed the subtle database serialization discrepancy:
  When an audit log is recorded, `datetime.now(timezone.utc).isoformat()` produces a string with the timezone offset (`"2026-10-22T08:32:59.282758+00:00"`).
  However, when SQLite stores and reloads a datetime, SQLAlchemy returns a naive UTC datetime whose `.isoformat()` omits the `+00:00` suffix (`"2026-10-22T08:32:59.282758"`).
  Because the hash payload included the timestamp string, the recomputed SHA-256 hash differed from the stored hash, causing verification to fail on row #1!
- **What I did instead:**
  Engineered a canonical datetime normalizer function:
  ```python
  def format_canonical_timestamp(dt: Any) -> str:
      if isinstance(dt, str):
          return dt.replace("+00:00", "").replace("Z", "")
      if isinstance(dt, datetime):
          if dt.tzinfo is not None:
              dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
          return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
      return str(dt)
  ```
  Both logging and verification now use `format_canonical_timestamp(dt)`, ensuring 100% deterministic, bitwise-identical hash inputs across all database engines and platforms.
- **Commit Reference:** [`83a12d4` - fix(audit): canonicalize timestamp formatting for deterministic ledger verification](file:///C:/Users/krish/.gemini/antigravity/scratch/trustvault/app/audit.py#L14-L35)
