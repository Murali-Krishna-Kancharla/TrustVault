# TrustVault — Secure Confidential Document Platform

> **"A security problem wearing the clothes of a CRUD application."**  
> TrustVault is an enterprise document security platform engineered around three non-negotiable guarantees: **the server decides on every request**, **the audit trail is cryptographically tamper-evident**, and **revocation takes effect immediately**.

---

## 1. The Three Non-Negotiable Standards

| Standard | Architectural Guarantee | Implementation in TrustVault |
| :--- | :--- | :--- |
| **1. Server Decides Every Time** | No document is reachable without server-side verification. Never client-side hiding. Through any route (API, direct UUID, IDOR probe). | Every single document access endpoint executes `verify_document_access()` in the active database transaction. Files are stored as AES-256-GCM encrypted chunks outside webroot and streamed only after full authorization. |
| **2. Cryptographic Proof of Access & Denial** | Every action and refused attempt is recorded. The audit trail cannot be quietly altered or deleted. | Merkle/blockchain-style SHA-256 hash chaining where record $N$ binds to record $N-1$ and is signed with server HMAC. Any altered byte breaks chain continuity and is flagged by `/api/audit/verify`. |
| **3. Immediate Revocation** | Revoking access works instantly. Whatever was issued before that moment stops working immediately. | Zero long-lived download URLs or pre-signed tokens. Permission deletions commit immediately via ACID database transactions. Session epochs (`token_version`) immediately invalidate active tokens upon user deactivation. |

---

## 2. Seed Accounts & Credentials

The system initializes automatically on startup with pre-seeded users and confidential documents.

| Role | Email | Password | Intended Function |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin@trustvault.local` | `AdminPass123!` | SecOps Governance, user lifecycle, audit trail review, tamper verification. *(Cannot read confidential documents without explicit grant).* |
| **Document Owner 1** | `alice.owner@trustvault.local` | `AlicePass123!` | Head of HR. Owns `Executive_Salary_Review_2026.pdf`. Grants & revokes access. |
| **Document Owner 2** | `carol.owner@trustvault.local` | `CarolPass123!` | General Counsel. Owns `Series_C_TermSheet_Acquisition.pdf` and `Internal_Audit_Findings_Q3.pdf`. |
| **Viewer 1** | `bob.viewer@trustvault.local` | `BobPass123!` | External Auditor. Has `edit` grant on Carol's Term Sheet; zero access to Alice's Salary Review. |
| **Viewer 2** | `dave.viewer@trustvault.local` | `DavePass123!` | Financial Analyst. Has `read` grant on Alice's Salary Review; zero access to Legal Term Sheet. |

*(The web interface includes a 1-click **Demo Role Switcher** in the top navigation bar for instant testing during evaluation).*

---

## 3. Quick Start & Deployment Instructions

### Prerequisites
- Python 3.11+
- Git

### Option A: Local Run (Clean Clone)
```bash
# 1. Clone repository
git clone <repository_url>
cd trustvault

# 2. Create virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy environment configuration
cp .env.example .env

# 5. Launch application (Database schema and seed data are created automatically)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Open **`http://localhost:8000`** in your browser.

### Option B: Docker Compose
```bash
docker compose up --build
```
Access the application at **`http://localhost:8000`**.

---

## 4. Running Automated Tests

TrustVault includes a comprehensive security regression suite covering all attack vectors detailed in [`THREATS.md`](file:///C:/Users/krish/.gemini/antigravity/scratch/trustvault/THREATS.md):

```bash
# Run the test suite with verbose output
python -m pytest tests/test_security.py -v
```

### Verified Test Cases (25 Tests)
1. `test_unauthenticated_request_blocked`: Unauthenticated requests to documents return 401.
2. `test_viewer_role_cannot_upload_documents`: Viewers cannot upload documents (returns 403).
3. `test_admin_cannot_download_unshared_confidential_document`: Administrators cannot read confidential documents without explicit grant (Separation of Duties).
4. `test_viewer_cannot_view_unshared_document_metadata`: Bob cannot view Alice's salary metadata (returns 403).
5. `test_viewer_cannot_download_unshared_document`: Bob cannot download Alice's salary document via IDOR (returns 403, 0 bytes streamed).
6. `test_unauthorized_download_logged_as_refused`: Every unauthorized access attempt is immutably logged as `REFUSED` in the audit ledger.
7. `test_read_only_viewer_cannot_edit_document`: User with `read` permission cannot update document metadata (returns 403).
8. `test_non_owner_cannot_delete_document`: Non-owners cannot delete documents (returns 403).
9. `test_viewer_cannot_grant_permissions`: Viewers cannot grant permissions to other users (returns 403).
10. `test_immediate_revocation_enforced`: Owner grants access $\to$ Viewer downloads $\to$ Owner revokes $\to$ Viewer retries download with same token and is instantly blocked (returns 403).
11. `test_search_isolation_prevents_metadata_leakage`: Searching does not reveal existence, counts, or titles of unshared documents.
12. `test_audit_chain_validity`: Cryptographic verification confirms ledger integrity from genesis to current head.
13. `test_audit_chain_detects_database_tampering`: Directly modifying an audit record in the database causes verification to fail and identifies the tampered record.
14. `test_files_stored_encrypted_on_disk`: Files on disk in `vault_storage/` are AES-256-GCM ciphertexts; reading raw bytes does not expose plaintext.
15. `test_upload_blocks_executable_disguised_as_pdf`: Windows PE binary (`MZ`) disguised as `.pdf` is rejected with 400 Bad Request.
16. `test_upload_blocks_linux_elf_binary`: Linux ELF executable is rejected with 400.
17. `test_upload_blocks_script_injection`: Files containing script tags are rejected.
18. `test_upload_accepts_valid_pdf`: Genuine PDF uploads succeed and are encrypted at rest.
19. `test_user_deactivation_immediately_invalidates_active_token`: Deactivating a user immediately invalidates their active JWT token on the next request.
20. `test_ai_advisory_never_widens_access_autonomously`: AI assistant provides suggestions but never modifies the permissions table without human confirmation.
21. `test_path_traversal_in_filename_sanitized`: Directory traversal sequences (`../../`) in filenames are stripped.
22. `test_viewer_forbidden_from_reading_audit_trail`: Viewers cannot inspect audit records (returns 403).
23. `test_expired_or_forged_jwt_token_rejected`: Tampered or forged JWT tokens are rejected with 401.
24. `test_audit_chain_detects_hash_link_breakage`: Modifying `prev_hash` to splice logs is detected.
25. `test_cannot_grant_permission_on_unowned_document`: Owners cannot grant permissions on documents they do not own.

---

## 5. Permissions & Authorization Model

TrustVault implements an explicit, per-document Role-Based & Attribute-Based Access Control (RBAC/ABAC) engine:

### 1. Document Ownership
- The user who uploads a document is its **Owner**.
- Owners have full rights: View Metadata, Download Decrypted File, Update Metadata, Delete Document, Grant Permissions to named users, and Revoke Permissions immediately.

### 2. Explicit Collaborator Grants
- Access is granted **per-document to named individuals** (no transitive folder inheritance).
- **`read`**: May view document metadata and download the decrypted file. Cannot edit or delete.
- **`edit`**: May view, download, and update metadata or upload new versions. Cannot manage permissions or delete.

### 3. Separation of Duties (Administrator Role)
- In enterprise security, IT administrators must not have automatic backdoor access to confidential files (e.g. executive payroll, whistleblower reports).
- In TrustVault, **Administrators govern platform health, inspect the audit ledger, and manage user accounts, but CANNOT view or download confidential documents without an explicit grant from the Document Owner**.

---

## 6. Cryptographic Tamper-Evident Audit Ledger

### Mathematical Chaining Formulation
For every event $i$:
$$\text{canonical\_payload}_i = \text{prev\_hash}_i \mathbin{\Vert} \text{timestamp}_i \mathbin{\Vert} \text{actor\_id}_i \mathbin{\Vert} \text{action}_i \mathbin{\Vert} \text{target\_id}_i \mathbin{\Vert} \text{status}_i \mathbin{\Vert} \text{details}_i$$
$$\text{record\_hash}_i = \text{SHA-256}(\text{canonical\_payload}_i)$$
$$\text{signature}_i = \text{HMAC-SHA256}(K_{\text{audit}}, \text{record\_hash}_i)$$
$$\text{prev\_hash}_{i+1} = \text{record\_hash}_i$$

- **Genesis Record:** Record #1 has $\text{prev\_hash} = 0^{64}$.
- **Immutability Guarantee:** If an attacker modifies any column of row $k$ in the database, $\text{SHA-256}(\text{row}_k) \neq \text{record\_hash}_k$. If the attacker recalculates $\text{record\_hash}_k$, the signature fails because they lack $K_{\text{audit}}$. If they attempt to rewrite subsequent rows, $\text{prev\_hash}_{k+1} \neq \text{record\_hash}_k$.

---

## 7. API Documentation & Authorization Matrix

| Method | Endpoint | Allowed Roles | Required Permission | Description |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/login` | Anyone | None | Authenticate credentials, return JWT with session epoch |
| `GET` | `/api/auth/me` | Authenticated | Active User | Get profile of currently authenticated user |
| `GET` | `/api/auth/users` | Authenticated | Active User | List active users for collaborator picker |
| `POST` | `/api/documents/upload` | `owner`, `admin` | Owner/Admin | Validate magic bytes, encrypt AES-GCM, store in vault |
| `GET` | `/api/documents` | Authenticated | Object-level filter | Search & list documents user owns or has grants for |
| `GET` | `/api/documents/{id}` | Authenticated | `read` / `edit` / `owner` | Get document metadata and classification |
| `GET` | `/api/documents/{id}/download` | Authenticated | `read` / `edit` / `owner` | Stream decrypted document with hardened headers |
| `PUT` | `/api/documents/{id}` | Authenticated | `edit` / `owner` | Update title, description, category, classification |
| `DELETE` | `/api/documents/{id}` | Authenticated | `owner` only | Delete document and securely remove encrypted storage blob |
| `GET` | `/api/documents/{id}/permissions` | Authenticated | `owner`, `admin` | View access control list for document |
| `POST` | `/api/documents/{id}/permissions` | Authenticated | `owner` only | Grant `read` or `edit` to named user; commit to ledger |
| `DELETE` | `/api/documents/{id}/permissions/{user_id}` | Authenticated | `owner` only | **Immediate Revocation**: Delete permission row instantly |
| `POST` | `/api/documents/{id}/permissions/ai-recommend` | Authenticated | `owner` only | AI advisory recommendation (human must confirm) |
| `GET` | `/api/audit` | `admin`, `owner` | Admin or Doc Owner | Query tamper-evident audit ledger with filters |
| `GET` | `/api/audit/verify` | Authenticated | Active User | Execute cryptographic verification of the entire ledger |
| `GET` | `/api/admin/dashboard` | `admin` | Admin role only | Administrative overview of stats, refused attempts, alerts |
| `POST` | `/api/admin/users/{user_id}/status` | `admin` | Admin role only | Activate/Deactivate user; increment `token_version` |

---

## 8. Five-Minute Demo Video Walkthrough Guide

When presenting or recording the 5-minute demo, follow this sequence:

1. **Minute 0:00 - 0:45: The Problem & The Non-Negotiables**
   - Explain the core motivation: Permissions creep (folder sprawl) and the inability to answer "who opened this and when" after a leak.
   - Introduce the three guarantees: Server decides every time, cryptographic proof, and immediate revocation.
2. **Minute 0:45 - 1:45: Document Vault & Isolation**
   - Log in as **Alice (Owner)** using the quick-switcher.
   - Show `Executive_Salary_Review_2026.pdf` (Confidential HR).
   - Switch to **Bob (External Auditor)**: The salary document is completely invisible in the vault and search yields zero results (zero metadata leakage).
3. **Minute 1:45 - 2:45: The Attack & The Refusal Invariant**
   - As Bob, open the **Security Attack Simulator** tab and execute the **Direct Object Reference (IDOR) Bypass**.
   - Show the resulting `HTTP 403 Forbidden` response.
   - Switch to the **Audit Trail** tab: point out the immediate red `REFUSED` badge logging Bob's IP, user ID, timestamp, and target document.
4. **Minute 2:45 - 3:45: Immediate Revocation Proof**
   - Show Alice granting Dave read access to the Salary Review. Dave downloads it.
   - Alice clicks **Revoke Access**.
   - Dave immediately retries the download in the same session: blocked instantly with `HTTP 403 Forbidden`. Explain why S3 pre-signed URLs or JWT permission caching fail this test and how TrustVault succeeds.
5. **Minute 3:45 - 5:00: Cryptographic Tamper-Proof Chain & AI Safety**
   - Click **Verify Ledger Cryptographic Integrity**: show the verification engine proving all records match their SHA-256 links and HMAC signatures.
   - Show the **AI Access Advisor**: show AI suggesting collaborators based on document classification, emphasizing that the machine **never** widens access on its own and requires explicit human confirmation.

---

## 9. Engineering Reflection & Write-Up

### What We Built
We built a resilient, zero-trust document security platform featuring:
- Per-request database authorization checks inside active ACID transactions.
- AES-256-GCM symmetric encryption for all files stored at rest.
- Magic byte inspection and binary signature filtering to block disguised executables and polyglot files.
- A cryptographic hash-chained audit ledger with HMAC signing and an on-demand verification engine.
- Session epoch tracking (`token_version`) for immediate user deactivation.
- A modern glassmorphism web console with a built-in Attack Simulator and role switcher.

### What We Deliberately Did Not Build (And Why)
1. **Folder-Level Permission Inheritance:**
   - *Rationale:* As the prompt noted, permissions go wrong when *"someone is given access to a folder so they can see one file, and they can now see forty."* Folder inheritance is the leading cause of transitive over-permissioning. By strictly enforcing explicit, per-document grants, we eliminate accidental lateral leakage.
2. **S3 Pre-Signed URLs:**
   - *Rationale:* Pre-signed URLs are immutable capabilities valid until expiration. If an owner revokes access at minute 1 of a 15-minute token, the recipient can still download. We chose authenticated server-side streaming to guarantee zero-delay revocation.
3. **Administrator Master Backdoor:**
   - *Rationale:* Most CRUD applications grant `admin` full read access. We deliberately severed administrative management from confidential document contents to maintain strict Separation of Duties.

### How We Used AI & Where It Was Wrong
AI was utilized across design and scaffolding, but was repeatedly challenged and corrected when it proposed flawed security patterns:
- In `PROMPTS.md` Entry 1, the AI proposed pre-signed URLs with a 15-minute expiration, which violated the Immediate Revocation standard. We rejected it in favor of authenticated streaming.
- In `PROMPTS.md` Entry 2, the AI proposed simple database inserts for audit logs, which could be altered by a rogue DB admin. We replaced it with a SHA-256 hash-chained ledger.
- In `PROMPTS.md` Entry 3, the AI gave administrators wildcard read access, which violated Separation of Duties. We enforced document-level ownership grants.
- In `PROMPTS.md` Entry 5, the AI trusted client `Content-Type` headers. We replaced it with binary magic byte validation.

TrustVault demonstrates that true software security is not achieved by hiding buttons on a UI, but by enforcing mathematical, cryptographic, and architectural invariants on the server on every single request.
