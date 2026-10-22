# TrustVault Threat Model & Security Defense Matrix (THREATS.md)

This document details the threat landscape evaluated during the architecture, design, and implementation of **TrustVault**. It documents the identified attack vectors, our engineering mitigations, the automated regression tests enforcing them, and the specific trade-offs and risks we knowingly accepted.

---

## 1. Threat Matrix Overview

| Threat ID | Category | Attack Vector | Mitigated? | Test Mapping |
| :--- | :--- | :--- | :---: | :--- |
| **TV-THREAT-01** | Authorization | Insecure Direct Object Reference (IDOR) on Document Download | ✅ Yes | `test_viewer_cannot_download_unshared_document` |
| **TV-THREAT-02** | Authorization | IDOR on Document Metadata Read / Inspection | ✅ Yes | `test_viewer_cannot_view_unshared_document_metadata` |
| **TV-THREAT-03** | Authorization | Immediate Revocation Bypass via Stale Sessions / Pre-signed URLs | ✅ Yes | `test_immediate_revocation_enforced` |
| **TV-THREAT-04** | Audit Integrity | Silent Tampering or Modification of Audit Records in Database | ✅ Yes | `test_audit_chain_detects_database_tampering` |
| **TV-THREAT-05** | Audit Integrity | Audit Log Splicing / Deletion / Truncation | ✅ Yes | `test_audit_chain_detects_hash_link_breakage` |
| **TV-THREAT-06** | Information Leak | Metadata & Existence Leakage via Search Queries | ✅ Yes | `test_search_isolation_prevents_metadata_leakage` |
| **TV-THREAT-07** | Separation of Duties | Privileged Administrator Backdoor into Confidential Documents | ✅ Yes | `test_admin_cannot_download_unshared_confidential_document` |
| **TV-THREAT-08** | File Storage | Plaintext Extraction from Storage Disk via Infrastructure Compromise | ✅ Yes | `test_files_stored_encrypted_on_disk` |
| **TV-THREAT-09** | File Ingestion | Malicious Executable Disguised as PDF (Polyglot / Extension Spoof) | ✅ Yes | `test_upload_blocks_executable_disguised_as_pdf` |
| **TV-THREAT-10** | File Ingestion | Linux ELF Binary & Script Uploads disguised as documents | ✅ Yes | `test_upload_blocks_linux_elf_binary`, `test_upload_blocks_script_injection` |
| **TV-THREAT-11** | File Ingestion | Directory Traversal via Filename (`../../` or `..\`) | ✅ Yes | `test_path_traversal_in_filename_sanitized` |
| **TV-THREAT-12** | Authorization | Cross-Owner Permission Tampering | ✅ Yes | `test_cannot_grant_permission_on_unowned_document` |
| **TV-THREAT-13** | Privilege Escalation | Viewer elevating self to Document Editor or Owner | ✅ Yes | `test_read_only_viewer_cannot_edit_document`, `test_viewer_cannot_grant_permissions` |
| **TV-THREAT-14** | Account Takeover | Replay of Tokens from Deactivated / Compromised Accounts | ✅ Yes | `test_user_deactivation_immediately_invalidates_active_token` |
| **TV-THREAT-15** | Token Forgery | Forged / Unsigned JWT Claims | ✅ Yes | `test_expired_or_forged_jwt_token_rejected` |
| **TV-THREAT-16** | AI Safety | Autonomous Permission Widening by AI Recommendation Engine | ✅ Yes | `test_ai_advisory_never_widens_access_autonomously` |

---

## 2. Detailed Threat Analysis & Defenses

### TV-THREAT-01: Insecure Direct Object Reference (IDOR) on Document Download
- **Attack Scenario:** An external viewer (Bob) inspects the network traffic and discovers the UUID of a confidential executive salary sheet (`Executive_Salary_Review_2026.pdf`) owned by Alice. Bob issues `GET /api/documents/{uuid}/download` with his valid JWT.
- **Defensive Mechanism:** The download endpoint invokes `verify_document_access(document_id, "read", user, db)`. It checks the database table `permissions` for an active row matching `(document_id, user_id)`. If absent, access is denied. Crucially, the refusal is logged in the cryptographic audit trail as an `ACCESS_REFUSED` event with Bob's IP, user ID, and target document ID before raising `HTTP 403 Forbidden`. Zero bytes of the file stream are transmitted.
- **Test Reference:** `test_viewer_cannot_download_unshared_document`, `test_unauthorized_download_logged_as_refused`.

---

### TV-THREAT-03: Immediate Revocation Bypass via Stale Sessions / Pre-signed URLs
- **Attack Scenario:** Alice grants Bob read access to a legal term sheet. Bob begins reviewing it. Alice realizes Bob was assigned to a conflicting deal and immediately revokes his access. In conventional systems using S3 pre-signed URLs (valid for 15-60 minutes) or cached permission claims in JWTs, Bob can continue downloading until the token expires.
- **Defensive Mechanism:**
  1. **Zero Pre-signed URLs:** TrustVault never issues detached pre-signed URLs. All downloads flow through an authenticated streaming controller that evaluates live database permissions at the exact millisecond of the request.
  2. **ACID Transaction Deletion:** Revoking a permission (`DELETE /api/documents/{id}/permissions/{user_id}`) commits immediately in the database.
  3. **No In-Memory Permission Caching:** The permission verification query executes on every request inside the database transaction.
- **Test Reference:** `test_immediate_revocation_enforced`.

---

### TV-THREAT-04 & TV-THREAT-05: Audit Log Alteration, Splicing, or Deletion
- **Attack Scenario:** A malicious insider or compromised administrator account accesses the database shell and modifies an audit log entry (e.g. changing an `ACCESS_REFUSED` entry to `SUCCESS`, or deleting records documenting unauthorized access).
- **Defensive Mechanism:**
  - TrustVault implements a **cryptographic hash-chained ledger** (similar to a Merkle blockchain):
    - Every log record stores `prev_hash`, which is the `record_hash` of the immediately preceding record (Genesis uses 64 zeros).
    - `record_hash = SHA256(prev_hash | canonical_timestamp | actor_id | action | target_id | status | details)`.
    - Every record is signed with `signature = HMAC_SHA256(AUDIT_HMAC_SECRET, record_hash)`.
  - The verification engine (`/api/audit/verify`) walks the ledger from record 1 to head:
    - If any payload field is altered, `record_hash` fails to match.
    - If a record is deleted, `prev_hash` of the next record does not match the previous record's hash.
    - If an attacker modifies the hash without the secret key, the HMAC signature validation fails.
- **Test Reference:** `test_audit_chain_validity`, `test_audit_chain_detects_database_tampering`, `test_audit_chain_detects_hash_link_breakage`.

---

### TV-THREAT-06: Information & Existence Leakage via Search Queries
- **Attack Scenario:** An unauthorized user queries `GET /api/documents?query=Salary` or `query=Acquisition`. A naive system filters results in application memory *after* querying the database, which can leak document counts, or uses database queries that match titles before checking permissions.
- **Defensive Mechanism:**
  - The SQL query itself enforces object-level security:
    ```python
    permitted_ids = [p[0] for p in db.query(Permission.document_id).filter(Permission.user_id == current_user.id).all()]
    q = q.filter(or_(Document.owner_id == current_user.id, Document.id.in_(permitted_ids)))
    ```
  - An unauthorized user searching for terms in confidential documents receives `[]` (empty list). Document titles, existence, or total counts are never leaked.
- **Test Reference:** `test_search_isolation_prevents_metadata_leakage`.

---

### TV-THREAT-07: Administrator Backdoor / Lack of Separation of Duties
- **Attack Scenario:** In many enterprise systems, an "admin" account has a wildcard bypass allowing them to view and download all files. An IT administrator can therefore quietly read executive salaries, proprietary IP, or internal HR complaint papers.
- **Defensive Mechanism:**
  - **Zero-Trust Separation of Duties:** TrustVault deliberately segregates administrative platform duties from document confidentiality.
  - The `admin` role can manage user accounts, inspect audit trails, and verify ledger integrity, but **cannot read or download confidential document contents** unless the Document Owner has explicitly granted them document-level permissions.
  - An ungranted download attempt by an Administrator returns `HTTP 403 Forbidden` and creates an audit record with `status="REFUSED"`.
- **Test Reference:** `test_admin_cannot_download_unshared_confidential_document`.

---

### TV-THREAT-08: Plaintext Extraction from Storage Disk via Infrastructure Compromise
- **Attack Scenario:** An attacker gains read access to the server's filesystem, backups, or storage volume.
- **Defensive Mechanism:**
  - Documents are encrypted before being written to disk using **AES-256-GCM** (authenticated symmetric encryption).
  - Storage files are named with random UUIDs (`vault_storage/{uuid}.enc`), never exposing the original filename on disk.
  - The disk payload contains `[12-byte random nonce] + [ciphertext] + [16-byte authentication tag]`.
  - Reading the file directly from disk produces unreadable ciphertext. Decryption occurs only in memory during an authorized streaming download.
- **Test Reference:** `test_files_stored_encrypted_on_disk`.

---

### TV-THREAT-09 & TV-THREAT-10: Polyglot Files & Disguised Executable Uploads
- **Attack Scenario:** An attacker uploads a Windows PE binary (`.exe`) or shell script renamed to `invoice.pdf`. If served with loose MIME types or processed by downstream indexers, code execution can occur.
- **Defensive Mechanism:**
  - Multi-layer validation in `app/security.py`:
    1. **Magic Byte Signature Inspection:** Reads the binary header and validates that PDF starts with `%PDF-`, Office documents start with ZIP magic bytes `PK\x03\x04`, etc.
    2. **Disallowed Binary Signatures:** Inspects the first 4KB for `MZ` (Windows PE), `\x7fELF` (Linux executable), `#!/` (shell script), `<script` (HTML/JS), and `<?php`.
    3. **Hardened Download Headers:** Streamed downloads are served with `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'`, and `Content-Disposition: attachment`.
- **Test Reference:** `test_upload_blocks_executable_disguised_as_pdf`, `test_upload_blocks_linux_elf_binary`, `test_upload_blocks_script_injection`, `test_upload_accepts_valid_pdf`.

---

### TV-THREAT-14: Stale Tokens from Deactivated or Compromised Users
- **Attack Scenario:** An employee is terminated. An administrator deactivates their account. However, the user still possesses a valid JWT token with 60 minutes of lifetime remaining.
- **Defensive Mechanism:**
  - User records maintain a monotonic `token_version` integer in the database.
  - When an administrator deactivates a user or resets credentials, `token_version` is incremented.
  - On every request, `get_current_user` compares the `token_version` in the JWT claim against the live database record. If they do not match, the token is rejected immediately with `HTTP 401 Unauthorized`.
- **Test Reference:** `test_user_deactivation_immediately_invalidates_active_token`.

---

### TV-THREAT-16: Autonomous Permission Widening by AI
- **Attack Scenario:** An integrated LLM/AI model hallucinates or is prompted into automatically granting access to sensitive documents to all users.
- **Defensive Mechanism:**
  - The AI Assistant is architecturally restricted to **advisory status only**.
  - The AI endpoint (`/api/documents/{id}/permissions/ai-recommend`) analyzes the category and suggests prospective candidates. It does **not** execute database writes to the `permissions` table.
  - A human document owner must explicitly review the suggestion and submit an independent `POST /api/documents/{id}/permissions` request.
  - Both the AI advisory generation and the subsequent human grant are immutably logged in the audit ledger.
- **Test Reference:** `test_ai_advisory_never_widens_access_autonomously`.

---

## 3. Knowingly Accepted Risks & Architectural Trade-offs

We believe security engineering is about making deliberate, defensible risk decisions. Below are the risks we identified, knowingly accepted for this release, and our justification:

### 1. Cryptographic Key Management (Dev Master Key vs HSM / KMS)
- **The Risk:** In the current reference implementation, `STORAGE_ENCRYPTION_KEY` and `AUDIT_HMAC_SECRET` are read from environment variables or `.env`. If the host operating system is compromised, an attacker could extract the keys.
- **Why We Accepted It:** A self-contained, easily deployable evaluation system cannot depend on external AWS KMS or Azure Key Vault hardware security modules (HSMs).
- **Production Path:** In production, keys would be managed via AWS KMS / HashiCorp Vault with envelope encryption, where the database audit ledger holds a key ARN and each document has a unique data encryption key (DEK) encrypted by a Key Encryption Key (KEK).

### 2. File Ingestion Sandboxing vs Content Inspection
- **The Risk:** Magic byte validation and pattern matching inspect the file header and banned byte sequences, but do not execute deep PDF structure parsing (e.g., detecting malformed font tables or embedded flash zero-days inside a valid `%PDF-` container).
- **Why We Accepted It:** Full document sanitization requires heavyweight sandbox parsers (e.g., Dangerzone, LibreOffice headless in gVisor, or ClamAV daemon) which would introduce multi-gigabyte container dependencies and significant processing latency.
- **Mitigation in Place:** Downloads are strictly forced as attachments with `Content-Disposition: attachment`, `Content-Security-Policy: default-src 'none'`, and `X-Content-Type-Options: nosniff`, preventing browser-side active content execution.

### 3. Folder-Level Permission Inheritance Deliberately Excluded
- **The Choice:** We chose **explicit per-document access control** rather than hierarchical folder inheritance.
- **Why We Chose It:** As stated in the problem description: *"Someone is given access to a folder so they can see one file, and they can now see forty."* Folder inheritance is the single most common cause of accidental over-permissioning in enterprise environments. By enforcing explicit, per-document access grants, we completely eliminate transitive permission leaks.

### 4. Client-Side Decryption vs Server-Side Streaming
- **The Choice:** Decryption occurs in the server runtime before streaming to the authenticated user, rather than zero-knowledge client-side decryption in WebAssembly.
- **Why We Chose It:** Zero-knowledge client-side encryption prevents server-side search, audit verification, and magic-byte malware inspection. By decrypting on-the-fly in server memory without persisting plaintext to disk, we achieve a robust balance between confidentiality and platform governability.
