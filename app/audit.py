import json
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models import AuditLog
from app.config import AUDIT_HMAC_SECRET

GENESIS_PREV_HASH = "0" * 64

def format_canonical_timestamp(dt: Any) -> str:
    """
    Normalizes datetime to a deterministic UTC canonical format across all databases.
    """
    if isinstance(dt, str):
        return dt.replace("+00:00", "").replace("Z", "")
    if isinstance(dt, datetime):
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
    return str(dt)

def compute_record_hash(prev_hash: str, timestamp_str: str, actor_id: Optional[str], action: str, target_id: str, status: str, details_str: str) -> str:
    """
    Computes cryptographic SHA-256 hash across canonical fields of the audit event.
    """
    canonical_payload = f"{prev_hash}|{timestamp_str}|{actor_id or 'none'}|{action}|{target_id}|{status}|{details_str}"
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()

def compute_hmac_signature(record_hash: str) -> str:
    """
    Computes HMAC-SHA256 signature using server audit master key.
    """
    return hmac.new(
        AUDIT_HMAC_SECRET.encode("utf-8"),
        record_hash.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

def record_audit_event(
    db: Session,
    actor_email: str,
    actor_role: str,
    action: str,
    target_type: str,
    target_id: str,
    ip_address: str,
    status: str,
    details: Optional[Dict[str, Any]] = None,
    actor_id: Optional[str] = None,
) -> AuditLog:
    """
    Appends a new audit record to the cryptographic hash chain.
    Atomically binds to previous record's hash.
    """
    details_str = json.dumps(details or {}, sort_keys=True)
    now = datetime.now(timezone.utc)
    timestamp_str = format_canonical_timestamp(now)

    # Get latest audit entry to link hash chain
    last_record = db.query(AuditLog).order_by(desc(AuditLog.id)).first()
    prev_hash = last_record.record_hash if last_record else GENESIS_PREV_HASH

    current_hash = compute_record_hash(
        prev_hash=prev_hash,
        timestamp_str=timestamp_str,
        actor_id=actor_id,
        action=action,
        target_id=target_id,
        status=status,
        details_str=details_str,
    )

    signature = compute_hmac_signature(current_hash)

    log_entry = AuditLog(
        timestamp=now,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        ip_address=ip_address,
        status=status,
        details=details_str,
        prev_hash=prev_hash,
        record_hash=current_hash,
        signature=signature,
    )

    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry

def verify_audit_integrity(db: Session) -> Tuple[bool, int, Optional[int], str]:
    """
    Verifies the entire cryptographic ledger from genesis to head.
    Returns: (is_valid, total_records, tampered_at_id, error_message)
    """
    records = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    if not records:
        return True, 0, None, "Ledger is empty (valid genesis state)"

    expected_prev_hash = GENESIS_PREV_HASH

    for idx, rec in enumerate(records):
        # 1. Verify prev_hash linkage
        if rec.prev_hash != expected_prev_hash:
            return (
                False,
                len(records),
                rec.id,
                f"Broken hash chain at record ID #{rec.id}: expected prev_hash '{expected_prev_hash}', got '{rec.prev_hash}'"
            )

        # 2. Recompute record_hash
        timestamp_str = format_canonical_timestamp(rec.timestamp)
        recomputed_hash = compute_record_hash(
            prev_hash=rec.prev_hash,
            timestamp_str=timestamp_str,
            actor_id=rec.actor_id,
            action=rec.action,
            target_id=rec.target_id,
            status=rec.status,
            details_str=rec.details,
        )

        if recomputed_hash != rec.record_hash:
            return (
                False,
                len(records),
                rec.id,
                f"Payload tamper detected at record ID #{rec.id}: content has been modified!"
            )

        # 3. Verify HMAC signature
        recomputed_sig = compute_hmac_signature(rec.record_hash)
        if not hmac.compare_digest(recomputed_sig, rec.signature):
            return (
                False,
                len(records),
                rec.id,
                f"Invalid cryptographic signature at record ID #{rec.id}: signature does not match audit master key!"
            )

        expected_prev_hash = rec.record_hash

    return True, len(records), None, f"All {len(records)} audit records verified successfully with zero tampering"
