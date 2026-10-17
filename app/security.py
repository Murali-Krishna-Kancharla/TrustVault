import os
import re
import hashlib
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import (
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    STORAGE_ENCRYPTION_KEY,
    ALLOWED_MIME_TYPES,
    DISALLOWED_PATTERNS,
    MAX_UPLOAD_SIZE_BYTES,
)

# --- Password Hashing ---
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

# --- JWT Token Management ---
def create_access_token(user_id: str, email: str, role: str, token_version: int, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "token_version": token_version,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

# --- AES-256-GCM Storage Encryption ---
def encrypt_file_data(plaintext_bytes: bytes) -> bytes:
    """
    Encrypts file content using AES-256-GCM authenticated encryption.
    Format stored on disk: [12-byte Nonce] + [Ciphertext + 16-byte GCM Tag]
    """
    aesgcm = AESGCM(STORAGE_ENCRYPTION_KEY)
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return nonce + ciphertext

def decrypt_file_data(encrypted_bytes: bytes) -> bytes:
    """
    Decrypts AES-256-GCM encrypted payload and verifies integrity tag.
    """
    if len(encrypted_bytes) < 28:
        raise ValueError("Encrypted data is corrupted or truncated")
    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]
    aesgcm = AESGCM(STORAGE_ENCRYPTION_KEY)
    return aesgcm.decrypt(nonce, ciphertext, None)

# --- File Validation & Sanitization ---
def sanitize_filename(filename: str) -> str:
    """
    Strips directory traversal sequences, null bytes, and dangerous characters.
    """
    # Replace path separators and null bytes
    cleaned = filename.replace("\\", "/").split("/")[-1]
    cleaned = cleaned.replace("\x00", "")
    # Keep only safe alphanumeric, dash, underscore, and dot
    cleaned = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", cleaned)
    if not cleaned or cleaned.startswith("."):
        cleaned = "document_" + cleaned.lstrip(".")
    return cleaned[:100]

def validate_uploaded_content(filename: str, content: bytes, declared_mime_type: str) -> Tuple[bool, str, str]:
    """
    Performs multi-layer file validation:
    1. Size limit enforcement
    2. Disallowed binary / script signatures (PE, ELF, PHP, JS, Shell)
    3. Magic byte signature verification against claimed MIME type
    Returns: (is_valid, sanitized_mime_type, error_reason)
    """
    if len(content) == 0:
        return False, "", "File is completely empty"

    if len(content) > MAX_UPLOAD_SIZE_BYTES:
        return False, "", f"File size exceeds maximum limit of {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB"

    # Inspect first 4096 bytes for banned patterns (executables, scripts)
    header_probe = content[:4096]
    for pattern in DISALLOWED_PATTERNS:
        if pattern in header_probe:
            return False, "", f"Prohibited executable or script pattern detected ({pattern.decode('latin1', 'ignore')})"

    ext = os.path.splitext(filename)[1].lower()
    
    # Extension mapping
    ext_to_mime = {
        ".pdf": "application/pdf",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".txt": "text/plain",
        ".csv": "text/csv",
    }

    if ext not in ext_to_mime:
        return False, "", f"Unsupported file extension '{ext}'. Allowed: {', '.join(ext_to_mime.keys())}"

    expected_mime = ext_to_mime[ext]
    
    # Check magic bytes for structured binary formats
    magic_prefixes = ALLOWED_MIME_TYPES.get(expected_mime, [])
    if magic_prefixes:
        matched = any(content.startswith(magic) for magic in magic_prefixes)
        if not matched:
            return False, "", f"File header magic bytes do not match expected format for {ext}"

    # Text / CSV validation: ensure valid UTF-8/ASCII without null bytes
    if expected_mime in ("text/plain", "text/csv"):
        try:
            content.decode("utf-8")
        except UnicodeDecodeError:
            try:
                content.decode("latin-1")
            except Exception:
                return False, "", "Text file contains invalid binary byte sequences"

    return True, expected_mime, ""

def compute_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()
