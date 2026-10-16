import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv("SECRET_KEY", "trustvault_super_secret_jwt_hmac_key_min_32_bytes_long_prod")
AUDIT_HMAC_SECRET = os.getenv("AUDIT_HMAC_SECRET", "trustvault_immutable_audit_log_ledger_hmac_secret_key_2026")
# 32-byte key for AES-256
RAW_ENCRYPTION_KEY = os.getenv("STORAGE_ENCRYPTION_KEY", "trustvault_aes_256_gcm_storage_master_key_32_bytes!")
STORAGE_ENCRYPTION_KEY = RAW_ENCRYPTION_KEY[:32].encode("utf-8").ljust(32, b"0")

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'trustvault.db'}")
VAULT_STORAGE_DIR = Path(os.getenv("VAULT_STORAGE_DIR", str(BASE_DIR / "vault_storage")))
VAULT_STORAGE_DIR.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD_SIZE_BYTES = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", 26214400)) # 25 MB
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 120))
ALGORITHM = "HS256"

# Allowed extensions and their expected MIME types and magic byte prefixes
ALLOWED_MIME_TYPES = {
    "application/pdf": [b"%PDF-"],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [b"PK\x03\x04"],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [b"PK\x03\x04"],
    "image/png": [b"\x89PNG\r\n\x1a\n"],
    "image/jpeg": [b"\xff\xd8\xff"],
    "text/plain": [], # Text plain validated via encoding checks
    "text/csv": [],
}

DISALLOWED_PATTERNS = [
    b"MZ",              # Windows PE executable
    b"\x7fELF",         # Linux ELF binary
    b"#!/",             # Shell script executable
    b"<script",         # Injected HTML / JS
    b"<?php",           # PHP executable script
]
