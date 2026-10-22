from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.database import Base, engine
from app.seed import seed_database
from app.routers import (
    auth_router,
    document_router,
    permission_router,
    audit_router,
    admin_router,
)

# Initialize database schema
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="TrustVault - Confidential Document & Cryptographic Audit Platform",
    description="Zero-trust document storage, per-request authorization, immediate revocation, and tamper-evident audit ledger.",
    version="1.0.0",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Include API Routers
app.include_router(auth_router.router)
app.include_router(document_router.router)
app.include_router(permission_router.router)
app.include_router(audit_router.router)
app.include_router(admin_router.router)

# Mount static files
STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.on_event("startup")
def on_startup():
    seed_database()

@app.get("/")
def serve_index():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "TrustVault"}
