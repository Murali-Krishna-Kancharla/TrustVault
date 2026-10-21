from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import UserLogin, TokenResponse, UserOut
from app.security import verify_password, create_access_token
from app.auth import get_current_user
from app.audit import record_audit_event

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenResponse)
def login(login_req: UserLogin, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    user = db.query(User).filter(User.email == login_req.email.lower()).first()

    if not user or not verify_password(login_req.password, user.hashed_password):
        record_audit_event(
            db=db,
            actor_email=login_req.email,
            actor_role="anonymous",
            action="USER_LOGIN",
            target_type="USER",
            target_id=user.id if user else "unregistered",
            ip_address=client_ip,
            status="REFUSED",
            details={"reason": "Invalid credentials provided"},
            actor_id=user.id if user else None,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        record_audit_event(
            db=db,
            actor_email=user.email,
            actor_role=user.role,
            action="USER_LOGIN",
            target_type="USER",
            target_id=user.id,
            ip_address=client_ip,
            status="REFUSED",
            details={"reason": "Account is deactivated"},
            actor_id=user.id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been deactivated. Please contact an administrator.",
        )

    access_token = create_access_token(
        user_id=user.id,
        email=user.email,
        role=user.role,
        token_version=user.token_version,
    )

    record_audit_event(
        db=db,
        actor_email=user.email,
        actor_role=user.role,
        action="USER_LOGIN",
        target_type="USER",
        target_id=user.id,
        ip_address=client_ip,
        status="SUCCESS",
        details={"message": "Successful authentication"},
        actor_id=user.id,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user,
    }

@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.get("/users", response_model=List[UserOut])
def list_available_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    List active users to facilitate granting permissions to named collaborators.
    """
    users = db.query(User).filter(User.is_active == True).all()
    return users
