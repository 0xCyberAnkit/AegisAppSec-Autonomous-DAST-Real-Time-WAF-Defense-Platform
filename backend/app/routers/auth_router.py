from fastapi import APIRouter, Depends, HTTPException, status, Response
from pydantic import BaseModel, EmailStr
from typing import Optional
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db import models
from app.core.auth import get_password_hash, verify_password, create_access_token, get_current_user

router = APIRouter(prefix="/api/auth", tags=["Authentication & Access Control"])

class RegisterRequest(BaseModel):
    email: str
    password: str
    full_name: str
    role: Optional[str] = "pentester" # admin, pentester, developer
    company: Optional[str] = "Independent"

class LoginRequest(BaseModel):
    email: str
    password: str

class DemoLoginRequest(BaseModel):
    role: str # admin, pentester, developer

@router.post("/register")
def register_user(req: RegisterRequest, response: Response, db: Session = Depends(get_db)):
    """Registers a new user account with enterprise role."""
    existing = db.query(models.User).filter_by(email=req.email.strip().lower()).first()
    if existing:
        raise HTTPException(status_code=400, detail="An account with this email address already exists.")
    
    new_user = models.User(
        email=req.email.strip().lower(),
        hashed_password=get_password_hash(req.password),
        full_name=req.full_name.strip(),
        role=req.role if req.role in ("admin", "pentester", "developer") else "pentester",
        company=req.company or "Independent"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_access_token({"sub": str(new_user.id), "email": new_user.email, "role": new_user.role})
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        max_age=86400,
        path="/",
        samesite="lax",
        secure=False
    )
    return {
        "status": "success",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": new_user.id,
            "email": new_user.email,
            "full_name": new_user.full_name,
            "role": new_user.role,
            "company": new_user.company
        }
    }

@router.post("/login")
def login_user(req: LoginRequest, response: Response, db: Session = Depends(get_db)):
    """Validates user credentials and issues JWT session token."""
    user = db.query(models.User).filter_by(email=req.email.strip().lower()).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password credentials."
        )

    token = create_access_token({"sub": str(user.id), "email": user.email, "role": user.role})
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        max_age=86400,
        path="/",
        samesite="lax",
        secure=False
    )
    return {
        "status": "success",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "company": user.company
        }
    }

@router.post("/demo-login")
def demo_login(req: DemoLoginRequest, response: Response, db: Session = Depends(get_db)):
    """1-Click quick login for evaluating different personas (Admin, Pentester, Developer)."""
    role_email_map = {
        "admin": "admin@aegisappsec.io",
        "pentester": "pentester@aegisappsec.io",
        "developer": "dev@aegisappsec.io"
    }
    target_email = role_email_map.get(req.role.lower(), "pentester@aegisappsec.io")
    user = db.query(models.User).filter_by(email=target_email).first()
    if not user:
        # Create on the fly if needed
        user = models.User(
            email=target_email,
            hashed_password=get_password_hash("DemoPass123!"),
            full_name=f"Demo {req.role.capitalize()} Operator",
            role=req.role.lower(),
            company="Aegis Cyber Systems"
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    token = create_access_token({"sub": str(user.id), "email": user.email, "role": user.role})
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        max_age=86400,
        path="/",
        samesite="lax",
        secure=False
    )
    return {
        "status": "success",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "company": user.company
        }
    }

@router.get("/me")
def get_current_user_profile(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Returns current active user profile information."""
    user_id = int(user.get("sub", 0))
    user_rec = db.query(models.User).filter_by(id=user_id).first()
    if not user_rec:
        return {
            "id": user_id,
            "email": user.get("email"),
            "role": user.get("role"),
            "full_name": "Authenticated Operator"
        }
    return {
        "id": user_rec.id,
        "email": user_rec.email,
        "full_name": user_rec.full_name,
        "role": user_rec.role,
        "company": user_rec.company,
        "created_at": user_rec.created_at.isoformat()
    }
