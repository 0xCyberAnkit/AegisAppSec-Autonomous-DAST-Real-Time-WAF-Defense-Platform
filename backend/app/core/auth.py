import os
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.core.config import settings

# JWT configuration
JWT_SECRET = os.getenv("AEGIS_JWT_SECRET", "aegis-enterprise-jwt-hyper-secret-key-2026")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # 24 hours

security_bearer = HTTPBearer(auto_error=False)

import hmac

def get_password_hash(password: str) -> str:
    """Hashes password with SHA-256 + cryptographic salt."""
    salt = settings.SECRET_KEY[:16]
    return hashlib.sha256(f"{salt}{password}".encode("utf-8")).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies plain password against hashed password using constant-time comparison."""
    if not plain_password or not hashed_password:
        return False
    computed = get_password_hash(plain_password)
    return hmac.compare_digest(computed, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Generates signed JWT bearer token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> Optional[dict]:
    """Decodes and validates JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

def get_current_user_optional(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
):
    """Optional user dependency for public/protected hybrid routes."""
    if not auth or not auth.credentials:
        return None
    payload = decode_token(auth.credentials)
    if not payload:
        return None
    return payload

def get_current_user(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
):
    """Strict authenticated user dependency."""
    if not auth or not auth.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required. Please sign in.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(auth.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload
