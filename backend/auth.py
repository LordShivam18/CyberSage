import base64
import hashlib
import hmac
import json
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Callable, Dict, Iterable, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import AuditEvent, User


ROLE_ADMIN = "administrator"
ROLE_ANALYST = "security_analyst"
ROLE_RESPONDER = "incident_responder"
ROLE_AUDITOR = "read_only_auditor"

ALL_ROLES = {ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class LoginRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    disabled: bool

    class Config:
        from_attributes = True
        orm_mode = True


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def hash_password(password: str, iterations: int = 260000) -> str:
    if len(password) < 10:
        raise ValueError("Password must be at least 10 characters long")
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64url(salt)}${_b64url(digest)}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations_text, salt_text, digest_text = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        salt = _b64url_decode(salt_text)
        expected = _b64url_decode(digest_text)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def create_access_token(user: User) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "iss": settings.jwt_issuer,
        "sub": user.username,
        "role": user.role,
        "iat": now,
        "exp": int((datetime.utcnow() + timedelta(minutes=settings.access_token_minutes)).timestamp()),
    }
    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}.{_b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    signature = hmac.new(settings.jwt_secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(signature)}"


def decode_access_token(token: str) -> Dict:
    try:
        header_text, payload_text, signature_text = token.split(".", 2)
        signing_input = f"{header_text}.{payload_text}"
        expected = hmac.new(
            settings.jwt_secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected, _b64url_decode(signature_text)):
            raise ValueError("Invalid signature")
        payload = json.loads(_b64url_decode(payload_text))
        if payload.get("iss") != settings.jwt_issuer:
            raise ValueError("Invalid issuer")
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ValueError("Token expired")
        return payload
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    user = db.query(User).filter(User.username == username).first()
    if not user or user.disabled:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    payload = decode_access_token(token)
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if not user or user.disabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is disabled or missing")
    return user


def require_roles(*roles: str) -> Callable:
    allowed = set(roles)

    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user

    return dependency


class RateLimiter:
    def __init__(self, limit_per_minute: int):
        self.limit = limit_per_minute
        self.events = defaultdict(deque)

    def __call__(self, request: Request):
        client_host = request.client.host if request.client else "unknown"
        key = f"{client_host}:{request.url.path}"
        now = time.monotonic()
        bucket = self.events[key]
        while bucket and now - bucket[0] > 60:
            bucket.popleft()
        if len(bucket) >= self.limit:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")
        bucket.append(now)


auth_rate_limiter = RateLimiter(settings.auth_rate_limit_per_minute)
predict_rate_limiter = RateLimiter(settings.predict_rate_limit_per_minute)


def audit_event(
    db: Session,
    action: str,
    target_type: str,
    target_id: Optional[str],
    details: Optional[Dict] = None,
    user: Optional[User] = None,
) -> None:
    db.add(
        AuditEvent(
            username=user.username if user else None,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details or {},
        )
    )
    db.flush()


def create_user(db: Session, username: str, password: str, role: str) -> User:
    if role not in ALL_ROLES:
        raise ValueError(f"Role must be one of: {', '.join(sorted(ALL_ROLES))}")
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        raise ValueError(f"User '{username}' already exists")
    user = User(username=username, password_hash=hash_password(password), role=role)
    db.add(user)
    db.flush()
    audit_event(db, "user_created", "user", username, {"role": role})
    return user
