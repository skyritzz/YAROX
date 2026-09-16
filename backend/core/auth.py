import hashlib
import secrets
import hmac
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Union
import jwt
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from core.config import settings
from database.session import get_db
from models.user import User, UserRole

# Standard bearer auth for API endpoints
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)
http_bearer = HTTPBearer(auto_error=False)

def hash_password(password: str) -> str:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with 100,000 iterations and a secure salt.
    Format: pbkdf2_sha256$100000$<salt_hex>$<hash_hex>
    """
    salt = secrets.token_hex(16)
    hash_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    return f"pbkdf2_sha256$100000${salt}${hash_bytes.hex()}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain password against the stored PBKDF2 hash using constant-time comparison.
    """
    try:
        parts = hashed_password.split('$')
        if len(parts) != 4 or parts[0] != 'pbkdf2_sha256':
            return False
        iterations = int(parts[1])
        salt = parts[2]
        expected_hash = parts[3]
        
        computed_hash = hashlib.pbkdf2_hmac(
            'sha256',
            plain_password.encode('utf-8'),
            salt.encode('utf-8'),
            iterations
        ).hex()
        
        return hmac.compare_digest(computed_hash, expected_hash)
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "iat": now})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> dict:
    """
    Decodes and validates a JWT token. Raises HTTPException on expiration or invalid signature.
    """
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(
    auth_header: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer),
    token_query: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Extracts and validates the current user from Bearer header or fallback token.
    """
    token = None
    if auth_header and auth_header.credentials:
        token = auth_header.credentials
    elif token_query:
        token = token_query

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    import uuid
    try:
        user_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user ID format")

    result = await db.execute(select(User).where(User.id == user_uuid, User.is_active == True))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    return user

def require_role(allowed_roles: List[UserRole]):
    """
    Dependency factory to enforce Role-Based Access Control (RBAC).
    """
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Required role: {[r.value for r in allowed_roles]}, current: {current_user.role.value}"
            )
        return current_user
    return role_checker

# Pre-configured RBAC dependencies
require_admin = require_role([UserRole.ADMIN])
require_analyst_or_admin = require_role([UserRole.ADMIN, UserRole.ANALYST])
require_authenticated = require_role([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])

async def seed_initial_users(db: AsyncSession):
    """
    Seeds default ADMIN, ANALYST, and VIEWER accounts if the users table is empty.
    """
    result = await db.execute(select(User).limit(1))
    existing = result.scalar_one_or_none()
    if existing is not None:
        return

    users_to_seed = [
        User(
            email=settings.INITIAL_ADMIN_EMAIL,
            hashed_password=hash_password(settings.INITIAL_ADMIN_PASSWORD),
            full_name="System Administrator",
            role=UserRole.ADMIN,
            is_active=True
        ),
        User(
            email=settings.INITIAL_ANALYST_EMAIL,
            hashed_password=hash_password(settings.INITIAL_ANALYST_PASSWORD),
            full_name="Senior SOC Analyst",
            role=UserRole.ANALYST,
            is_active=True
        ),
        User(
            email=settings.INITIAL_VIEWER_EMAIL,
            hashed_password=hash_password(settings.INITIAL_VIEWER_PASSWORD),
            full_name="Audit Viewer",
            role=UserRole.VIEWER,
            is_active=True
        ),
    ]
    for u in users_to_seed:
        db.add(u)
    await db.commit()
    print("Pre-seeded default user accounts for ADMIN, ANALYST, and VIEWER.")
