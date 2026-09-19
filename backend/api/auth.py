from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from database.session import get_db
from models.user import User, UserRole
from schemas.auth import LoginRequest, TokenResponse, UserResponse, RegisterUserRequest
from core.auth import SESSION_COOKIE_NAME, verify_password, hash_password, create_access_token, get_current_user, require_admin
from core.config import settings

router = APIRouter()

@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == request.email.strip().lower()))
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(request.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been deactivated",
        )
        
    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email, "role": user.role.value}
    )
    
    # The browser receives the session as an httpOnly cookie: it is never exposed to
    # JavaScript and never travels in a URL. The body still carries the token for
    # machine clients (scripts, tests, integrations) that use the bearer header.
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=access_token,
        httponly=True,
        samesite="lax",
        secure=settings.ENVIRONMENT.lower() == "production",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user_id=str(user.id),
        email=user.email,
        full_name=user.full_name,
        role=user.role
    )


@router.post("/logout")
async def logout(response: Response):
    """Clears the browser session cookie."""
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"message": "Signed out"}

@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: RegisterUserRequest,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    # Check if user already exists
    existing = await db.execute(select(User).where(User.email == request.email.strip().lower()))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists"
        )
        
    new_user = User(
        email=request.email.strip().lower(),
        hashed_password=hash_password(request.password),
        full_name=request.full_name,
        role=request.role,
        is_active=True
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user
