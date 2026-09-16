from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from database.session import get_db
from models.user import User, UserRole
from schemas.auth import LoginRequest, TokenResponse, UserResponse, RegisterUserRequest
from core.auth import verify_password, hash_password, create_access_token, get_current_user, require_admin

router = APIRouter()

@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: AsyncSession = Depends(get_db)):
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
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user_id=str(user.id),
        email=user.email,
        full_name=user.full_name,
        role=user.role
    )

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
