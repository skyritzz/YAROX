from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from models.user import UserRole
import uuid

class LoginRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=6, description="User password")

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    email: str
    full_name: Optional[str]
    role: UserRole

class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    full_name: Optional[str]
    role: UserRole
    is_active: bool

class RegisterUserRequest(BaseModel):
    email: str = Field(..., description="Valid email address")
    password: str = Field(..., min_length=8, description="Minimum 8 characters")
    full_name: Optional[str] = None
    role: UserRole = UserRole.ANALYST
