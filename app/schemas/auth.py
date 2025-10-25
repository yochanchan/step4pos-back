from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6, pattern=r"^[\x21-\x7E]+$")
    display_name: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserPublic(BaseModel):
    id: int
    email: Optional[EmailStr] = None
    display_name: str
    email_verified: bool

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    refresh_expires_at: datetime
    user: UserPublic


class SignupResponse(TokenResponse):
    pass


class LoginResponse(TokenResponse):
    pass


class LogoutResponse(BaseModel):
    status: str = "ok"
