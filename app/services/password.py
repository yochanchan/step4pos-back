from __future__ import annotations

import re
from typing import Iterable

from passlib.context import CryptContext

from app.core.exceptions import ApiError

_pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__type="id",
    argon2__rounds=3,
    argon2__memory_cost=102400,  # ~100 MB
    argon2__parallelism=8,
)

_PASSWORD_MIN_LENGTH = 6
_PASSWORD_ALLOWED_PATTERN = re.compile(r"^[\x21-\x7E]+$")


def validate_password_strength(password: str) -> None:
    """Validate password complexity and raise ApiError if requirements are not met."""
    if len(password) < _PASSWORD_MIN_LENGTH:
        raise ApiError(
            code="weak_password",
            message="Password is too short.",
            hint=f"Use at least {_PASSWORD_MIN_LENGTH} characters.",
        )

    if not _PASSWORD_ALLOWED_PATTERN.match(password):
        raise ApiError(
            code="weak_password",
            message="Password contains unsupported characters.",
            hint="Use half-width ASCII characters (no spaces).",
        )


def hash_password(password: str) -> str:
    validate_password_strength(password)
    return _pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return _pwd_context.verify(password, hashed_password)
