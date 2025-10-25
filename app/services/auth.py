from __future__ import annotations

import hashlib
import logging
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

import jwt
from email_validator import EmailNotValidError, validate_email
from passlib.context import CryptContext
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.exceptions import ApiError
from app.db.models import AuthIdentity, AuthProvider, RefreshToken, User

logger = logging.getLogger(__name__)

_pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__type="id",
    argon2__rounds=3,
    argon2__memory_cost=102400,
    argon2__parallelism=8,
)

_PASSWORD_MIN_LENGTH = 6
_PASSWORD_PATTERN = re.compile(r"^[\x21-\x7E]+$")

ALGORITHM = "HS256"


@dataclass(slots=True)
class RefreshBundle:
    token: str
    token_hash: str
    jti: str
    issued_at: datetime
    expires_at: datetime


@dataclass(slots=True)
class AuthResult:
    user: User
    access_token: str
    access_expires_at: datetime
    refresh_bundle: RefreshBundle


def _normalize_email(raw_email: str) -> str:
    try:
        return validate_email(raw_email, check_deliverability=False).normalized
    except EmailNotValidError as exc:
        raise ApiError(
            code="invalid_email",
            message="メールアドレスが不正です。",
            hint=str(exc),
        ) from exc


def _mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    masked = f"{local[:1]}***" if local else "***"
    return f"{masked}@{domain}" if domain else masked


def _validate_password(password: str) -> None:
    if len(password) < _PASSWORD_MIN_LENGTH:
        raise ApiError(
            code="weak_password",
            message="Password is too short.",
            hint=f"Use at least {_PASSWORD_MIN_LENGTH} characters.",
        )
    if not _PASSWORD_PATTERN.match(password):
        raise ApiError(
            code="weak_password",
            message="Password contains unsupported characters.",
            hint="Use half-width ASCII characters without spaces.",
        )


def _hash_password(password: str) -> str:
    _validate_password(password)
    return _pwd_context.hash(password)


def _verify_password(password: str, hashed: str) -> bool:
    try:
        return _pwd_context.verify(password, hashed)
    except Exception:
        return False


def _jwt_secret() -> str:
    if not settings.jwt_secret:
        raise ApiError(
            code="server_config_error",
            message="JWT 秘密鍵が設定されていません。",
            hint="環境変数 JWT_SECRET を設定してください。",
        )
    return settings.jwt_secret


def _create_access_token(subject: str, scope: Optional[str] = None) -> tuple[str, datetime, str]:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.access_token_ttl_minutes)
    jti = str(uuid4())
    payload: Dict[str, Any] = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": jti,
    }
    if scope:
        payload["scope"] = scope
    token = jwt.encode(payload, _jwt_secret(), algorithm=ALGORITHM)
    return token, expire, jti


def decode_token(token: str, *, verify_exp: bool = True) -> Dict[str, Any]:
    try:
        return jwt.decode(
            token,
            _jwt_secret(),
            algorithms=[ALGORITHM],
            options={"verify_exp": verify_exp},
        )
    except jwt.ExpiredSignatureError as exc:
        raise ApiError(
            code="token_expired",
            message="アクセストークンの有効期限が切れています。",
            status_code=401,
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise ApiError(
            code="token_invalid",
            message="無効なトークンです。",
            status_code=401,
        ) from exc


def _hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_refresh_bundle() -> RefreshBundle:
    issued = datetime.utcnow()
    expires = issued + timedelta(days=settings.refresh_token_ttl_days)
    token = secrets.token_urlsafe(48)
    return RefreshBundle(
        token=token,
        token_hash=_hash_refresh_token(token),
        jti=str(uuid4()),
        issued_at=issued,
        expires_at=expires,
    )


async def _store_refresh(
    session: AsyncSession,
    *,
    user_id: int,
    bundle: RefreshBundle,
) -> None:
    session.add(
        RefreshToken(
            user_id=user_id,
            jti=bundle.jti,
            token_hash=bundle.token_hash,
            issued_at=bundle.issued_at,
            expires_at=bundle.expires_at,
        )
    )
    await session.flush()


async def _get_refresh_by_hash(session: AsyncSession, token_hash: str) -> Optional[RefreshToken]:
    result = await session.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    return result.scalar_one_or_none()


def _is_refresh_active(record: RefreshToken) -> bool:
    if record.revoked_at is not None:
        return False
    return record.expires_at >= datetime.utcnow()


async def _revoke_refresh(session: AsyncSession, record: RefreshToken) -> None:
    record.revoked_at = datetime.utcnow()
    session.add(record)
    await session.flush()


async def _revoke_refresh_by_hash(session: AsyncSession, token_hash: str) -> None:
    await session.execute(
        update(RefreshToken)
        .where(RefreshToken.token_hash == token_hash, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.utcnow())
    )


async def _revoke_all_refresh(session: AsyncSession, user_id: int) -> None:
    await session.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.utcnow())
    )


async def _issue_tokens(session: AsyncSession, user: User) -> AuthResult:
    bundle = _new_refresh_bundle()
    await _store_refresh(session, user_id=user.id, bundle=bundle)
    token, expires_at, _ = _create_access_token(str(user.id))
    return AuthResult(
        user=user,
        access_token=token,
        access_expires_at=expires_at,
        refresh_bundle=bundle,
    )


async def signup(
    session: AsyncSession,
    *,
    email: str,
    password: str,
    display_name: Optional[str],
) -> AuthResult:
    normalized_email = _normalize_email(email)
    display = (display_name or normalized_email.split("@", 1)[0]).strip() or "User"

    try:
        existing = await session.execute(select(User).where(User.email == normalized_email))
        if existing.scalar_one_or_none():
            raise ApiError(
                code="email_already_exists",
                message="このメールアドレスは既に登録されています。",
                status_code=409,
            )

        password_hash = _hash_password(password)
        user = User(email=normalized_email, password_hash=password_hash, display_name=display)
        session.add(user)
        await session.flush()

        result = await _issue_tokens(session, user)
        await session.commit()
        logger.info("signup_success user_id=%s", user.id)
        return result
    except ApiError:
        await session.rollback()
        logger.info("signup_failed email=%s", _mask_email(email))
        raise
    except Exception as exc:
        await session.rollback()
        logger.exception("signup_error email=%s", _mask_email(email))
        raise ApiError(code="signup_failed", message="サインアップに失敗しました。") from exc


async def login(
    session: AsyncSession,
    *,
    email: str,
    password: str,
) -> AuthResult:
    normalized_email = _normalize_email(email)
    try:
        result = await session.execute(select(User).where(User.email == normalized_email))
        user = result.scalar_one_or_none()
        if not user or not user.password_hash or user.deleted_at is not None:
            raise ApiError(
                code="invalid_credentials",
                message="メールアドレスまたはパスワードが正しくありません。",
                status_code=401,
            )
        if not _verify_password(password, user.password_hash):
            raise ApiError(
                code="invalid_credentials",
                message="メールアドレスまたはパスワードが正しくありません。",
                status_code=401,
            )

        result = await _issue_tokens(session, user)
        await session.commit()
        logger.info("login_success user_id=%s", user.id)
        return result
    except ApiError:
        await session.rollback()
        logger.info("login_failed email=%s", _mask_email(email))
        raise
    except Exception as exc:
        await session.rollback()
        logger.exception("login_error email=%s", _mask_email(email))
        raise ApiError(code="login_failed", message="ログインに失敗しました。") from exc


async def refresh(
    session: AsyncSession,
    *,
    refresh_token: Optional[str],
) -> AuthResult:
    if not refresh_token:
        raise ApiError(
            code="refresh_token_missing",
            message="リフレッシュトークンがありません。",
            status_code=401,
        )

    token_hash = _hash_refresh_token(refresh_token)
    record = await _get_refresh_by_hash(session, token_hash)
    if record is None:
        await session.rollback()
        raise ApiError(
            code="refresh_token_invalid",
            message="リフレッシュトークンが無効です。",
            status_code=401,
        )

    if not _is_refresh_active(record):
        await _revoke_all_refresh(session, record.user_id)
        await session.commit()
        raise ApiError(
            code="refresh_token_reused",
            message="リフレッシュトークンが利用できません。",
            status_code=401,
        )

    user = await session.get(User, record.user_id)
    if not user or user.deleted_at is not None:
        await _revoke_refresh(session, record)
        await session.commit()
        raise ApiError(
            code="user_not_found",
            message="ユーザーが存在しません。",
            status_code=401,
        )

    await _revoke_refresh(session, record)
    result = await _issue_tokens(session, user)
    await session.commit()
    logger.info(
        "refresh_success user_id=%s old_jti=%s new_jti=%s",
        user.id,
        record.jti,
        result.refresh_bundle.jti,
    )
    return result


async def logout(
    session: AsyncSession,
    *,
    refresh_token: Optional[str],
) -> None:
    if not refresh_token:
        await session.rollback()
        return

    token_hash = _hash_refresh_token(refresh_token)
    record = await _get_refresh_by_hash(session, token_hash)
    if record is None:
        await session.rollback()
        return

    await _revoke_refresh(session, record)
    await session.commit()
    logger.info("logout_success user_id=%s", record.user_id)


async def login_with_provider(
    session: AsyncSession,
    *,
    provider: AuthProvider,
    provider_user_id: str,
    email: Optional[str],
    display_name: str,
    email_verified: bool,
) -> AuthResult:
    try:
        result = await session.execute(
            select(AuthIdentity)
            .where(
                AuthIdentity.provider == provider,
                AuthIdentity.provider_user_id == provider_user_id,
            )
            .options(selectinload(AuthIdentity.user))
        )
        identity = result.scalar_one_or_none()

        if identity:
            user = identity.user
            identity.last_sign_in_at = datetime.utcnow()
            identity.email_at_provider = email or identity.email_at_provider
            identity.display_name_at_provider = display_name
        else:
            user = None
            if email:
                result = await session.execute(select(User).where(User.email == email))
                user = result.scalar_one_or_none()

            if user:
                if email and not user.email:
                    user.email = email
                if email_verified:
                    user.email_verified = True
                user.display_name = user.display_name or display_name
            else:
                user = User(
                    email=email,
                    email_verified=email_verified,
                    password_hash=None,
                    display_name=display_name,
                )
                session.add(user)
                await session.flush()

            identity = AuthIdentity(
                user_id=user.id,
                provider=provider,
                provider_user_id=provider_user_id,
                email_at_provider=email,
                display_name_at_provider=display_name,
                last_sign_in_at=datetime.utcnow(),
            )
            session.add(identity)

        result = await _issue_tokens(session, user)
        await session.commit()
        logger.info(
            "social_login_success provider=%s user_id=%s provider_user_id=%s",
            provider.value,
            user.id,
            provider_user_id,
        )
        return result
    except ApiError:
        await session.rollback()
        logger.info(
            "social_login_failed provider=%s provider_user_id=%s",
            provider.value,
            provider_user_id,
        )
        raise
    except Exception as exc:
        await session.rollback()
        logger.exception(
            "social_login_error provider=%s provider_user_id=%s",
            provider.value,
            provider_user_id,
        )
        raise ApiError(code="login_failed", message="ソーシャルログインに失敗しました。") from exc
