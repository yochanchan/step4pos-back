from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
from uuid import uuid4

from jwt import decode as jwt_decode, encode as jwt_encode
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.core.config import settings
from app.core.exceptions import ApiError

ALGORITHM = "HS256"


def _get_secret() -> str:
    if not settings.jwt_secret:
        raise ApiError(
            code="server_config_error",
            message="JWT 秘密鍵が設定されていません。",
            hint="環境変数 JWT_SECRET を設定してください。",
        )
    return settings.jwt_secret


def create_access_token(
    *,
    subject: str,
    scope: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
) -> Tuple[str, datetime, str]:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.access_token_ttl_minutes))
    jti = str(uuid4())
    payload: Dict[str, Any] = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": jti,
    }
    if scope:
        payload["scope"] = scope

    token = jwt_encode(payload, _get_secret(), algorithm=ALGORITHM)
    return token, expire, jti


def decode_token(token: str, *, verify_exp: bool = True) -> Dict[str, Any]:
    options = {"verify_exp": verify_exp}
    try:
        payload = jwt_decode(
            token,
            _get_secret(),
            algorithms=[ALGORITHM],
            options=options,
        )
    except ExpiredSignatureError as exc:
        raise ApiError(
            code="token_expired",
            message="アクセストークンの有効期限が切れています。",
            status_code=401,
        ) from exc
    except InvalidTokenError as exc:
        raise ApiError(
            code="token_invalid",
            message="無効なトークンです。",
            status_code=401,
        ) from exc
    return payload
