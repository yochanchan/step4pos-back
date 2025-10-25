from typing import Annotated, Optional

from fastapi import Depends, Header
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ApiError
from app.db.models import User
from app.db.session import get_async_session
from app.services.auth import decode_token


async def get_current_user(
    authorization: Annotated[Optional[str], Header(alias="Authorization")] = None,
    session: AsyncSession = Depends(get_async_session),
) -> User:
    if not authorization:
        raise ApiError(
            code="unauthorized",
            message="認証が必要です。",
            status_code=401,
        )

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise ApiError(
            code="unauthorized",
            message="Bearer トークンが必要です。",
            status_code=401,
        )

    payload = decode_token(token)
    sub = payload.get("sub")
    if sub is None:
        raise ApiError(
            code="unauthorized",
            message="トークンにユーザー情報が含まれていません。",
            status_code=401,
        )

    try:
        user_id = int(sub)
    except (TypeError, ValueError) as exc:
        raise ApiError(
            code="unauthorized",
            message="トークンに不正なユーザー情報が含まれています。",
            status_code=401,
        ) from exc

    user = await session.get(User, user_id)
    if not user or user.deleted_at is not None:
        raise ApiError(
            code="user_not_found",
            message="ユーザーが存在しません。",
            status_code=401,
        )

    return user
