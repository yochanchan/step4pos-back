from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ApiError
from app.core.config import settings
from app.db.session import get_async_session
from app.db.models import AuthProvider
from app.dependencies.auth import get_current_user
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    SignupRequest,
    SignupResponse,
    TokenResponse,
    UserPublic,
)
from app.services import auth_service, line_oidc

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_refresh_cookie(response: Response, result: auth_service.AuthResult) -> None:
    bundle = result.refresh_bundle
    max_age = int((bundle.expires_at - datetime.utcnow()).total_seconds())
    if max_age < 0:
        max_age = 0

    expires_at = bundle.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=bundle.token,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_same_site,
        max_age=max_age,
        expires=expires_at,
        path=settings.refresh_cookie_path,
        domain=settings.refresh_cookie_domain,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        path=settings.refresh_cookie_path,
        domain=settings.refresh_cookie_domain,
    )


def _build_token_response(result: auth_service.AuthResult) -> TokenResponse:
    return TokenResponse(
        access_token=result.access_token,
        expires_at=result.access_expires_at,
        refresh_expires_at=result.refresh_bundle.expires_at,
        user=UserPublic.model_validate(result.user),
    )


@router.post(
    "/signup",
    response_model=SignupResponse,
    status_code=status.HTTP_201_CREATED,
)
async def signup(
    payload: SignupRequest,
    response: Response,
    session: AsyncSession = Depends(get_async_session),
) -> SignupResponse:
    result = await auth_service.signup(
        session,
        email=payload.email,
        password=payload.password,
        display_name=payload.display_name,
    )
    _set_refresh_cookie(response, result)
    return _build_token_response(result)


@router.post("/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    response: Response,
    session: AsyncSession = Depends(get_async_session),
) -> LoginResponse:
    result = await auth_service.login(
        session,
        email=payload.email,
        password=payload.password,
    )
    _set_refresh_cookie(response, result)
    return _build_token_response(result)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_async_session),
) -> TokenResponse:
    refresh_token = request.cookies.get(settings.refresh_cookie_name)
    result = await auth_service.refresh(session, refresh_token=refresh_token)
    _set_refresh_cookie(response, result)
    return _build_token_response(result)


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_async_session),
) -> LogoutResponse:
    refresh_token = request.cookies.get(settings.refresh_cookie_name)
    await auth_service.logout(session, refresh_token=refresh_token)
    _clear_refresh_cookie(response)
    return LogoutResponse()


@router.get("/me", response_model=UserPublic)
async def get_me(
    current_user=Depends(get_current_user),
) -> UserPublic:
    return UserPublic.model_validate(current_user)


@router.get("/line/login")
async def line_login() -> RedirectResponse:
    url, context_token = line_oidc.create_login_redirect()
    response = RedirectResponse(url, status_code=status.HTTP_302_FOUND)
    line_oidc.set_context_cookie(response, context_token)
    return response


@router.get("/line/callback", response_model=LoginResponse)
async def line_callback(
    request: Request,
    response: Response,
    code: Optional[str] = None,
    state: Optional[str] = None,
    session: AsyncSession = Depends(get_async_session),
) -> LoginResponse:
    if not code:
        raise ApiError(
            code="line_code_missing",
            message="LINE認証コードが不足しています。",
            status_code=400,
        )
    context_token = request.cookies.get(line_oidc.CONTEXT_COOKIE_NAME)
    if not context_token:
        raise ApiError(
            code="line_context_missing",
            message="LINE認証コンテキストが見つかりません。",
            status_code=401,
        )

    context = line_oidc.decode_context(context_token)
    line_oidc.clear_context_cookie(response)

    if not state:
        raise ApiError(
            code="line_state_missing",
            message="LINE認証の state が不足しています。",
            status_code=401,
        )
    line_oidc.decode_state_hash(context, state)
    line_oidc.validate_redirect(context)

    token_data = await line_oidc.exchange_code_for_tokens(code, context.code_verifier)
    verify_payload = await line_oidc.verify_id_token(
        token_data.get("id_token"),
        expected_nonce=context.nonce,
    )
    profile_payload = await line_oidc.fetch_profile(token_data.get("access_token"))
    profile = line_oidc.build_profile(verify_payload, profile_payload)

    result = await auth_service.login_with_provider(
        session,
        provider=AuthProvider.line,
        provider_user_id=profile.provider_user_id,
        email=profile.email,
        display_name=profile.display_name,
        email_verified=profile.email_verified,
    )
    _set_refresh_cookie(response, result)
    return _build_token_response(result)
