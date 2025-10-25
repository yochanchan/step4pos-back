from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple
from urllib.parse import urlencode, urljoin

import httpx
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.core.config import settings
from app.core.exceptions import ApiError

AUTHORIZATION_ENDPOINT = "https://access.line.me/oauth2/v2.1/authorize"
TOKEN_ENDPOINT = "https://api.line.me/oauth2/v2.1/token"
VERIFY_ENDPOINT = "https://api.line.me/oauth2/v2.1/verify"
PROFILE_ENDPOINT = "https://api.line.me/v2/profile"

CONTEXT_COOKIE_NAME = "line_oidc_ctx"
CONTEXT_MAX_AGE = 300  # seconds


@dataclass(slots=True)
class LineOIDCContext:
    state_id: str
    nonce: str
    code_verifier: str
    redirect_hash: str
    redirect_to: str


@dataclass(slots=True)
class LineOIDCProfile:
    provider_user_id: str
    email: Optional[str]
    email_verified: bool
    display_name: str


def _ensure_line_config() -> None:
    if not settings.line_client_id or not settings.line_redirect_uri:
        raise ApiError(
            code="line_not_configured",
            message="LINEクライアントが構成されていません。",
            hint="環境変数 OIDC_LINE_CLIENT_ID / OIDC_LINE_REDIRECT_URI を設定してください。",
            status_code=503,
        )


def _serializer() -> URLSafeTimedSerializer:
    secret = settings.jwt_secret or settings.line_client_secret
    if not secret:
        raise ApiError(
            code="line_not_configured",
            message="LINE用の署名鍵が設定されていません。",
            hint="JWT_SECRET もしくは OIDC_LINE_CLIENT_SECRET を設定してください。",
            status_code=503,
        )
    return URLSafeTimedSerializer(secret_key=secret, salt="line-oidc-context")


def _hash_redirect_uri(redirect_uri: str) -> str:
    return hashlib.sha256(redirect_uri.encode("utf-8")).hexdigest()


def _generate_pkce_pair() -> Tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def _generate_state() -> Tuple[str, str]:
    state_id = secrets.token_urlsafe(16)
    _, digest = _generate_state_for_id(state_id)
    return state_id, digest


def encode_context(context: LineOIDCContext) -> str:
    serializer = _serializer()
    data = {
        "sid": context.state_id,
        "nonce": context.nonce,
        "verifier": context.code_verifier,
        "redirect_hash": context.redirect_hash,
        "redirect_to": context.redirect_to,
    }
    return serializer.dumps(data)


def decode_context(token: str) -> LineOIDCContext:
    serializer = _serializer()
    try:
        data = serializer.loads(token, max_age=CONTEXT_MAX_AGE)
    except SignatureExpired as exc:
        raise ApiError(
            code="line_context_expired",
            message="LINE認証コンテキストの有効期限が切れています。",
            status_code=401,
        ) from exc
    except BadSignature as exc:
        raise ApiError(
            code="line_context_invalid",
            message="LINE認証コンテキストが不正です。",
            status_code=401,
        ) from exc

    return LineOIDCContext(
        state_id=data["sid"],
        nonce=data["nonce"],
        code_verifier=data["verifier"],
        redirect_hash=data["redirect_hash"],
        redirect_to=data.get("redirect_to", "/"),
    )


def _sanitize_redirect_path(raw_redirect: Optional[str]) -> str:
    if not raw_redirect:
        return "/"
    raw_redirect = raw_redirect.strip()
    if raw_redirect.startswith("http://") or raw_redirect.startswith("https://"):
        return "/"
    if not raw_redirect.startswith("/"):
        raw_redirect = f"/{raw_redirect.lstrip('/')}"
    return raw_redirect or "/"


def resolve_post_login_redirect(redirect_to: str) -> str:
    if redirect_to.startswith("http://") or redirect_to.startswith("https://"):
        return redirect_to
    base = settings.cors_origins[0].rstrip("/") if settings.cors_origins else ""
    if base:
        return urljoin(f"{base}/", redirect_to.lstrip("/"))
    return redirect_to or "/"


def create_login_redirect(*, redirect_to: Optional[str] = None) -> Tuple[str, str]:
    _ensure_line_config()

    state_id, state_hash = _generate_state()
    nonce = secrets.token_urlsafe(16)
    code_verifier, code_challenge = _generate_pkce_pair()
    redirect_hash = _hash_redirect_uri(settings.line_redirect_uri)
    sanitized_redirect = _sanitize_redirect_path(redirect_to)

    context = LineOIDCContext(
        state_id=state_id,
        nonce=nonce,
        code_verifier=code_verifier,
        redirect_hash=redirect_hash,
        redirect_to=sanitized_redirect,
    )

    context_token = encode_context(context)
    query = {
        "response_type": "code",
        "client_id": settings.line_client_id,
        "redirect_uri": settings.line_redirect_uri,
        "state": state_hash,
        "scope": "openid profile email",
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "consent",
    }

    authorize_url = f"{AUTHORIZATION_ENDPOINT}?{urlencode(query)}"
    return authorize_url, context_token


async def exchange_code_for_tokens(code: str, code_verifier: str) -> dict:
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.line_redirect_uri,
        "client_id": settings.line_client_id,
        "code_verifier": code_verifier,
    }
    if settings.line_client_secret:
        payload["client_secret"] = settings.line_client_secret

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            TOKEN_ENDPOINT,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if response.status_code != 200:
        raise ApiError(
            code="line_token_exchange_failed",
            message="LINE連携でアクセストークンを取得できませんでした。",
            hint=response.text,
            status_code=401,
        )
    return response.json()


async def verify_id_token(id_token: str, expected_nonce: str) -> dict:
    if not id_token:
        raise ApiError(
            code="line_id_token_missing",
            message="LINE IDトークンが含まれていません。",
            status_code=401,
        )

    data = {
        "id_token": id_token,
        "client_id": settings.line_client_id,
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            VERIFY_ENDPOINT,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if response.status_code != 200:
        raise ApiError(
            code="line_verify_failed",
            message="LINE IDトークンの検証に失敗しました。",
            hint=response.text,
            status_code=401,
        )
    payload = response.json()
    if payload.get("nonce") != expected_nonce:
        raise ApiError(
            code="line_nonce_mismatch",
            message="LINE認証要求が一致しません。",
            status_code=401,
        )
    return payload


async def fetch_profile(access_token: Optional[str]) -> Optional[dict]:
    if not access_token:
        return None

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            PROFILE_ENDPOINT,
            headers={"Authorization": f"Bearer {access_token}"},
        )
    if response.status_code != 200:
        return None
    return response.json()


def _generate_state_for_id(state_id: str) -> Tuple[str, str]:
    digest = hmac.new(
        key=(settings.jwt_secret or settings.line_client_secret or "line").encode("utf-8"),
        msg=state_id.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()[:24]
    return state_id, digest


def decode_state_hash(context: LineOIDCContext, state_param: str) -> None:
    expected = _generate_state_for_id(context.state_id)[1]
    if not hmac.compare_digest(state_param, expected):
        raise ApiError(
            code="line_state_mismatch",
            message="LINE認証要求が一致しません。",
            status_code=401,
        )


def validate_redirect(context: LineOIDCContext) -> None:
    current_hash = _hash_redirect_uri(settings.line_redirect_uri)
    if not hmac.compare_digest(context.redirect_hash, current_hash):
        raise ApiError(
            code="line_redirect_mismatch",
            message="LINEリダイレクトURIが一致しません。",
            status_code=401,
        )


def build_profile(
    verify_payload: dict,
    profile_payload: Optional[dict],
) -> LineOIDCProfile:
    provider_user_id = verify_payload["sub"]
    email = verify_payload.get("email")
    display_name = verify_payload.get("name")
    if not display_name and profile_payload:
        display_name = profile_payload.get("displayName")
    display_name = display_name or "LINEユーザー"
    email_verified = bool(email)

    return LineOIDCProfile(
        provider_user_id=provider_user_id,
        email=email,
        email_verified=email_verified,
        display_name=display_name,
    )


def clear_context_cookie(response) -> None:
    response.delete_cookie(
        key=CONTEXT_COOKIE_NAME,
        path="/auth/line",
        domain=settings.refresh_cookie_domain,
    )


def set_context_cookie(response, token: str) -> None:
    response.set_cookie(
        key=CONTEXT_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite="lax",
        max_age=CONTEXT_MAX_AGE,
        path="/auth/line",
        domain=settings.refresh_cookie_domain,
    )
