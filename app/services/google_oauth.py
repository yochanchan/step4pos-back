from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple
from urllib.parse import urlencode, urljoin

import httpx
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.core.config import settings
from app.core.exceptions import ApiError

AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
TOKENINFO_ENDPOINT = "https://oauth2.googleapis.com/tokeninfo"
USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo"

CONTEXT_COOKIE_NAME = "google_oauth_ctx"
CONTEXT_MAX_AGE = 300  # seconds


@dataclass(slots=True)
class GoogleOAuthContext:
    state_id: str
    nonce: str
    code_verifier: str
    redirect_hash: str
    redirect_to: str


@dataclass(slots=True)
class GoogleProfile:
    provider_user_id: str
    email: Optional[str]
    email_verified: bool
    display_name: str


def _ensure_google_config() -> None:
    if not settings.google_client_id or not settings.google_redirect_uri:
        raise ApiError(
            code="google_not_configured",
            message="Google クライアントが構成されていません。",
            hint="環境変数 GOOGLE_CLIENT_ID / GOOGLE_REDIRECT_URI を設定してください。",
            status_code=503,
        )


def _serializer() -> URLSafeTimedSerializer:
    secret = settings.jwt_secret or settings.google_client_secret
    if not secret:
        raise ApiError(
            code="google_not_configured",
            message="Google 用の署名鍵が設定されていません。",
            hint="JWT_SECRET または GOOGLE_CLIENT_SECRET を設定してください。",
            status_code=503,
        )
    return URLSafeTimedSerializer(secret_key=secret, salt="google-oauth-context")


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


def encode_context(context: GoogleOAuthContext) -> str:
    serializer = _serializer()
    data = {
        "sid": context.state_id,
        "nonce": context.nonce,
        "verifier": context.code_verifier,
        "redirect_hash": context.redirect_hash,
        "redirect_to": context.redirect_to,
    }
    return serializer.dumps(data)


def decode_context(token: str) -> GoogleOAuthContext:
    serializer = _serializer()
    try:
        data = serializer.loads(token, max_age=CONTEXT_MAX_AGE)
    except SignatureExpired as exc:
        raise ApiError(
            code="google_context_expired",
            message="Google 認証コンテキストの有効期限が切れています。",
            status_code=401,
        ) from exc
    except BadSignature as exc:
        raise ApiError(
            code="google_context_invalid",
            message="Google 認証コンテキストが不正です。",
            status_code=401,
        ) from exc

    return GoogleOAuthContext(
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
    _ensure_google_config()

    state_id, state_hash = _generate_state()
    nonce = secrets.token_urlsafe(16)
    code_verifier, code_challenge = _generate_pkce_pair()
    redirect_hash = _hash_redirect_uri(settings.google_redirect_uri)
    sanitized_redirect = _sanitize_redirect_path(redirect_to)

    context = GoogleOAuthContext(
        state_id=state_id,
        nonce=nonce,
        code_verifier=code_verifier,
        redirect_hash=redirect_hash,
        redirect_to=sanitized_redirect,
    )

    context_token = encode_context(context)
    query = {
        "response_type": "code",
        "client_id": settings.google_client_id,
        "redirect_uri": settings.google_redirect_uri,
        "state": state_hash,
        "scope": "openid email profile",
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        # optional but useful
        "access_type": "offline",
        "prompt": "consent",
    }

    authorize_url = f"{AUTHORIZATION_ENDPOINT}?{urlencode(query)}"
    return authorize_url, context_token


async def exchange_code_for_tokens(code: str, code_verifier: str) -> dict:
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.google_redirect_uri,
        "client_id": settings.google_client_id,
        "code_verifier": code_verifier,
    }
    if settings.google_client_secret:
        payload["client_secret"] = settings.google_client_secret

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            TOKEN_ENDPOINT,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if response.status_code != 200:
        raise ApiError(
            code="google_token_exchange_failed",
            message="Google 連携でアクセストークンを取得できませんでした。",
            hint=response.text,
            status_code=401,
        )
    return response.json()


async def verify_id_token(id_token: str | None, expected_nonce: str) -> dict:
    if not id_token:
        raise ApiError(
            code="google_id_token_missing",
            message="Google ID トークンが含まれていません。",
            status_code=401,
        )

    params = {"id_token": id_token}
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(TOKENINFO_ENDPOINT, params=params)
    if response.status_code != 200:
        raise ApiError(
            code="google_verify_failed",
            message="Google ID トークンの検証に失敗しました。",
            hint=response.text,
            status_code=401,
        )
    payload = response.json()

    aud = payload.get("aud")
    iss = payload.get("iss")
    nonce = payload.get("nonce")
    exp = payload.get("exp")

    if aud != settings.google_client_id:
        raise ApiError(
            code="google_audience_mismatch",
            message="Google 認証のクライアント ID が一致しません。",
            status_code=401,
        )
    if iss not in ("https://accounts.google.com", "accounts.google.com"):
        raise ApiError(
            code="google_issuer_invalid",
            message="Google 認証の issuer が不正です。",
            status_code=401,
        )
    if nonce != expected_nonce:
        raise ApiError(
            code="google_nonce_mismatch",
            message="Google 認証要求が一致しません。",
            status_code=401,
        )
    if exp is not None:
        try:
            exp_ts = int(exp)
        except Exception:
            exp_ts = 0
        if exp_ts <= int(datetime.now(timezone.utc).timestamp()):
            raise ApiError(
                code="google_token_expired",
                message="Google ID トークンの有効期限が切れています。",
                status_code=401,
            )
    return payload


async def fetch_profile(access_token: Optional[str]) -> Optional[dict]:
    if not access_token:
        return None
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            USERINFO_ENDPOINT, headers={"Authorization": f"Bearer {access_token}"}
        )
    if resp.status_code != 200:
        return None
    return resp.json()


def _generate_state_for_id(state_id: str) -> Tuple[str, str]:
    digest = hmac.new(
        key=(settings.jwt_secret or settings.google_client_secret or "google").encode(
            "utf-8"
        ),
        msg=state_id.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()[:24]
    return state_id, digest


def decode_state_hash(context: GoogleOAuthContext, state_param: str) -> None:
    expected = _generate_state_for_id(context.state_id)[1]
    if not hmac.compare_digest(state_param, expected):
        raise ApiError(
            code="google_state_mismatch",
            message="Google 認証要求が一致しません。",
            status_code=401,
        )


def validate_redirect(context: GoogleOAuthContext) -> None:
    current_hash = _hash_redirect_uri(settings.google_redirect_uri)
    if not hmac.compare_digest(context.redirect_hash, current_hash):
        raise ApiError(
            code="google_redirect_mismatch",
            message="Google リダイレクト URI が一致しません。",
            status_code=401,
        )


def build_profile(
    verify_payload: dict,
    profile_payload: Optional[dict] | None = None,
) -> GoogleProfile:
    provider_user_id = verify_payload["sub"]
    email = verify_payload.get("email")
    display_name = (
        verify_payload.get("name")
        or (
            ((verify_payload.get("given_name") or "") + " " + (verify_payload.get("family_name") or "")).strip()
        )
        or (profile_payload.get("name") if profile_payload else None)
        or "Googleユーザー"
    )
    email_verified = bool(verify_payload.get("email_verified") or email)

    return GoogleProfile(
        provider_user_id=provider_user_id,
        email=email,
        email_verified=email_verified,
        display_name=display_name,
    )


def clear_context_cookie(response) -> None:
    response.delete_cookie(
        key=CONTEXT_COOKIE_NAME,
        path="/auth/google",
        domain=settings.refresh_cookie_domain,
    )


def set_context_cookie(response, token: str) -> None:
    response.set_cookie(
        key=CONTEXT_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=settings.google_cookie_secure,
        samesite="lax",
        max_age=CONTEXT_MAX_AGE,
        path="/auth/google",
        domain=settings.refresh_cookie_domain,
    )
